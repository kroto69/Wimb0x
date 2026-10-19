# WinBox Native (M2) Protocol — Technical Spec

Clean-room reference for reimplementing the WinBox client against your own routers.
Synthesized 2026-10-14 from three public sources: **tik4net** (C#, `danikf/tik4net`
v4 WinboxNative), **joanne-li/winbox-terminal-protocol** (Python), and
**Cisco-Talos/Winbox_Protocol_Dissector** (Wireshark Lua). The two full client
implementations agree byte-for-byte on the new generation.

Big picture: WinBox native = **TCP 8291** + binary TLV message layer ("M2") + one of
two auth/crypto generations. Not the 8728 API, not REST.

## 1. Transport framing (TCP 8291)

- Plain TCP socket, `NoDelay`.
- **Handshake frames are NOT chunked**: `[len 1B][tag 1B]` + payload, raw.
- **Data frames ARE chunked**: each chunk = `[len 1B][tag 1B][payload]`.
  First chunk tag: `0x06` = encrypted, `0x01` = raw. Continuation chunks: tag `0xFF`.
  `len = 0xFF` → 255 bytes, more chunks follow; shorter length ends the frame.
- **Encrypted-frame termination subtlety**: a frame ALSO ends once the assembled payload
  reaches the length its first two bytes declare (`18 + enc_len`). RouterOS sends NO
  zero-length terminator when an encrypted frame is an exact multiple of 255 bytes —
  waiting for a short chunk there swallows the next frame.
- Assembled payload: encrypted → `[enc_len 2B BE][IV 16B][ciphertext]`;
  raw → `[len 2B BE][M2 message]` (inner 2-byte length is redundant; skip it).

## 2. Two generations & selection

|              | New (secure)            | Legacy            |
|--------------|-------------------------|-------------------|
| RouterOS     | ≥ 6.43                  | < 6.43            |
| Auth         | EC-SRP5 (Curve25519)    | MD5 challenge-resp|
| Wire crypto  | AES-128-CBC per frame + HMAC-SHA1 | none (plaintext M2) |
| Frame tag    | `0x06`                  | `0x01`            |

**Selection rule** (both sources identical): client sends the EC-SRP5 init frame
immediately. If the router stays **silent ≥ 3 s** or answers with a wrong tag →
treat as unsupported → **reconnect fresh** and run the legacy MD5 flow.
Silence is the only signal an old router gives.

## 3. Auth — EC-SRP5 (new), step by step

Curve: **Curve25519 in Weierstrass form** — `p = 2²⁵⁵−19`,
order `R = 0x1000…5CF5D3ED` (full value in source), generator = `lift_x(9, parity 0)`,
Montgomery `A = 486662`.

1. **C→S** `[len][0x06]`: `username_utf8 + 0x00 + xWA(32B BE) + parityA(1B)`,
   where `(xWA, parityA) = to_montgomery(privA·G)`, `privA` = 32 random bytes.
2. **S→C** `[len][0x06]`: must be **exactly 49 bytes** =
   `xWB(32) + parityB(1) + salt(16)`, else fail (a real error, not "unsupported").
3. Client computes:
   - `valPriv = SHA256(salt ‖ SHA256("user:pass"))` (account name strips anything
     after `'+'`; password UTF-8).
   - `(xGamma, _) = gen_pubkey(valPriv)`; `v = redp1(xGamma, 1)` (deterministic point
     via double-SHA256 loop); `wB = lift_x(xWB, parityB)`; `sum = wB + v`.
   - `j = SHA256(xWA ‖ xWB)`; `vh = (BE(valPriv)·BE(j) + BE(privA)) mod R`;
     `zPt = vh·sum`; `(zMont, _) = to_montgomery(zPt)`; **`secret = SHA256(zMont)`**.
   - `clientCc = SHA256(j ‖ zMont)`.
4. **C→S**: `clientCc` (32B) as `[len][0x06]` frame.
5. **S→C**: 32B server confirmation — **or a plaintext refusal**
   (e.g. `"invalid user name or password (6)"`), surfaced verbatim.
6. Verify `serverCc == SHA256(j ‖ clientCc ‖ zMont)`; mismatch → wrong credentials.
7. Derive stream keys from `secret` (§5).

## 4. Auth — MD5 challenge-response (legacy)

All messages are M2 over **raw tag-`0x01` frames, unencrypted**:

1. Get session id: `M2(SYS_TO=[2,2] mproxy, SYS_FROM=[0,srcId], SYS_CMD=7,
   SYS_REQUEST=true, SYS_REQID=n, key_1="list" (string)` → response carries
   `SESSION_ID` (`0xFE0001`).
2. Challenge setup: `SYS_TO=[2,2], SYS_CMD=5, SESSION_ID=sid`
   (response may never arrive — drain & discard).
3. Get salt: `SYS_TO=[13,4] sysinfo, SYS_CMD=4, SYS_REQUEST=true, SESSION_ID=sid`
   → response `key_9` (raw) = 16-byte salt.
4. Login: `SYS_TO=[13,4], SYS_CMD=1, SESSION_ID=sid, key_1=username (string),
   key_9=salt (raw), key_10=hash (raw, 17 bytes)` where
   `hash = 0x00 ‖ MD5(0x00 ‖ password_utf8 ‖ salt)`.
5. Check `SYS_STATUS` (`0xFF0008`): 0 = success.

## 5. Session encryption (new path)

- **AES-128-CBC**, fresh random 16-byte IV **per frame**, keys fixed for the session.
  No stream state, no sequence numbers, no replay window — each frame decrypts
  independently (that's what makes request multiplexing safe).
- Legacy/MD5 path: **no encryption** in public implementations (plaintext M2).
  (RC4 appears only in the Android app's legacy "secure mode"; its key derivation
  is undocumented publicly — the `.so` is the only witness.)
- Key derivation from 32-byte `secret` (identical in both sources, incl. magic strings):
  - `m2 = "On the client side, this is the send key; on the server side, it is the receive key."`
  - `m3 = "On the client side, this is the receive key; on the server side, it is the send key."`
  - Client: `txRaw = secret ‖ 40×0x00 ‖ m2 ‖ 40×0xF2`;
    `rxRaw = secret ‖ 40×0x00 ‖ m3 ‖ 40×0xF2` (server swaps m2/m3).
  - `txEnc = SHA1(txRaw)[0:16]`, `rxEnc = SHA1(rxRaw)[0:16]`;
    `sk = HkdfExpand(txEnc)`, `rk = HkdfExpand(rxEnc)`;
    `sendAes=sk[0:16]`, `sendHmac=sk[16:36]`, `recvAes=rk[0:16]`, `recvHmac=rk[16:36]`.
  - Custom HKDF: `h1 = HMAC-SHA1(key=64×0x00, msg)`;
    `round_i = HMAC-SHA1(key=h1, prev ‖ (i+1))` for i=0,1; take first 36 bytes.
- Per-frame encrypt (MAC-then-Encrypt):
  `body = M2 ‖ HMAC-SHA1(M2, hmacKey)`; pad: `padByte = 0x0F − (len(body) mod 16)`,
  append `padByte+1` copies of `padByte` (custom — never emits a byte > 0x0F,
  NOT PKCS#7); AES-128-CBC with random IV; wire = `[enc_len 2B BE][IV 16B][ciphertext]`.
- Per-frame decrypt: split IV/ciphertext, AES-CBC decrypt, strip `lastByte+1` pad
  bytes, strip 20-byte HMAC. **Neither public implementation verifies the HMAC**
  (both strip it) — do the same for interop, don't rely on it for integrity.

## 6. M2 message format

- Magic: ASCII **`M2`** (`0x4D 0x32`), then concatenated TLV fields.
- Each field: **`[key_lo][key_hi][namespace][type][value…]`** — key is LE in namespace.
- Namespaces: `0x00` = user (app data), `0xFE` = session, `0xFF` = system.
- Type byte:

| Type      | Hex         | Value encoding                              |
|-----------|-------------|---------------------------------------------|
| bool      | `0x00`/`0x01` | no value bytes — type byte IS the value   |
| u8        | `0x09`      | 1 byte                                      |
| u32       | `0x08`      | 4 bytes LE                                  |
| u64       | `0x10`      | 8 bytes LE                                  |
| addr6     | `0x18`      | exactly 16 bytes, no length prefix          |
| string    | `0x21`/`0x20` | 1-byte len / 2-byte LE len + UTF-8        |
| raw       | `0x31`/`0x30` | 1-byte len / 2-byte LE len + bytes        |
| embedded  | `0x29`/`0x28`/`0x2A` | 1/2/4-byte len + full `M2` submessage |
| u32[]     | `0x88`      | u16 LE count + u32 LE each                  |
| u64[]     | `0x90`      | u16 LE count + u64 LE each                  |
| string[]  | `0xA0`      | u16 LE count; each u16 LE len + bytes       |
| raw[]     | `0xB0`      | like string[]                               |
| msg[]     | `0xA8`      | u16 LE count; each 2-byte len + message     |

  Rule of thumb: bit 0 of type = 1-byte length (`0x21/0x31/0x29`), cleared = 2-byte
  LE length; for integers bit 0 selects u8 vs u32 width.
- **System keys** (`0xFF…`): `0xFF0001` SYS_TO (u32[] handler path),
  `0xFF0002` SYS_FROM (u32[]), `0xFF0005` reply_expected (bool),
  `0xFF0006` request_id (u8), `0xFF0007` command, `0xFF0008` error code,
  `0xFF0009` error string.
- **Session keys** (`0xFE…`): `0xFE0001` session id — **u8 if ≤255, u32 if larger**
  (a truncated id addresses the wrong session).
- **CRUD commands** (`0xFF0007`): `0xFE0002` get-one, `0xFE0003` set,
  `0xFE0004` getall, `0xFE0005` add, `0xFE0006` remove, `0xFE0007` move,
  `0xFE000D` get singleton, `0xFE000E` set singleton, `0xFE0008` setup/wizard,
  `0xFE0012` subscribe, `0xFE0013` unsubscribe, `0xFE0014` logout/disconnect,
  `0xFE0016` reset.
- **CRUD framing**: every request carries `SYS_TO` = handler path u32[]
  (e.g. `[20,0]` = /interface), command, request id, `reply_expected=true`.
  getall: `ufe0004`; get-one: `ufe0001`=.id; set: `ufe0001`=.id + changed fields;
  add: fields only (+ optional `ufe0005`=place-before id); remove: `ufe0001`=.id.
- **Correlation**: `0xFF0006` (request id, 1–255, wraps, 0 reserved) is **echoed in
  the response** and is the only dispatch key; `0xFF0001`/`0xFF0002` swap in the
  response; one request → exactly one response frame. Paging = a *new* request
  echoing continuation keys `0xFE0003` (u32) / `0xFE0015` (opaque raw) — no
  multi-frame streaming.
- **Unsolicited frames**: only a `0xFE0014` logout push (no request id), broadcast
  to every WinBox session (e.g. RoMON relay link closes). A reader must skip
  id-less frames that don't match the pending request.
- Worked byte example (getall `/ip/address`):
  `4D 32 | 01 00 FF 88 02 00 0D000000 04000000 | 02 00 FF 88 02 00 00000000 01000000 | 05 00 FF 01 | 06 00 FF 09 00 | 07 00 FF 09 07`

## 7. Handler paths (live-verified 2026-10-15, RB750Gr3)

| Handler | Path | Fields (key: type) |
|---|---|---|
| /log | [3,4] | 0x1: time (u32 unix), 0x2: buffer (str), 0x3: message (str), 0x4: topics (u32[]) |
| /ip neighbor | [10,1] | 0x1: IP (u32), 0x2: MAC (raw 6B), 0x6: identity (str) |
| /ip hotspot active | [63,13] | 0x1: user (str), 0x2: address (u32), 0x3: uptime (u32 s), 0xb: MAC (raw), 0x12: server (u8), 0x13: login-by (str) |
| Tools ping speed | [77] | action: START cmd=2 (u1=ip u32, u2/u3=pkt size) → sid; POLL cmd=1 (+sid) → 0x1=current, 0x2=avg (u8/u32 bps); CANCEL cmd=3 (+sid). Poll tanpa sid → error "get: no id" |
| /ppp secret | [27,101] | 0x1: name, 0x2: password, 0x3: service (u32), 0x5: profile (u32), 0x6f: disabled (bool). SET/REMOVE target via 0xFE0001 (item id), bukan nama |
| /interface bridge port | [16,2] | live 3 rows 2026-10-15 |
| /interface bridge vlan | [16,13] | live 0 rows (valid, kosong) 2026-10-15 |
| /ip dhcp-client | [43,1] | live 3 rows 2026-10-15 |
| /ip hotspot server | [63,11] | live 1 row 2026-10-15 |
| /ip hotspot server profile | [63,14] | live 2 rows 2026-10-15 |
| /ip hotspot user | [63,1] | live 83 rows 2026-10-15 |
| /ip hotspot ip-binding | [63,10] | live 25 rows 2026-10-15 |
| Tools traceroute | [26] | type query (jg def captured); native streaming invocation BELUM crack (coba OPEN/GETALL/SUBSCRIBE/cmd2) — fallback via terminal `/tool traceroute` |

## 8. Known gaps / discrepancies

1. Legacy secure-mode RC4 key schedule: undocumented publicly; only in the app's
   `.so`. Public impls do legacy as plaintext.
2. The APK's "protocol byte 5 vs 6" is JNI-internal, not a wire byte. On the wire:
   new handshake + encrypted frames = tag `0x06`; legacy raw frames = `0x01`.
3. joanne-li's `_send_raw_m2` doesn't chunk payloads ≥ 255 B (non-conformant;
   works only because auth messages are small). Chunk properly.
4. Dissector naming for `0xFF0003` differs; prefer tik4net/joanne-li (verified live).

## 9. Source index

- tik4net (`github.com/danikf/tik4net`): `tik4net/Winbox/WinboxM2Session.cs`,
  `tik4net/Winbox/WinboxTcpTransport.cs`, `tik4net/Crypto/EcSrp5.cs`,
  `tik4net/Crypto/WinboxStreamCrypto.cs`, `tik4net/Winbox/M2Message.cs`,
  `Docs/winbox-native-m2-protocol.md`, `Docs/findings-winbox.md`.
- joanne-li/winbox-terminal-protocol: `PROTOCOL.md`, `winbox_terminal_client.py`.
- Cisco-Talos/Winbox_Protocol_Dissector: `Winbox_Dissector.lua`.
