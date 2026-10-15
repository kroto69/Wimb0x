# Architecture

How the library is put together and why.

## Layers

```
┌─────────────────────────────────────────────┐
│ WinboxOps.kt / WinboxFeatures.kt            │  typed features, mode-aware CRUD
├─────────────────────────────────────────────┤
│ WinboxSession.kt                            │  TCP session: login, request/response
├──────────────┬──────────────┬───────────────┤
│ M2.kt        │ WinboxFrame  │ WinboxCrypto  │  codec / framing / AES-128-CBC
│              │              │ EcSrp5.kt     │  Curve25519-Weierstrass + SRP
└──────────────┴──────────────┴───────────────┘
┌─────────────────────────────────────────────┐
│ discovery/  Mndp.kt, MndpDiscovery.kt       │  UDP 5678 neighbor discovery
└─────────────────────────────────────────────┘
```

- **Codec (`M2.kt`)** — pure functions: `M2Message.encode()` /
  `M2Message.decode()`. Keys are 3-byte little-endian; the top byte is the
  namespace (`0x00` user, `0xFE` session, `0xFF` system). No I/O here.
- **Framing (`WinboxFrame.kt`)** — chunked TCP frames. Encrypted frames end
  when the assembled payload reaches the length declared in its first two
  bytes (RouterOS sends no zero-length terminator on exact 255-byte
  multiples — see `docs/PROTOCOL.md` §1).
- **Crypto (`WinboxCrypto.kt`, `EcSrp5.kt`)** — EC-SRP5 over Curve25519 in
  Weierstrass form (not the usual Montgomery form; the lift is in
  `EcSrp5.kt`), then HKDF → per-direction AES-128-CBC keys.
- **Session (`WinboxSession.kt`)** — owns the socket. `login()` tries
  EC-SRP5 first; on ≥3 s silence it reconnects and runs legacy MD5.
  `requestRaw` (encrypted) and `requestLegacy` (plaintext) are kept
  separate on purpose: mixing them caused real bugs during development.
- **Ops (`WinboxOps.kt`)** — the layer apps should use. `getAllRows`,
  `addRow`, `setRow`, `removeRow` pick the right transport from
  `sessionMode`. Typed wrappers (`getLogs`, `getHotspotActive`,
  `getRouterNeighbors`, `pingStart/poll/stop`) encode the field knowledge
  from `docs/HANDLERS.md` so callers don't memorize hex keys.
- **Discovery (`discovery/`)** — independent of sessions; binds UDP 5678,
  broadcasts solicitations, parses TLV replies on a daemon thread.

## Key design decisions

1. **Mode-aware, not mode-specific.** The same router can negotiate
   EC-SRP5 on one connection and legacy MD5 on the next (observed live).
   Public ops check `sessionMode` per call instead of caching the mode.
2. **Row identity is explicit.** `setRow`/`removeRow` require the `0xFE0001`
   field and `require()` it. Targeting by name silently does nothing on the
   router — the type system now makes that mistake impossible.
3. **No hidden I/O in codec/crypto.** Everything that touches the network
   lives in `WinboxSession` or `MndpDiscovery`, which are `Closeable`.
4. **Zero dependencies.** Only the JDK. This keeps the library usable from
   plain JVM, Android, and server apps without version conflicts.
5. **Hardcoded paths, no `.jg` fetching.** The official WinBox client downloads
   `.jg` plugin files from the router (via mproxy `[2,2]`) on every connect;
   those files define each menu's handler path and fields, so the official
   client adapts to any RouterOS version automatically. This library takes
   the opposite approach: handler paths and field ids were extracted from
   `.jg` once during development and are now hardcoded (`WinboxPaths`,
   `docs/HANDLERS.md`). Simpler at runtime, at the cost of possibly going
   stale if MikroTik changes paths in a future RouterOS release (in practice
   these are very stable). `.jg` fetching can be added later if dynamic
   adaptation is ever needed.
6. **Reads are one-shot; subscribe is future work.** `getAllRows` sends
   `CMD_GET_ALL` (`0xFE0004`) and returns one response — call it on a timer
   and you have polling, the same pattern as the 8728 API. The protocol
   itself also offers `CMD_SUBSCRIBE` (`0xFE0012`): the router then *pushes*
   updates whenever the data changes — no timer, less traffic, truly live.
   That is the real architectural difference versus API polling, and it is
   what the official client uses for live views. It is not implemented in
   this library yet.

## Threading

- `WinboxSession` is **not** thread-safe; use one session per thread or
  external synchronization. Request/response correlation is by `0xFF0006`
  request id on a single socket.
- `MndpDiscovery` runs its listener on a daemon thread and is safe to
  share; `neighbors()` returns a snapshot.

## Gotchas (learned live)

- GET_ALL needs the `0xFE000C = 0x10000005` flag or handlers return zero rows.
- IPv4 addresses are **octet-LSB** u32 (`192.168.88.1` = `0x0158A8C0`).
- Ping `[77]` is an action (start/poll/cancel with session id), not a table.
- Traceroute `[26]` streaming is not yet reverse-engineered; use the
  terminal fallback.
- Kotlin `apply {}` receiver shadowing: inside `socket.apply { }`,
  bare `port` resolves to `DatagramSocket.getPort()` (-1), not the outer
  property — always qualify (`this@MndpDiscovery.port`). This was a real
  crash found by testing.
