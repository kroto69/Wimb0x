# Handler path reference

`SYS_TO` is a `u32[]` identifying the WinBox handler. All paths below were
verified live against RouterOS (RB750Gr3) on 2026-10-15. Field keys are M2
user-namespace keys; see `docs/PROTOCOL.md` §6 for the key encoding.

Conventions: `u32`/`u8` = unsigned int, `str` = string, `bool`, `raw(N)` =
raw bytes, `u32[]` = array, `ip` = u32 in **octet-LSB** order
(e.g. `192.168.88.1` = `0x0158A8C0`).

## System / logs

| Path | Menu | Notes |
|---|---|---|
| `[3,4]` | `/log` | read-only, ordered. `0x1`: time (u32 unix), `0x2`: buffer (str), `0x3`: message (str), `0x4`: topics (`u32[]`) |
| `[13,4]` | Active Users | type:'map' — tabel sesi login aktif. Dipakai handshake login: minta salt (CMD_GET) + kirim kredensial (cmd 1). BUKAN system info |
| `[24,2]` | `/system resource` | **Resources = type:'item' (singleton)**, `autorefresh:1000` — app resmi MikroTik poll tiap 1 dtk. Field: uptime `0x1`, free mem `0x3`, cpu load `0x9`, board name, version, arch, dll. **Tidak bisa SUBSCRIBE** (subscribe hanya untuk tabel type:'map') — poll tiap 2–5 dtk. Path ini juga host tabel CPU per-core (type:'map') |
| `[24,29]` | `/system health` | GET_ALL → 2 rows (sensors, `0xfe0010`="voltage"..). SUBSCRIBE ACKs but **never pushes** on value change — poll it |

## Interface

| Path | Menu | Notes |
|---|---|---|
| `[20,0]` | `/interface` | all interfaces; bridge ports/VLANs included by type |
| `[16,2]` | `/interface bridge port` | |
| `[16,13]` | `/interface bridge vlan` | |

## PPP

| Path | Menu | Notes |
|---|---|---|
| `[27,101]` | `/ppp secret` | `0x1`: name, `0x2`: password, `0x3`: service (u32), `0x5`: profile (u32), `0x6f`: disabled (bool). **SET/REMOVE must target `0xFE0001`** (item id from GET_ALL); without it the router silently ignores the write. Accuracy note: RouterOS has NO "last uptime" field on secrets — real read-only fields are `last-logged-out`, `last-caller-id`, `last-disconnect-reason` (v6+v7), but their M2 field IDs are UNMAPPED (not in .jg set; discover via live getAllRows with stats bit). Mockup "Sesi Terakhir / last uptime" cannot be wired to real secret data — use `/ppp active` uptime for online users or mark placeholder. |
| `[27,102]` | `/ppp profile` | |
| `[27,103]` | `/ppp active` | read-only |

## IP

| Path | Menu | Notes |
|---|---|---|
| `[20,1]` | `/ip address` | |
| `[43,1]` | `/ip dhcp-client` | |
| `[10,1]` | `/ip neighbor` | router-observed neighbors. `0x1`: IP (u32), `0x2`: MAC (`raw(6)`), `0x6`: identity (str) |
| `[44,1]` | `/ip route` | |
| `[68,1]` | `/ip service` | |
| `[20,8]` | `/ip arp` | `0x1`: IP (u32), `0x2`: MAC (`raw(6)`) |

## Hotspot

| Path | Menu | Notes |
|---|---|---|
| `[63,11]` | `/ip hotspot server` | |
| `[63,14]` | `/ip hotspot server profile` | |
| `[63,1]` | `/ip hotspot user` | |
| `[63,10]` | `/ip hotspot ip-binding` | |
| `[63,13]` | `/ip hotspot active` | read-only. `0x1`: user, `0x2`: address (u32), `0x3`: uptime (u32 s), `0xb`: MAC (`raw(6)`), `0x12`: server (u8), `0x13`: login-by (str) |

## Firewall

| Path | Menu | Notes |
|---|---|---|
| `[20,3]` | `/ip firewall filter` | |
| `[20,5]` | `/ip firewall nat` | |
| `[20,7]` | `/ip firewall mangle` | |

## Queue

| Path | Menu | Notes |
|---|---|---|
| `[20,9]` | `/queue simple` | |
| `[20,12]` | `/queue tree` | |

## DHCP / DNS

| Path | Menu | Notes |
|---|---|---|
| `[23,0]` | `/ip dhcp-server` | |
| `[23,1]` | `/ip dhcp-server lease` | |
| `[14,1]` | `/ip dns cache` | |
| `[14,2]` | `/ip dns settings` | singleton |
| `[14,3]` | `/ip dns static` | |

## Tools

| Path | Menu | Notes |
|---|---|---|
| `[51]` | `/tool netwatch` | |
| `[77]` | Tools → Ping Speed | **action, not a table.** `START cmd=2` (`u1`=target ip u32, `u2`/`u3`=packet sizes) → session id (`0xFE0001`); `POLL cmd=1` + sid → `0x1`=current, `0x2`=average (bps, u8/u32); `CANCEL cmd=3` + sid. Poll without sid → error `"get: no id"` |
| `[26]` | Tools → Traceroute | mapped; native streaming invocation not fully reverse-engineered — use the terminal (`/tool traceroute`) as fallback |
| `[76]` | terminal (mepty) | arbitrary commands; see `WinboxSession.terminalSend`/`terminalExec` |

## CRUD commands

| Command | Value | Notes |
|---|---|---|
| `CMD_GET_ALL` | `0xFE0004` | needs `0xFE000C = 0x10000005` flag or the handler returns no rows |
| `CMD_ADD` | `0xFE0005` | fields only |
| `CMD_SET` | `0xFE0003` | `0xFE0001` = id + changed fields |
| `CMD_REMOVE` | `0xFE0006` | `0xFE0001` = id |
| `CMD_GET_ONE` | `0xFE0002` | |
| `CMD_GET` | `7` | capabilities-style reads |

## TAHAP 1-4 additions (2026-10-16) — 🟡 belum live-test

### Typed models & readers
- `WinboxModels.kt`: 14 data class (PppSecret, PppProfile, PppActive, InterfaceInfo,
  IpAddressRow, RouteRow, ServiceRow, QueueRow, FwRule, NetwatchRow, DhcpClientRow,
  BridgePortRow, NeighborRow, SystemInfo).
- `WinboxReaders.kt`: pure parser `M2Message -> model` + `WinboxSession.getXxx()`.
- Backward-compat: `parsePppSecret(row, profileNames)`, `parsePppActive(row)`,
  `parseInterface(row)` tetap ada sebagai alias.

### WriteResult & verifiedSet
- `WriteResult.Ok/Err/Timeout` — baca `0xFF0008` (kode) dan `0xFF0009` (pesan).
- `writeCatching { }` — wrapper runCatching → WriteResult.
- `verifiedSet(path, id, fields)` — SET lalu verifikasi baca ulang, retry 3x/300ms.
  Wajib target `0xFE0001`.
- `*Result` variant untuk **semua 53** fungsi add/set/remove di WinboxCrud.kt.
  Fungsi Boolean lama tetap ada.

### Paging
- `getAllRows()` menangani continuation `0xFE0003` (u32) / `0xFE0015` (raw).
- Legacy branch sekarang kirim continuation via param `extra` di `getAllLegacy`.
- Pure helpers: `extractRows()`, `extractContinuation()` — dites offline.

### Dump tools (examples/)
- `DumpTable.kt` — dump JSON read-only; mask password key `0x2` di `[27,101]`.
- `DiffDump.kt` — diff dua dump untuk identifikasi key.

### Interface detail [20,0] — dari .jg, BELUM live-verified
- `0x26D` MAC, `0x10064` MTU, `0x3F2` speed, `0x100D4`/`0x100D3` Tx/Rx rate.
- ⚠️ Jangan dipercaya sebelum DumpTable ke router nyata.
