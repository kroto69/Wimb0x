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
| `[13,4]` | system info | capabilities; 15 fields |

## Interface

| Path | Menu | Notes |
|---|---|---|
| `[20,0]` | `/interface` | all interfaces; bridge ports/VLANs included by type |
| `[16,2]` | `/interface bridge port` | |
| `[16,13]` | `/interface bridge vlan` | |

## PPP

| Path | Menu | Notes |
|---|---|---|
| `[27,101]` | `/ppp secret` | `0x1`: name, `0x2`: password, `0x3`: service (u32), `0x5`: profile (u32), `0x6f`: disabled (bool). **SET/REMOVE must target `0xFE0001`** (item id from GET_ALL); without it the router silently ignores the write |
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
