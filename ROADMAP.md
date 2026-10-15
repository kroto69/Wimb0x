# Roadmap — Wimb0x WinBox Library

Peta status implementasi library WinBox Kotlin (clean-room, zero dependency).
Sumber detail protokol: `docs/PROTOCOL.md`, daftar handler: `docs/HANDLERS.md`, arsitektur: `docs/ARCHITECTURE.md`.

Legenda: ✅ terverifikasi live ke router fisik · 🟡 sudah diimplementasi, belum live-test · 🔴 rencana/belum dikerjakan

## 1. Protocol core

| Area | Status | Bukti |
|---|---|---|
| Framing + codec M2 (termasuk tipe `0x98` & `0x80`) | ✅ | 57/57 unit test; interop live |
| Kriptografi AES-128-CBC / HKDF / RC4 | ✅ | interop live |
| EC-SRP5 (login modern) | 🟡 | 9/9 sama dengan referensi Python; **belum live-test ke router modern** (router tes lawas, pakai MD5) |
| Legacy MD5 fallback | ✅ | login live ke RB750Gr3 |
| Sesi TCP 8291 + login | ✅ | live |
| Generic CRUD (`getAllRows`, add/set/remove) | ✅ | PPP secret CRUD 10/10 live |
| Terminal / mepty `[76]` | ✅ | live |
| Ping `[77]` (start/poll/cancel) | ✅ | live (ke 127.0.0.1 ~32 Mbps) |
| Subscribe push + `LiveTable` | ✅ | 7/7 push ADD/SET/REMOVE, 4/4 e2e, 6/6 unit — live |
| Stats bit `0x2` (`withStats`) di GET_ALL/subscribe/liveTable | ✅ | dipakai untuk counter runtime |
| MNDP discovery (UDP 5678) | 🟡 | socket/lifecycle 6/6; **full loop solicit→receive→parse belum dites di LAN/HP fisik** (sandbox blokir UDP) |
| Resolve MAC→IP via cache MNDP (`normalizeMac`, `lookupMac`, `solicitAndResolve`) | 🟡 | 13/13 unit test; belum live-test di LAN |

> Catatan arsitektur (terverifikasi live): SUBSCRIBE hanya push **perubahan struktural** tabel.
> Perubahan nilai (CPU, traffic, sensor) **tidak pernah di-push** — app official MikroTik sendiri
> polling tiap 1 detik (`autorefresh:1000`). Jadi: subscribe untuk tabel, polling untuk nilai live.

## 2. Handler coverage

Semua path di bawah ✅ **live 2026-10-15** ke RB750Gr3, kecuali yang bertanda 🟡/🔴.

| Path | Menu | Status |
|---|---|---|
| `[3,4]` | `/log` | ✅ |
| `[13,4]` | system info / capabilities | ✅ |
| `[24,2]` | `/system resource` | ✅ (polling — subscribe ACK tapi 0 push) |
| `[24,29]` | `/system health` | ✅ (polling — subscribe ACK tapi 0 push) |
| `[20,0]` | `/interface` | ✅ |
| `[16,2]` | `/interface bridge port` | ✅ |
| `[16,13]` | `/interface bridge vlan` | ✅ |
| `[27,101]` | `/ppp secret` | ✅ (password terbaca; SET/REMOVE wajib target `0xFE0001`) |
| `[27,102]` | `/ppp profile` | ✅ |
| `[27,103]` | `/ppp active` | ✅ |
| `[20,1]` | `/ip address` | ✅ |
| `[43,1]` | `/ip dhcp-client` | ✅ |
| `[10,1]` | `/ip neighbor` | ✅ |
| `[44,1]` | `/ip route` | ✅ |
| `[68,1]` | `/ip service` | ✅ |
| `[20,8]` | `/ip arp` | ✅ |
| `[63,11]` | `/ip hotspot server` | ✅ |
| `[63,14]` | `/ip hotspot server profile` | ✅ |
| `[63,1]` | `/ip hotspot user` | ✅ |
| `[63,10]` | `/ip hotspot ip-binding` | ✅ |
| `[63,13]` | `/ip hotspot active` | ✅ |
| `[20,3]` | `/ip firewall filter` | ✅ |
| `[20,5]` | `/ip firewall nat` | ✅ |
| `[20,7]` | `/ip firewall mangle` | ✅ |
| `[20,9]` | `/queue simple` | ✅ |
| `[20,12]` | `/queue tree` | ✅ |
| `[23,0]` | `/ip dhcp-server` | ✅ |
| `[23,1]` | `/ip dhcp-server lease` | ✅ |
| `[14,1]` | `/ip dns cache` | ✅ |
| `[14,2]` | `/ip dns settings` | ✅ |
| `[14,3]` | `/ip dns static` | ✅ |
| `[51]` | `/tool netwatch` | ✅ |
| `[77]` | ping | ✅ (action; bukan tabel) |
| `[76]` | terminal (mepty) | ✅ |
| `[26]` | traceroute | 🟡 path terpetakan; **native streaming belum terpecahkan** — fallback via terminal |

## 3. Integrasi aplikasi Android (`wimb0x-app`)

| Area | Status |
|---|---|
| `SessionManager` (connect/login/disconnect + subscriber) | 🟡 ada, **belum di-wire ke UI login** |
| Login: tab Discover MNDP → ketuk MAC → resolve IP → connect | 🔴 |
| "Ingat password" + tab Saved (penyimpanan aman) | 🔴 |
| Binding data nyata ke 34 layar (sekarang masih mock) | 🔴 |
| Subscribe tabel struktural (PPP/hotspot/firewall/IP/log) | 🔴 |
| Polling traffic **hanya baris terlihat** (viewport-only) | 🔴 desain ada |
| Auto Diagnose (ping, loss/jitter, throughput vs rate-limit, verdict) | 🔴 desain ada |
| CRUD mengikuti hak akses user RouterOS | 🔴 |
| Reconnect/backoff + resubscribe + lifecycle background/foreground | 🔴 |
| Race fix: ACK `pending` terpasang sebelum kirim; listener subscribe terdaftar sebelum tunggu ACK | 🔴 |

## 4. Wajib tes di perangkat fisik sebelum klaim stabil

- [ ] MNDP solicit→receive→parse di LAN/HP asli
- [ ] EC-SRP5 login ke router modern (RouterOS 7)
- [ ] Aplikasi penuh di HP fisik (belum pernah)
- [ ] Traceroute native `[26]` atau fallback terminal yang teruji

## Riwayat verifikasi (2026-10-15)

- 18/18 handler live OK · PPP secret CRUD 10/10 · subscribe push 7/7 · `liveTable()` e2e 4/4
- Unit: 57/57 (core) · 6/6 (LiveTable) · 13/13 (MAC) · 6/6 (MNDP socket)
- Router tes: RB750Gr3 (`Serper`), RouterOS lawas — hasil di router modern bisa berbeda

- 2026-10-15 field dump live 20 tabel → `docs/FIELD-MAP-2026-10-15.md` + konstanta `WinboxFields.kt` (PPP secret ✅, firewall/queue/hotspot/netwatch 🔍).
