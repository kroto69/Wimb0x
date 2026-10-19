# Models — Typed Read Models

Daftar model di `WinboxModels.kt` + parser di `WinboxReaders.kt`.

Legenda status: ✅ live-verified · 🟡 implemented, belum live-test · ⬜ UNMAPPED (nullable)

| Model | Key terpakai | Status |
|---|---|---|
| PppSecret | 0x1 (name, FieldKey), 0x2 (password), 0x3 (service), 0x5 (profileRef), 0xF (callerId), 0xFE0009 (comment), 0x6F (disabled) | 🟡 |
| PppSecret.localAddress | — | ⬜ UNMAPPED |
| PppSecret.remoteAddress | — | ⬜ UNMAPPED |
| PppProfile | FieldKey name, 0x2/0x3 (enum), 0xFE0009, 0xFE000A | 🟡 |
| PppProfile.rateLimit (0x16 Str) | "7M/9M" rx/tx [live v6+v7 2026-10-17] | ✅ |
| PppProfile.dnsServers (0x15 U32Array) | [10.9.9.9,10.8.8.8] [live v6+v7 2026-10-17] | ✅ |
| PppProfile.onlyOne (0x19) | yes=u8:1 no=u8:0 default=u32:max [live v6+v7 2026-10-17] | ✅ |
| PppProfile.parentQueue | — | ⬜ UNMAPPED |
| PppActive | FieldKey name, 0x3 (callerId), 0x9/0xA (bytesA/B u64) | 🟡 |
| PppActive arah | — | ⬜ arah bytesA/B belum terverifikasi |
| InterfaceInfo | 0x10006 (name), 0x10005, 0x1001E, 0xFE0009, 0xFE000A | 🟡 |
| InterfaceInfo.running/mac/mtu/speed/rx/tx/vlanId | — | ⬜ UNMAPPED |
| IpAddressRow | 0x1 (ip), 0x3 (netmask→prefix), 0x2 (ifaceRef) | 🟡 |
| IpAddressRow.dynamic | — | ⬜ UNMAPPED |
| RouteRow | 0x1 (dst str), 0x2E/0x6 (gateway MsgArray), 0x3F0 (distance) | 🟡 |
| RouteRow.active/dynamic | — | ⬜ UNMAPPED |
| ServiceRow | 0x1 (name, toleran str/uint), 0x2 (port, toleran) | 🟡 |
| QueueRow | 0x2 (name), 0x72 (target MsgArray), FieldKey rate, 0x36 (prio) | 🟡 |
| FwRule | 0x27 (chain), 0x28 (action), 0x1A2/0x1A3, 0x194, 0x1B7/0x1B8, 0x190/0x191, 0x2710/0x2711 | 🟡 |
| FwRule action name | — | ⬜ mapping numerik→nama UNMAPPED |
| NetwatchRow | 0x1 (host ip), 0x2 (interval), 0x4 (status) | 🟡 |
| DhcpClientRow | 0x66/0x67 (ip), 0x68 (gateway) | 🟡 |
| DhcpClientRow.dns/status | — | ⬜ UNMAPPED |
| BridgePortRow | — | ⬜ sebagian UNMAPPED (perlu resolve) |
| NeighborRow | 0x1 (ip), 0x2 (mac), 0x6 (identity) | ✅ (live 2026-10-15) |
| SystemInfo | [24,2]: 0x1, 0x3, 0x9, 0x2c/0x19, 0x1a, 0x16; [24,1]: 0xc | ✅ (live v6+v7) |
