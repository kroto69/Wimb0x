# Field Map Dump — Items 4–8 (2026-10-17)

Dump read-only via `DumpPort` (custom, host:port) — tidak ada tulis ke router.
Router: v6 = 103.102.14.90:8988 (ROS 6.49.19, RB750Gr3, mmips),
v7 = 103.13.204.64:8987 (ROS 7.24.4, RB4011iGS+, arm).
File mentah: `docs/dumps/iface_v{6,7}.json`, `brport_v{6,7}.json`,
`dhcp_v{6,7}.json`, `log_v{6,7}.json`.

Aturan: dua-bukti (nilai masuk akal + konsisten v6/v7, atau korelasi silang).
Yang tak terverifikasi = UNMAPPED.

---

## Item 4 — Interface detail [20,0] (48 baris v6, 121 baris v7)

| Key | Tipe wire | Contoh nilai | Status |
|-----|-----------|--------------|--------|
| `0x404` | Raw 6 byte | `08:55:31:6c:6f:7a` (v6), `c4:ad:34:8d:56:b3` (v7) | **TERVERIFIKASI = MAC address** |
| `0x3E9` | Raw 6 byte | identik dengan 0x404 di semua baris | **TERVERIFIKASI = MAC (duplikat/factory)** |
| `0x10064` | U32 | `1500` (v6+v7) | **TERVERIFIKASI = MTU** (cocok .jg) |
| `0x10065` | U32 | `1596` (v6), `1592` (v7) | **TERVERIFIKASI = L2MTU** (nilai wajar, konsisten pola) |
| `0x3F2` | U8 | `2` di semua ether 1G; `3` di sfp-sfpplus1 (v7) | **TERVERIFIKASI = speed (enum)** — key cocok .jg (`enm`), tapi BUKAN bps mentah |
| `0x1000E` | Bool | True = port link-up / sesi connected; False = port no-link (ether2/3 v6, ether2/3/4/6/7/8/10 v7 — beda tiap router, realistis) | **TERVERIFIKASI = running** |
| `0x3F5` | U8 | `2` konstan di semua ether | UNMAPPED (teramati, semantik tak diketahui) |
| `0x3F3`, `0x3F4` | Bool | True di semua ether | UNMAPPED (bukan running — True juga saat link down) |

Catatan:
- `.jg` menyebut MAC = `0x26D` — **SALAH untuk data live**: 0 baris punya 0x26D
  di v6 maupun v7. MAC aktual di `0x404`.
- `0x404` hanya ada di interface L2 (ether, vlan, loopback) — tidak di
  pppoe-in/tunnel/wg. Konsisten dengan semantik MAC.
- Speed `0x3F2` adalah **enum** (2 ≈ 1G, 3 ≈ 10G/SFP+); mapping lengkap butuh
  port 100M — belum teramati.

---

## Item 5 — Bridge

| Tabel | Hasil |
|-------|-------|
| `[16,1]` | **0 baris di v6 dan v7** — bukan tabel bridge. Interface bridge dibaca dari `[20,0]` (type=`bridge`) |
| `[16,2]` bridge port | 3 baris (v6); 0 baris (v7 — tidak ada bridge terkonfigurasi) |

| Key | Tipe wire | Contoh nilai | Status |
|-----|-----------|--------------|--------|
| `0x1` | U8 | `10` di semua baris → `bridge1` (itemId 10) | **TERVERIFIKASI = bridge (itemId)** |
| `0x3` | U8 | `3,4,5` → `ether3, ether4, ether5` (itemId cocok persis) | **TERVERIFIKASI = interface (itemId)** |
| `0xFE000A` | Bool | disabled standar | TERVERIFIKASI (konvensi) |
| `0xFE0009` | Str | comment standar | TERVERIFIKASI (konvensi) |
| `0x4`, `0x12`, `0x13`, `0x14`, `0x1E`, `0xFE0005`, dll | U8/Bool | nilai kecil/konstan | UNMAPPED (satu router saja, tak cukup bukti) |

---

## Item 6 — VLAN (dari [20,0], 3 baris v6 + 3 baris v7)

| Key | Tipe wire | Contoh nilai | Status |
|-----|-----------|--------------|--------|
| `0x7D1` | U8 (≤255) / U32 (>255) | `30` (v-30IN), `313` (v313), `200` (vlan1), `203` (V-203), `79` (v-79), `100` (v-100) | **TERVERIFIKASI = VLAN ID** — 5/6 cocok dengan nama; pola lebar-variabel sama seperti enum `0xA` |
| `0x7D2` | U8 | `3`→ether3, `1`→ether1 (v6); `1`→ether1, `11`→sfp-sfpplus1 (v7) | **TERVERIFIKASI = parent interface (itemId)** — 6/6 plausible, konsisten v6/v7 |

---

## Item 7 — DHCP client [43,1] (3 baris v6 [disabled], 1 baris v7 [aktif])

| Key | Tipe wire | Contoh nilai | Status |
|-----|-----------|--------------|--------|
| `0x2` | U8 | v7: `10` + `0xFE0010`="ether10" (itemId ether10 = 10 ✅ ganda); v6: `3,1,6` → ether3, ether1, v-30IN | **TERVERIFIKASI = interface (itemId)** |
| `0xFE0010` | Str | `"ether10"` (v7) | **TERVERIFIKASI = interface (nama)** |
| `0xFE001C` | StrArray | `["Interface not active"]` (v7; ether10 memang link-down per 0x1000E) | **TERVERIFIKASI = status** |
| `0xFE000A` | Bool | disabled standar | TERVERIFIKASI (konvensi) |
| `0x12` (U8), `0xF`, `0x14`, `0xFE0012`, `0x19`, `0x21` | — | konstan/bervariasi tanpa pola jelas | UNMAPPED |
| address, gateway, DNS, netmask | — | tidak ada di dump (klien v7 tidak aktif; v6 disabled) | UNMAPPED (butuh lease aktif) |

---

## Item 8 — Log [3,4] (2000 baris v6, 1000 baris v7)

| Key | Tipe wire | Contoh nilai | Status |
|-----|-----------|--------------|--------|
| `0x4` | U32Array | `[17,1,5]`, `[13,11,1,7]`, `[9,3]` | **TERVERIFIKASI = topics (array enum)** — variasi wajar antar baris |
| `0x1` | U32 | `1791876868` → 2026-10-13 14:34 WIB | **TERVERIFIKASI = timestamp (unix)** |
| `0x3` | Str | `"->: 91bki97 (10.3.30.102): logged out: keepalive timeout"` | **TERVERIFIKASI = message** |
| `0x5` | Str | `"app=winbox duser=KianSantang outcome=success src=10.99.99.1"` (hanya v7, hanya baris account) | **TERVERIFIKASI = info akun** (detail login) |
| `0x2` | Str | `"disk"` (semua baris v6), `"memory"` (semua baris v7) | UNMAPPED (konstan per router; semantik tak pasti — diduga target aksi logging) |
| dynamic flag | — | tidak ada field Bool di 500+ baris sampel tiap versi | **UNMAPPED — tidak ada di data** |

Catatan: mapping nilai enum topics → nama ("system", "info", …) belum dipetakan;
butuh referensi enum atau DiffDump.

---

## Ringkasan cepat

**TERVERIFIKASI (siap diimplementasikan):**
- Interface: MAC (`0x404`), MTU (`0x10064`), L2MTU (`0x10065`), speed-enum (`0x3F2`), running (`0x1000E`)
- Bridge port `[16,2]`: bridge=`0x1`, interface=`0x3` (itemId)
- VLAN: vlan-id=`0x7D1` (U8/U32), parent=`0x7D2` (itemId)
- DHCP client: interface=`0x2`+`0xFE0010`, status=`0xFE001C`
- Log: topics=`0x4`, time=`0x1`, message=`0x3`, account-info=`0x5`

**Tetap UNMAPPED:** speed enum lengkap, `0x3F5`, detail bridge-port lain,
DHCP address/gateway/DNS (butuh lease aktif), log `0x2`, log dynamic flag
(tidak ada di data), mapping nama topics.
