package tik.foundation.winbox

/**
 * Wrapper fitur tingkat tinggi di atas [WinboxSession]: Hotspot Active [63,13]
 * dan Logs [3,4]. Keduanya terverifikasi LIVE 2026-10-15 ke RB750Gr3
 * (definisi dari `roteros.jg`/`hotspot.jg`; lihat WINBOX-PROTOCOL.md §7).
 *
 * CATATAN desain:
 * - `getAllRows()` sadar-mode: jalur EC-SRP5 pakai [crud], jalur legacy
 *   pakai [WinboxSession.getAllLegacy]. Ini hanya untuk baca (GET_ALL);
 *   add/set/remove yang sadar-mode masih pekerjaan terpisah.
 * - IPv4 disimpan router sebagai u32 **octet-LSB** (oktet pertama = byte
 *   paling rendah; sesuai encoder webfig master.js) — mis. 192.168.88.1 =
 *   0x0158A8C0. Lihat [formatIpv4U32].
 */

/** Satu baris /ip hotspot active — read-only. */
data class HotspotActiveUser(
    /** nama login (field 0x1) */
    val user: String,
    /** IP client, dotted-quad (field 0x2, u32 octet-LSB) */
    val address: String,
    /** durasi sesi dalam detik (field 0x3) */
    val uptimeSec: Long,
    /** MAC client (field 0xb, raw 6 byte) */
    val mac: String,
    /** server hotspot (field 0x12, u8) — bisa null */
    val server: Int?,
    /** cara login, mis. "http-chap"/"mac" (field 0x13) — bisa null */
    val loginBy: String?,
)

/** Satu baris /log — read-only. */
data class LogEntry(
    /** waktu unix (field 0x1) */
    val timeUnix: Long,
    /** nama buffer, mis. "memory" (field 0x2) — bisa null */
    val buffer: String?,
    /** topik (field 0x4, u32[]) */
    val topics: List<Long>,
    /** isi pesan (field 0x3) */
    val message: String,
)

/** Ambil integer tak peduli lebar wire-nya (u8 vs u32 — bit 0 tipe M2). */
private fun M2Message.uint(key: Int): Long? = u32(key) ?: u8(key)?.toLong()

/** u32 octet-LSB → "a.b.c.d". */
fun formatIpv4U32(v: Long): String =
    listOf(v, v shr 8, v shr 16, v shr 24)
        .joinToString(".") { (it and 0xFF).toString() }

/** 6 byte → "DC:2C:6E:66:44:61" (uppercase ala WinBox). */
fun formatMac(b: ByteArray): String =
    if (b.size == 6) b.joinToString(":") { "%02X".format(it) }
    else b.joinToString("") { "%02x".format(it) }

/** Baca semua baris (GET_ALL) dari handler path, sadar-mode sesi. */
fun WinboxSession.getAllRows(handlerPath: List<Int>, withStats: Boolean = false): List<M2Message> {
    val resp = if (sessionMode.startsWith("EC-SRP5")) {
        crud(handlerPath, CMD_GET_ALL.toLong(), withStats = withStats)
    } else {
        getAllLegacy(handlerPath, withStats = withStats)
            ?: throw WinboxException("legacy getall timeout: $handlerPath")
    }
    return (resp.fields.firstOrNull { it.key == 0xFE0002 }?.value as? M2Value.MsgArray)?.vs
        ?: emptyList()
}

/**
 * Baca singleton (GET_SINGLETON 0xFE000D) — untuk objek tunggal seperti
 * /system identity, /system resource. Return null kalau tidak ada.
 */
fun WinboxSession.getSingleton(handlerPath: List<Int>): M2Message? {
    return try {
        val resp = if (sessionMode.startsWith("EC-SRP5")) {
            crud(handlerPath, CMD_GET_SINGLETON.toLong())
        } else {
            // legacy: coba getAll, ambil baris pertama
            getAllLegacy(handlerPath)?.let { legacyResp ->
                val rows = (legacyResp.fields.firstOrNull { it.key == 0xFE0002 }?.value as? M2Value.MsgArray)?.vs
                return rows?.firstOrNull()
            }
            return null
        }
        // response singleton: fields langsung di root, atau dalam MsgArray 1 elemen
        val asArray = (resp.fields.firstOrNull { it.key == 0xFE0002 }?.value as? M2Value.MsgArray)?.vs?.firstOrNull()
        asArray ?: resp
    } catch (_: Exception) {
        null
    }
}

/** Parse satu baris mentah → [HotspotActiveUser]. Pure, bisa dites offline. */
fun parseHotspotRow(row: M2Message): HotspotActiveUser = HotspotActiveUser(
    user = row.str(m2Key(1, M2Ns.USER)) ?: "?",
    address = row.uint(m2Key(2, M2Ns.USER))?.let { formatIpv4U32(it) } ?: "?",
    uptimeSec = row.uint(m2Key(3, M2Ns.USER)) ?: 0L,
    mac = row.raw(m2Key(0x0B, M2Ns.USER))?.let { formatMac(it) } ?: "?",
    server = row.u8(m2Key(0x12, M2Ns.USER)),
    loginBy = row.str(m2Key(0x13, M2Ns.USER)),
)

/** Parse satu baris mentah → [LogEntry]. Pure, bisa dites offline. */
fun parseLogRow(row: M2Message): LogEntry = LogEntry(
    timeUnix = row.uint(m2Key(1, M2Ns.USER)) ?: 0L,
    buffer = row.str(m2Key(2, M2Ns.USER)),
    topics = row.u32Array(m2Key(4, M2Ns.USER)) ?: emptyList(),
    message = row.str(m2Key(3, M2Ns.USER)) ?: "",
)

/**
 * Daftar user hotspot yang sedang aktif ([63,13]).
 * Live 2026-10-15: 6 user kebaca (field 0x1=user, 0x2=IP, 0x3=uptime,
 * 0xb=MAC, 0x12=server, 0x13=login-by).
 */
fun WinboxSession.getHotspotActive(): List<HotspotActiveUser> =
    getAllRows(listOf(63, 13)).map { parseHotspotRow(it) }

/**
 * Seluruh log router ([3,4]), sudah terurut dari router.
 * Live 2026-10-15: 316 baris (field 0x1=time u32, 0x2=buffer, 0x3=message,
 * 0x4=topics u32[]).
 */
fun WinboxSession.getLogs(): List<LogEntry> =
    getAllRows(listOf(3, 4)).map { parseLogRow(it) }
