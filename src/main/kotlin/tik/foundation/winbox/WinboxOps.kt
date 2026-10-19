package tik.foundation.winbox

/**
 * Operasi tulis mode-aware + helper fitur yang belum ada di WinboxFeatures.kt:
 * paths terpusat, add/set/remove sadar-mode, RouterNeighbor [10,1], Ping [77].
 *
 * Semua pola sudah terverifikasi live 2026-10-15 ke RB750Gr3.
 */

/** Kumpulan handler path terverifikasi (lihat WINBOX-PROTOCOL.md §7). */
object WinboxPaths {
    val LOG = listOf(3, 4)
    val IP_NEIGHBOR = listOf(10, 1)
    val PING = listOf(77)
    val TRACEROUTE = listOf(26)
    val PPP_SECRET = listOf(27, 101)
    val PPP_PROFILE = listOf(27, 102)
    val PPP_ACTIVE = listOf(27, 103)
    val IP_ADDRESS = listOf(20, 1)
    val IP_DHCP_CLIENT = listOf(43, 1)
    val DHCP_SERVER = listOf(23, 0)
    val DHCP_NETWORK = listOf(23, 2)
    val DNS_SETTINGS = listOf(14, 2)
    val DNS_STATIC = listOf(14, 3)
    val IP_SERVICE = listOf(68, 1)
    val IP_ROUTE = listOf(44, 1)
    val FIREWALL_FILTER = listOf(20, 3)
    val FIREWALL_NAT = listOf(20, 5)
    val FIREWALL_MANGLE = listOf(20, 7)
    val QUEUE_SIMPLE = listOf(20, 9)
    val INTERFACE = listOf(20, 0)
    val BRIDGE_PORT = listOf(16, 2)
    val BRIDGE_VLAN = listOf(16, 13)
    val NETWATCH = listOf(51)
    val HOTSPOT_SERVER = listOf(63, 11)
    val HOTSPOT_SERVER_PROFILE = listOf(63, 14)
    val HOTSPOT_USER = listOf(63, 1)
    val HOTSPOT_IP_BINDING = listOf(63, 10)
    val HOTSPOT_ACTIVE = listOf(63, 13)
    val SYSTEM_RESOURCE = listOf(24, 2)
    val SYSTEM_HEALTH = listOf(24, 29)
}

/** True bila sesi berjalan di jalur legacy (bukan EC-SRP5). */
private fun WinboxSession.isLegacy(): Boolean = sessionMode.startsWith("legacy")

private fun WinboxSession.sendWrite(path: List<Int>, cmd: Long, extra: List<M2Field>): M2Message? =
    try {
        if (!isLegacy()) crud(path, cmd, extra)
        else requestLegacy(
            M2Message(
                listOf(sysTo(*path.toIntArray()), sysFrom(0, 1), sysRequest(true), sysCmd(cmd)) + extra,
            ),
        )
    } catch (_: Exception) {
        null
    }

/** Tambah baris. Null bila gagal. */
fun WinboxSession.addRow(path: List<Int>, fields: List<M2Field>): M2Message? =
    sendWrite(path, CMD_ADD.toLong(), fields)

/**
 * Ubah baris. [id] WAJIB field 0xFE0001 dari GET_ALL — tanpa itu router
 * diam-diam tidak mengubah apa-apa (temuan 2026-10-15).
 */
fun WinboxSession.setRow(path: List<Int>, id: M2Field, fields: List<M2Field>): M2Message? {
    require(id.key == 0xFE0001) { "setRow butuh id 0xFE0001" }
    return sendWrite(path, CMD_SET.toLong(), listOf(id) + fields)
}

/** Hapus baris via id 0xFE0001. */
fun WinboxSession.removeRow(path: List<Int>, id: M2Field): M2Message? {
    require(id.key == 0xFE0001) { "removeRow butuh id 0xFE0001" }
    return sendWrite(path, CMD_REMOVE.toLong(), listOf(id))
}

/** Ambil field id 0xFE0001 dari baris GET_ALL (U8 atau U32). */
fun M2Message.itemId(): M2Field? =
    fields.firstOrNull { it.key == 0xFE0001 }?.let { f ->
        when (val v = f.value) {
            is M2Value.U8 -> M2Field(0xFE0001, M2Value.U8(v.v))
            is M2Value.U32 -> M2Field(0xFE0001, M2Value.U32(v.v))
            else -> null
        }
    }

/** "192.168.88.1" → u32 octet-LSB ala RouterOS. */
fun ipToU32(ip: String): Long {
    val p = ip.split(".").map { it.toLong() }
    require(p.size == 4 && p.all { it in 0..255 }) { "IP tidak valid: $ip" }
    return p[0] or (p[1] shl 8) or (p[2] shl 16) or (p[3] shl 24)
}

// ---------- /ip neighbor [10,1] ----------

/** Satu tetangga dari /ip neighbor (yang dilihat router). */
data class RouterNeighbor(
    val identity: String,
    val ip: String?,
    val mac: String?,
)

fun WinboxSession.getRouterNeighbors(): List<RouterNeighbor> =
    getAllRows(WinboxPaths.IP_NEIGHBOR).map { r ->
        RouterNeighbor(
            identity = r.str(m2Key(6, M2Ns.USER)) ?: "",
            ip = r.u32(m2Key(1, M2Ns.USER))?.let { formatIpv4U32(it) },
            mac = r.raw(m2Key(2, M2Ns.USER))?.let { formatMac(it) },
        )
    }

// ---------- Ping [77] ----------

/** Hasil satu poll ping speed (bps). */
data class PingSample(val currentBps: Long?, val averageBps: Long?)

private fun M2Message.num(key: Int): Long? = when (val v = first(key)?.value) {
    is M2Value.U8 -> v.v.toLong()
    is M2Value.U32 -> v.v
    else -> null
}

/**
 * Ping speed ala WinBox: START(2) → sid, POLL(1)+sid → data, CANCEL(3)+sid.
 * Definisi dari advtool.jg; terverifikasi live 2026-10-15.
 */
fun WinboxSession.pingStart(targetIp: String, smallPkt: Long = 32, bigPkt: Long = 1500): Int? {
    val r = sendWrite(
        WinboxPaths.PING, 2,
        listOf(
            M2Field(m2Key(1, M2Ns.USER), M2Value.U32(ipToU32(targetIp))),
            M2Field(m2Key(2, M2Ns.USER), M2Value.U32(smallPkt)),
            M2Field(m2Key(3, M2Ns.USER), M2Value.U32(bigPkt)),
        ),
    ) ?: return null
    return r.num(0xFE0001)?.toInt()
}

fun WinboxSession.pingPoll(sessionId: Int): PingSample? {
    val r = sendWrite(WinboxPaths.PING, 1, listOf(M2Field(0xFE0001, M2Value.U8(sessionId))))
        ?: return null
    if (r.str(0xFF0009) != null) return null // error, mis. "get: no id"
    return PingSample(currentBps = r.num(m2Key(1, M2Ns.USER)), averageBps = r.num(m2Key(2, M2Ns.USER)))
}

fun WinboxSession.pingStop(sessionId: Int) {
    sendWrite(WinboxPaths.PING, 3, listOf(M2Field(0xFE0001, M2Value.U8(sessionId))))
}
