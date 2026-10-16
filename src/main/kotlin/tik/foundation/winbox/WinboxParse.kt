package tik.foundation.winbox

/**
 * Typed parsing: M2Message mentah -> data class siap tampil.
 *
 * Dipindah dari WinboxRepo (app) ke lib supaya update field/parsing
 * cukup di lib — app tinggal sync & rebuild, tanpa rombak kode.
 *
 * Konvensi: semua fungsi return null kalau field kunci tidak ada
 * (baris tidak valid untuk tipe tersebut).
 */

// ---------------------------------------------------------------- data class

/** Satu baris /ppp secret [27,101]. */
data class PppSecret(
    val rowId: M2Field?,
    val name: String,
    val password: String,
    /** service sebagai u32 mentah — enum string belum dipetakan (lihat Field Inspector). */
    val serviceRaw: Long?,
    /** nama profile (di-resolve dari tabel profile via id). */
    val profile: String,
    val disabled: Boolean,
)

/** Satu baris /ppp active [27,103]. */
data class PppActive(
    val name: String,
    val callerId: String = "",
    val bytesIn: Long = 0,
    val bytesOut: Long = 0,
)

/** Queue simple [20,9] — field otoritatif dari .jg. */
data class QueueInfo(
    val name: String,
    val target: String = "",
    val dst: String = "",
    val upMax: Long?,
    val downMax: Long?,
    val rateUp: Long? = null,
    val rateDown: Long? = null,
    val comment: String,
    val disabled: Boolean,
)

/** Firewall rule — [20,3] filter / [20,5] nat / [20,7] mangle. */
data class FwRuleInfo(
    val chain: String,
    val action: String,
    val comment: String,
    val disabled: Boolean,
    val bytes: Long?,
    val packets: Long?,
)

/** IP Address [20,1]. */
data class IpAddrInfo(
    val address: String,
    val iface: String,
    val comment: String,
    val disabled: Boolean,
)

/** IP Route [44,1]. */
data class IpRouteInfo(
    val dst: String,
    val comment: String,
    val disabled: Boolean,
)

/** IP Service [68,1]. */
data class IpSvcInfo(
    val name: String,
    val port: Long?,
    val disabled: Boolean,
)

/** Hotspot User [63,1]. */
data class HsUserInfo(
    val name: String,
    val profile: String,
    val comment: String,
    val disabled: Boolean,
)

/** Hotspot Server [63,11]. */
data class HsServerInfo(
    val name: String,
    val iface: String,
    val comment: String,
    val disabled: Boolean,
)

/** Netwatch [51]. */
data class NetwatchInfo(
    val name: String,
    val status: String,
    val comment: String,
    val disabled: Boolean,
)

/** Info /system resource [24,2] (polling). Key: 0x9 cpu-load, 0x3 free-mem KB, 0x1 uptime. */
data class SysInfo(
    val cpuLoadPct: Int?,
    val freeMemKb: Long?,
    val uptimeSec: Long?,
    val identity: String = "",
    val version: String = "",
    val boardName: String = "",
    val arch: String = "",
)

/** Interface [20,0] — lib sediakan semua, app filter yang perlu ditampilkan. */
data class InterfaceInfo(
    val rowId: Long?,
    val name: String,
    val defaultName: String = "",
    val type: String = "",
    val comment: String = "",
    val disabled: Boolean = false,
)

// ---------------------------------------------------------------- parse

private fun u64safe(v: ULong?): Long? =
    v?.let { if (it > Long.MAX_VALUE.toULong()) null else it.toLong() }

/** Decode target queue: MsgArray[M2Message(0x1=U32 IP, 0x2=U32 netmask)] -> "ip/prefix, ...". */
fun decodeQueueTarget(r: M2Message): String =
    (r.first(QueueFields.TARGET)?.value as? M2Value.MsgArray)
        ?.vs?.mapNotNull { m ->
            val ip = m.u32(0x1) ?: return@mapNotNull null
            val mask = m.u32(0x2) ?: 0xFFFFFFFFL
            val prefix = (32 - java.lang.Long.numberOfTrailingZeros(mask)).coerceIn(0, 32)
            "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 8) and 0xFF}.${ip and 0xFF}/$prefix"
        }?.joinToString(", ").orEmpty()

fun parsePppSecret(r: M2Message, profileNames: Map<Long, String> = emptyMap()): PppSecret? {
    val name = r.str(m2Key(1, M2Ns.USER)) ?: return null
    val profId = r.u32(m2Key(5, M2Ns.USER)) ?: r.u8(m2Key(5, M2Ns.USER))?.toLong()
    return PppSecret(
        rowId = r.fields.firstOrNull { it.key == 0xFE0001 },
        name = name,
        password = r.str(PppSecretFields.PASSWORD) ?: "",
        serviceRaw = r.u32(m2Key(3, M2Ns.USER)) ?: r.u8(m2Key(3, M2Ns.USER))?.toLong(),
        profile = profId?.let { profileNames[it] } ?: "",
        disabled = r.bool(m2Key(0x6f, M2Ns.USER)) ?: false,
    )
}

fun parsePppActive(r: M2Message): PppActive? {
    val name = r.str(m2Key(1, M2Ns.USER)) ?: return null
    return PppActive(
        name = name,
        callerId = r.str(m2Key(3, M2Ns.USER)) ?: "",
        bytesIn = u64safe(r.u64(m2Key(9, M2Ns.USER))) ?: 0,
        bytesOut = u64safe(r.u64(m2Key(10, M2Ns.USER))) ?: 0,
    )
}

fun parseQueue(r: M2Message): QueueInfo? {
    val name = r.str(QueueFields.NAME) ?: return null
    return QueueInfo(
        name = name,
        target = decodeQueueTarget(r),
        dst = r.str(QueueFields.DST).orEmpty(),
        upMax = r.u32(QueueFields.UP_MAX) ?: u64safe(r.u64(QueueFields.UP_MAX)),
        downMax = r.u32(QueueFields.DOWN_MAX),
        // Rate live (v7): u64 0xD8 = up, 0x13C = down
        rateUp = u64safe(r.u64(0xD8)),
        rateDown = u64safe(r.u64(0x13C)),
        comment = r.str(QueueFields.COMMENT).orEmpty(),
        disabled = r.bool(QueueFields.DISABLED) ?: false,
    )
}

fun parseFwRule(r: M2Message): FwRuleInfo? {
    // chain/action key generik 0x27/0x28 — sama di filter/nat/mangle [jg]
    val ch = r.str(0x27) ?: ""
    val act = r.u8(0x28)?.toString() ?: r.u32(0x28)?.toString() ?: ""
    return FwRuleInfo(
        chain = ch,
        action = act,
        comment = r.str(0xFE0009).orEmpty(),
        disabled = r.bool(0xFE000A) ?: false,
        bytes = u64safe(r.u64(0x2710)),
        packets = u64safe(r.u64(0x2711)),
    )
}

fun parseIpAddr(r: M2Message): IpAddrInfo? {
    val addrU = r.u32(IpAddrFields.ADDRESS) ?: return null
    val ifaceId = r.u32(IpAddrFields.INTERFACE) ?: r.u8(IpAddrFields.INTERFACE)?.toLong()
    return IpAddrInfo(
        address = formatIpv4U32(addrU),
        iface = ifaceId?.toString().orEmpty(),
        comment = r.str(IpAddrFields.COMMENT).orEmpty(),
        disabled = r.bool(IpAddrFields.DISABLED) ?: false,
    )
}

fun parseIpRoute(r: M2Message): IpRouteInfo? {
    val dst = r.u32(IpRouteFields.DST) ?: return null
    return IpRouteInfo(
        dst = formatIpv4U32(dst),
        comment = r.str(IpRouteFields.COMMENT).orEmpty(),
        disabled = r.bool(IpRouteFields.DISABLED) ?: false,
    )
}

fun parseIpService(r: M2Message): IpSvcInfo? {
    val name = r.str(IpServiceFields.NAME) ?: return null
    return IpSvcInfo(
        name = name,
        port = r.u32(IpServiceFields.PORT) ?: r.u8(IpServiceFields.PORT)?.toLong(),
        disabled = r.bool(IpServiceFields.DISABLED) ?: false,
    )
}

fun parseHsUser(r: M2Message): HsUserInfo? {
    val name = r.str(HsUserFields.NAME) ?: return null
    return HsUserInfo(
        name = name,
        profile = r.u8(HsUserFields.PROFILE)?.toString().orEmpty(),
        comment = r.str(HsUserFields.COMMENT).orEmpty(),
        disabled = r.bool(HsUserFields.DISABLED) ?: false,
    )
}

fun parseHsServer(r: M2Message): HsServerInfo? {
    val name = r.str(HsServerFields.NAME) ?: return null
    return HsServerInfo(
        name = name,
        iface = r.u8(HsServerFields.INTERFACE)?.toString().orEmpty(),
        comment = r.str(HsServerFields.COMMENT).orEmpty(),
        disabled = r.bool(HsServerFields.DISABLED) ?: false,
    )
}

fun parseNetwatch(r: M2Message): NetwatchInfo? {
    val name = r.str(0xFE0009).orEmpty().ifEmpty { r.str(1).orEmpty() }
    if (name.isEmpty()) return null
    return NetwatchInfo(
        name = name,
        status = r.u8(NetwatchFields.STATUS)?.toString().orEmpty(),
        comment = r.str(NetwatchFields.COMMENT).orEmpty(),
        disabled = r.bool(NetwatchFields.DISABLED) ?: false,
    )
}

fun parseNeighbor(r: M2Message): RouterNeighbor? {
    val ip = r.u32(m2Key(1, M2Ns.USER))?.let { formatIpv4U32(it) }
    val mac = r.raw(m2Key(2, M2Ns.USER))?.joinToString(":") { "%02X".format(it) }
    val id = r.str(m2Key(6, M2Ns.USER)) ?: ""
    if (ip == null && mac == null && id.isEmpty()) return null
    return RouterNeighbor(identity = id, ip = ip, mac = mac)
}

/**
 * Parse interface [20,0]. Lib sediakan semua field yang diketahui —
 * app pilih (filter) mana yang ditampilkan di UI.
 */
fun parseInterface(r: M2Message): InterfaceInfo? {
    // Nama: 0x10006 (v7) fallback ke 0x1 (v6)
    val name = r.str(InterfaceFields.NAME)
        ?: r.str(m2Key(1, M2Ns.USER))
        ?: return null
    return InterfaceInfo(
        rowId = r.u32(InterfaceFields.ROW_ID) ?: r.u8(InterfaceFields.ROW_ID)?.toLong(),
        name = name,
        defaultName = r.str(InterfaceFields.DEFAULT_NAME).orEmpty(),
        type = r.str(InterfaceFields.TYPE).orEmpty(),
        comment = r.str(InterfaceFields.COMMENT).orEmpty(),
        disabled = r.bool(InterfaceFields.DISABLED) ?: false,
    )
}

/**
 * Parse /system identity [24,1] singleton.
 * Live v6: 0xc = identity ("Serper"), 0xd = version ("6.49.19").
 */
fun parseSystemIdentity(r: M2Message): Pair<String, String> {
    val identity = r.str(0xc).orEmpty()
    val version = r.str(0xd).orEmpty()
    return identity to version
}

/**
 * Parse /system resource [24,2] singleton.
 * Live v6/v7: 0x1 = uptime (detik), 0x3 = free mem (KB), 0x9 = cpu load (%),
 * 0x2c/0x19 = board name ("RB4011iGS+"), 0x1a = arch ("arm"), 0x16 = version ("7.24.4 (stable)").
 */
fun parseSystemResource(r: M2Message): SysInfo {
    return SysInfo(
        cpuLoadPct = r.u8(0x9)?.toInt() ?: r.u32(0x9)?.toInt(),
        freeMemKb = r.u32(0x3),
        uptimeSec = r.u32(0x1),
        version = r.str(0x16).orEmpty().substringBefore(" ").ifEmpty { r.str(0xd).orEmpty() },
        boardName = r.str(0x2c).orEmpty().ifEmpty { r.str(0x19).orEmpty() },
        arch = r.str(0x1a).orEmpty(),
    )
}
