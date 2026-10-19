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
// (PppSecret, PppActive, InterfaceInfo pindah ke WinboxModels.kt — TAHAP 2)

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

// (InterfaceInfo pindah ke WinboxModels.kt — TAHAP 2)

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



fun parseQueue(r: M2Message): QueueInfo? {
    val name = r.str(QueueFields.NAME) ?: return null
    return QueueInfo(
        name = name,
        target = decodeQueueTarget(r),
        dst = r.str(QueueFields.DST).orEmpty(),
        upMax = r.u32(QueueFields.UP_MAX) ?: u64safe(r.u64(QueueFields.UP_MAX)),
        downMax = r.u32(QueueFields.DOWN_MAX),
        // Rate live (v7): u64 0xD8 = download, 0x13C = upload
        // (arah diperbaiki 2026-10-16 sesuai kenyataan router)
        rateUp = u64safe(r.u64(0x13C)),
        rateDown = u64safe(r.u64(0xD8)),
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

/** DHCP Client [43,1] — lib sediakan semua, app filter. */
data class DhcpClientInfo(
    val rowId: Long?,
    val interfaceId: Long?,
    val usePeerDns: Boolean = true,
    val usePeerNtp: Boolean = true,
    val addDefaultRoute: Int? = null,
    val comment: String = "",
    val disabled: Boolean = false,
    // Status (read-only, dari router)
    val ipAddress: String = "",
    val gateway: String = "",
    val dhcpServer: String = "",
    val expiresAfterSec: Long? = null,
)

fun parseDhcpClient(r: M2Message): DhcpClientInfo? {
    val ifaceId = r.u32(DhcpClientFields.INTERFACE) ?: r.u8(DhcpClientFields.INTERFACE)?.toLong()
    // IP address: network → U32 IP + U32 netmask
    val ipU = r.u32(DhcpClientFields.IP_ADDRESS)
    val maskU = r.u32(DhcpClientFields.IP_NETMASK) ?: 0xFFFFFFFFL
    val ipStr = if (ipU != null) {
        val prefix = (32 - java.lang.Long.numberOfTrailingZeros(maskU)).coerceIn(0, 32)
        "${formatIpv4U32(ipU)}/$prefix"
    } else ""
    return DhcpClientInfo(
        rowId = r.u32(DhcpClientFields.ROW_ID) ?: r.u8(DhcpClientFields.ROW_ID)?.toLong(),
        interfaceId = ifaceId,
        usePeerDns = r.bool(DhcpClientFields.USE_PEER_DNS) ?: true,
        usePeerNtp = r.bool(DhcpClientFields.USE_PEER_NTP) ?: true,
        addDefaultRoute = r.u8(DhcpClientFields.ADD_DEFAULT_ROUTE)?.toInt()
            ?: r.u32(DhcpClientFields.ADD_DEFAULT_ROUTE)?.toInt(),
        comment = r.str(DhcpClientFields.COMMENT).orEmpty(),
        disabled = r.bool(DhcpClientFields.DISABLED) ?: false,
        ipAddress = ipStr,
        gateway = r.u32(DhcpClientFields.GATEWAY)?.let { formatIpv4U32(it) }.orEmpty(),
        dhcpServer = r.u32(DhcpClientFields.DHCP_SERVER)?.let { formatIpv4U32(it) }.orEmpty(),
        expiresAfterSec = r.u32(DhcpClientFields.EXPIRES_AFTER),
    )
}

/** Bridge Port [16,2] — lib sediakan semua, app filter. */
data class BridgePortInfo(
    val rowId: Long?,
    val interfaceId: Long?,
    val bridgeId: Long?,
    val horizon: Long? = null,
    val comment: String = "",
    val disabled: Boolean = false,
)

fun parseBridgePort(r: M2Message): BridgePortInfo? {
    val ifaceId = r.u32(BridgePortFields.INTERFACE) ?: r.u8(BridgePortFields.INTERFACE)?.toLong()
    ?: return null
    return BridgePortInfo(
        rowId = r.u32(BridgePortFields.ROW_ID) ?: r.u8(BridgePortFields.ROW_ID)?.toLong(),
        interfaceId = ifaceId,
        bridgeId = r.u32(BridgePortFields.BRIDGE) ?: r.u8(BridgePortFields.BRIDGE)?.toLong(),
        horizon = r.u32(BridgePortFields.HORIZON),
        comment = r.str(BridgePortFields.COMMENT).orEmpty(),
        disabled = r.bool(BridgePortFields.DISABLED) ?: false,
    )
}
