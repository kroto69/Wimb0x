package tik.foundation.winbox

/**
 * Typed CRUD untuk semua tabel utama — TETAP via protokol WinBox
 * (addRow/setRow/removeRow di WinboxOps.kt, mode-aware EC-SRP5/legacy).
 *
 * Setiap fungsi mengembalikan true bila router merespons (non-null).
 * Field yang null = tidak dikirim (untuk SET: tidak diubah).
 *
 * Tingkat validasi per tabel:
 * - [live] = sudah dites tulis/hapus ke router beneran.
 * - [jg]   = field dari definisi resmi .jg, struktur terkonfirmasi di dump
 *            tapi operasi tulisnya belum dites live satu-satu.
 */

// ---------- helper internal ----------

private fun strF(key: Int, v: String?): M2Field? =
    v?.let { M2Field(key, M2Value.Str(it)) }

private fun boolF(key: Int, v: Boolean?): M2Field? =
    v?.let { M2Field(key, M2Value.Bool(it)) }

private fun u8F(key: Int, v: Int?): M2Field? =
    v?.let { M2Field(key, M2Value.U8(it)) }

private fun u32F(key: Int, v: Long?): M2Field? =
    v?.let { M2Field(key, M2Value.U32(it)) }

private fun ipF(key: Int, v: String?): M2Field? =
    v?.let { M2Field(key, M2Value.U32(ipToU32(it))) }

private fun WinboxSession.doAdd(path: List<Int>, vararg fields: M2Field?): Boolean =
    runCatching { addRow(path, fields.filterNotNull()) != null }.getOrDefault(false)

private fun WinboxSession.doSet(path: List<Int>, id: M2Field, vararg fields: M2Field?): Boolean =
    runCatching { setRow(path, id, fields.filterNotNull()) != null }.getOrDefault(false)

private fun WinboxSession.doRemove(path: List<Int>, id: M2Field): Boolean =
    runCatching { removeRow(path, id) != null }.getOrDefault(false)

/** "20M"/"512K"/"1500" → bps. */
fun parseRateToBps(s: String): Long {
    val t = s.trim().uppercase()
    val mult = when {
        t.endsWith("G") -> 1_000_000_000L
        t.endsWith("M") -> 1_000_000L
        t.endsWith("K") -> 1_000L
        else -> 1L
    }
    val num = t.trimEnd('G', 'M', 'K').toLongOrNull() ?: 0L
    return num * mult
}

// ================= PPP Secret [27,101] — [live] CRUD 10/10 =================

data class PppSecretInput(
    val name: String? = null,
    val password: String? = null,
    val service: Int? = null, // u8; 3 = PPPoE (teramati)
    val profileId: Long? = null, // u32 — id profile dari getAllRows(PPP_PROFILE)
    val callerId: String? = null,
    val comment: String? = null,
    val disabled: Boolean? = null,
)

internal fun PppSecretInput.toFields() = arrayOf(
    strF(PppSecretFields.NAME, name),
    strF(PppSecretFields.PASSWORD, password),
    u8F(PppSecretFields.SERVICE, service),
    u32F(PppSecretFields.PROFILE, profileId),
    strF(PppSecretFields.CALLER_ID, callerId),
    strF(PppSecretFields.COMMENT, comment),
    boolF(PppSecretFields.DISABLED, disabled),
)

/** [live] */
fun WinboxSession.addPppSecret(input: PppSecretInput): Boolean =
    doAdd(WinboxPaths.PPP_SECRET, *input.toFields())

/** [live] */
fun WinboxSession.setPppSecret(id: M2Field, input: PppSecretInput): Boolean =
    doSet(WinboxPaths.PPP_SECRET, id, *input.toFields())

/** [live] */
fun WinboxSession.removePppSecret(id: M2Field): Boolean =
    doRemove(WinboxPaths.PPP_SECRET, id)

// ================= PPP Profile [27,102] — [jg]+[live-dump] =================

data class PppProfileInput(
    val name: String? = null,
    val localAddress: Int? = null, // u8 enm
    val remoteAddress: Int? = null, // u8 enm
    val comment: String? = null,
    val disabled: Boolean? = null,
)

internal fun PppProfileInput.toFields() = arrayOf(
    strF(PppProfileFields.NAME, name),
    u8F(PppProfileFields.LOCAL_ADDRESS, localAddress),
    u8F(PppProfileFields.REMOTE_ADDRESS, remoteAddress),
    strF(PppProfileFields.COMMENT, comment),
    boolF(PppProfileFields.DISABLED, disabled),
)

/** [jg] — struktur terkonfirmasi di dump v7 */
fun WinboxSession.addPppProfile(input: PppProfileInput): Boolean =
    doAdd(WinboxPaths.PPP_PROFILE, *input.toFields())

/** [jg] */
fun WinboxSession.setPppProfile(id: M2Field, input: PppProfileInput): Boolean =
    doSet(WinboxPaths.PPP_PROFILE, id, *input.toFields())

/** [jg] */
fun WinboxSession.removePppProfile(id: M2Field): Boolean =
    doRemove(WinboxPaths.PPP_PROFILE, id)

// ================= Interface [20,0] — SET saja — [live-dump] =================

/**
 * Interface fisik tidak bisa add/remove — hanya SET.
 * [live] field terkonfirmasi di dump v7 (163 rows).
 */
fun WinboxSession.setInterface(
    id: M2Field,
    name: String? = null,
    comment: String? = null,
    disabled: Boolean? = null,
): Boolean = doSet(
    WinboxPaths.INTERFACE, id,
    strF(InterfaceFields.NAME, name),
    strF(InterfaceFields.COMMENT, comment),
    boolF(InterfaceFields.DISABLED, disabled),
)

// ================= IP Address [20,1] — [jg] =================

data class IpAddressInput(
    val address: String? = null, // "192.168.88.1/24" — prefix ikut dikirim apa adanya
    val interfaceIdx: Int? = null, // u8 enm → index interface
    val comment: String? = null,
    val disabled: Boolean? = null,
)

internal fun IpAddressInput.toFields() = arrayOf(
    strF(IpAddrFields.ADDRESS, address),
    u8F(IpAddrFields.INTERFACE, interfaceIdx),
    strF(IpAddrFields.COMMENT, comment),
    boolF(IpAddrFields.DISABLED, disabled),
)

/** [jg] */
fun WinboxSession.addIpAddress(input: IpAddressInput): Boolean =
    doAdd(WinboxPaths.IP_ADDRESS, *input.toFields())

/** [jg] */
fun WinboxSession.setIpAddress(id: M2Field, input: IpAddressInput): Boolean =
    doSet(WinboxPaths.IP_ADDRESS, id, *input.toFields())

/** [jg] */
fun WinboxSession.removeIpAddress(id: M2Field): Boolean =
    doRemove(WinboxPaths.IP_ADDRESS, id)

// ================= IP Route [44,1] — [jg] =================

data class IpRouteInput(
    val dst: String? = null, // "0.0.0.0/0"
    val gateway: String? = null, // IP gateway
    val distance: Long? = null,
    val comment: String? = null,
    val disabled: Boolean? = null,
)

internal fun IpRouteInput.toFields() = arrayOf(
    strF(IpRouteFields.DST, dst),
    ipF(IpRouteFields.GATEWAY, gateway),
    u32F(IpRouteFields.DISTANCE, distance),
    strF(IpRouteFields.COMMENT, comment),
    boolF(IpRouteFields.DISABLED, disabled),
)

/** [jg] */
fun WinboxSession.addIpRoute(input: IpRouteInput): Boolean =
    doAdd(WinboxPaths.IP_ROUTE, *input.toFields())

/** [jg] */
fun WinboxSession.setIpRoute(id: M2Field, input: IpRouteInput): Boolean =
    doSet(WinboxPaths.IP_ROUTE, id, *input.toFields())

/** [jg] */
fun WinboxSession.removeIpRoute(id: M2Field): Boolean =
    doRemove(WinboxPaths.IP_ROUTE, id)

// ================= IP Service [68,1] — SET saja — [jg] =================

/** Service list tetap — hanya SET (port/enable). [jg] */
fun WinboxSession.setIpService(
    id: M2Field,
    port: Long? = null,
    disabled: Boolean? = null,
): Boolean = doSet(
    WinboxPaths.IP_SERVICE, id,
    u32F(IpServiceFields.PORT, port),
    boolF(IpServiceFields.DISABLED, disabled),
)

// ================= Firewall [20,3]/[20,5]/[20,7] — [jg] =================

data class FwRuleInput(
    val chain: String? = null,
    val action: Int? = null, // enm — mapping angka dari .jg
    val srcAddress: String? = null,
    val dstAddress: String? = null,
    val protocol: String? = null, // "tcp"/"udp"/"icmp"
    val srcPort: String? = null,
    val dstPort: String? = null,
    val inInterface: String? = null,
    val outInterface: String? = null,
    val comment: String? = null,
    val disabled: Boolean? = null,
)

internal fun FwRuleInput.toFilterFields() = arrayOf(
    strF(FwFilterFields.CHAIN, chain),
    u8F(FwFilterFields.ACTION, action),
    strF(FwFilterFields.SRC_ADDRESS, srcAddress),
    strF(FwFilterFields.DST_ADDRESS, dstAddress),
    strF(FwFilterFields.PROTOCOL, protocol),
    strF(FwFilterFields.SRC_PORT, srcPort),
    strF(FwFilterFields.DST_PORT, dstPort),
    strF(FwFilterFields.IN_INTERFACE, inInterface),
    strF(FwFilterFields.OUT_INTERFACE, outInterface),
    strF(FwFilterFields.COMMENT, comment),
    boolF(FwFilterFields.DISABLED, disabled),
)

private fun FwRuleInput.toNatFields() = arrayOf(
    strF(FwNatFields.CHAIN, chain),
    u8F(FwNatFields.ACTION, action),
    strF(FwNatFields.COMMENT, comment),
    boolF(FwNatFields.DISABLED, disabled),
)

private fun FwRuleInput.toMangleFields() = arrayOf(
    strF(FwMangleFields.CHAIN, chain),
    u8F(FwMangleFields.ACTION, action),
    strF(FwMangleFields.COMMENT, comment),
    boolF(FwMangleFields.DISABLED, disabled),
)

/** [jg] */
fun WinboxSession.addFwFilter(input: FwRuleInput): Boolean =
    doAdd(WinboxPaths.FIREWALL_FILTER, *input.toFilterFields())

/** [jg] */
fun WinboxSession.setFwFilter(id: M2Field, input: FwRuleInput): Boolean =
    doSet(WinboxPaths.FIREWALL_FILTER, id, *input.toFilterFields())

/** [jg] */
fun WinboxSession.removeFwFilter(id: M2Field): Boolean =
    doRemove(WinboxPaths.FIREWALL_FILTER, id)

/** [jg] */
fun WinboxSession.addFwNat(input: FwRuleInput): Boolean =
    doAdd(WinboxPaths.FIREWALL_NAT, *input.toNatFields())

/** [jg] */
fun WinboxSession.setFwNat(id: M2Field, input: FwRuleInput): Boolean =
    doSet(WinboxPaths.FIREWALL_NAT, id, *input.toNatFields())

/** [jg] */
fun WinboxSession.removeFwNat(id: M2Field): Boolean =
    doRemove(WinboxPaths.FIREWALL_NAT, id)

/** [jg] */
fun WinboxSession.addFwMangle(input: FwRuleInput): Boolean =
    doAdd(WinboxPaths.FIREWALL_MANGLE, *input.toMangleFields())

/** [jg] */
fun WinboxSession.setFwMangle(id: M2Field, input: FwRuleInput): Boolean =
    doSet(WinboxPaths.FIREWALL_MANGLE, id, *input.toMangleFields())

/** [jg] */
fun WinboxSession.removeFwMangle(id: M2Field): Boolean =
    doRemove(WinboxPaths.FIREWALL_MANGLE, id)

// ================= Simple Queue [20,9] — [jg] =================

data class QueueInput(
    val name: String? = null,
    val target: String? = null, // "192.168.88.0/24"
    val dstAddress: String? = null, // "192.168.90.21/32"
    val parent: Int? = null, // enm — index parent queue
    val upMaxBps: Long? = null,
    val downMaxBps: Long? = null,
    val upLimitAtBps: Long? = null,
    val downLimitAtBps: Long? = null,
    val priority: Int? = null, // 1-8
    val comment: String? = null,
    val disabled: Boolean? = null,
)

internal fun QueueInput.toFields() = arrayOf(
    strF(QueueFields.NAME, name),
    strF(QueueFields.TARGET, target),
    strF(QueueFields.DST, dstAddress),
    u8F(QueueFields.PARENT, parent),
    u32F(QueueFields.UP_MAX, upMaxBps),
    u32F(QueueFields.DOWN_MAX, downMaxBps),
    u32F(QueueFields.UP_LIMIT_AT, upLimitAtBps),
    u32F(QueueFields.DOWN_LIMIT_AT, downLimitAtBps),
    u8F(QueueFields.UP_PRIORITY, priority),
    u8F(QueueFields.DOWN_PRIORITY, priority),
    strF(QueueFields.COMMENT, comment),
    boolF(QueueFields.DISABLED, disabled),
)

/** [jg] */
fun WinboxSession.addQueue(input: QueueInput): Boolean =
    doAdd(WinboxPaths.QUEUE_SIMPLE, *input.toFields())

/** [jg] */
fun WinboxSession.setQueue(id: M2Field, input: QueueInput): Boolean =
    doSet(WinboxPaths.QUEUE_SIMPLE, id, *input.toFields())

/** [jg] */
fun WinboxSession.removeQueue(id: M2Field): Boolean =
    doRemove(WinboxPaths.QUEUE_SIMPLE, id)

// ================= Hotspot User [63,1] — [jg] =================

data class HsUserInput(
    val name: String? = null,
    val password: String? = null,
    val profileId: Long? = null, // enm → id dari [63,14]
    val comment: String? = null,
    val disabled: Boolean? = null,
)

internal fun HsUserInput.toFields() = arrayOf(
    strF(HsUserFields.NAME, name),
    strF(HsUserFields.PASSWORD, password),
    u32F(HsUserFields.PROFILE, profileId),
    strF(HsUserFields.COMMENT, comment),
    boolF(HsUserFields.DISABLED, disabled),
)

/** [jg] */
fun WinboxSession.addHsUser(input: HsUserInput): Boolean =
    doAdd(WinboxPaths.HOTSPOT_USER, *input.toFields())

/** [jg] */
fun WinboxSession.setHsUser(id: M2Field, input: HsUserInput): Boolean =
    doSet(WinboxPaths.HOTSPOT_USER, id, *input.toFields())

/** [jg] */
fun WinboxSession.removeHsUser(id: M2Field): Boolean =
    doRemove(WinboxPaths.HOTSPOT_USER, id)

// ================= Hotspot Server [63,11] — [jg] =================

data class HsServerInput(
    val name: String? = null,
    val interfaceIdx: Int? = null, // enm → index interface
    val comment: String? = null,
    val disabled: Boolean? = null,
)

internal fun HsServerInput.toFields() = arrayOf(
    strF(HsServerFields.NAME, name),
    u8F(HsServerFields.INTERFACE, interfaceIdx),
    strF(HsServerFields.COMMENT, comment),
    boolF(HsServerFields.DISABLED, disabled),
)

/** [jg] */
fun WinboxSession.addHsServer(input: HsServerInput): Boolean =
    doAdd(WinboxPaths.HOTSPOT_SERVER, *input.toFields())

/** [jg] */
fun WinboxSession.setHsServer(id: M2Field, input: HsServerInput): Boolean =
    doSet(WinboxPaths.HOTSPOT_SERVER, id, *input.toFields())

/** [jg] */
fun WinboxSession.removeHsServer(id: M2Field): Boolean =
    doRemove(WinboxPaths.HOTSPOT_SERVER, id)

// ================= Hotspot IP Binding [63,10] — [jg] =================

data class HsBindingInput(
    val mac: String? = null, // "AA:BB:CC:DD:EE:FF"
    val address: String? = null,
    val toAddress: String? = null,
    val serverIdx: Int? = null,
    val type: Int? = null, // enm
    val comment: String? = null,
    val disabled: Boolean? = null,
)

internal fun HsBindingInput.toFields() = arrayOf(
    strF(HsBindingFields.MAC, mac),
    strF(HsBindingFields.ADDRESS, address),
    ipF(HsBindingFields.TO_ADDRESS, toAddress),
    u8F(HsBindingFields.SERVER, serverIdx),
    u8F(HsBindingFields.TYPE, type),
    strF(HsBindingFields.COMMENT, comment),
    boolF(HsBindingFields.DISABLED, disabled),
)

/** [jg] */
fun WinboxSession.addHsBinding(input: HsBindingInput): Boolean =
    doAdd(WinboxPaths.HOTSPOT_IP_BINDING, *input.toFields())

/** [jg] */
fun WinboxSession.setHsBinding(id: M2Field, input: HsBindingInput): Boolean =
    doSet(WinboxPaths.HOTSPOT_IP_BINDING, id, *input.toFields())

/** [jg] */
fun WinboxSession.removeHsBinding(id: M2Field): Boolean =
    doRemove(WinboxPaths.HOTSPOT_IP_BINDING, id)

// ================= Netwatch [51] — [jg] =================

data class NetwatchInput(
    val host: String? = null,
    val name: String? = null, // disimpan di comment
    val intervalSec: Long? = null,
    val timeoutMs: Long? = null,
    val upScript: String? = null,
    val downScript: String? = null,
    val disabled: Boolean? = null,
)

internal fun NetwatchInput.toFields() = arrayOf(
    ipF(NetwatchFields.HOST, host),
    strF(NetwatchFields.COMMENT, name),
    u32F(NetwatchFields.INTERVAL, intervalSec),
    u32F(NetwatchFields.TIMEOUT, timeoutMs),
    strF(NetwatchFields.UP_SCRIPT, upScript),
    strF(NetwatchFields.DOWN_SCRIPT, downScript),
    boolF(NetwatchFields.DISABLED, disabled),
)

/** [jg] */
fun WinboxSession.addNetwatch(input: NetwatchInput): Boolean =
    doAdd(WinboxPaths.NETWATCH, *input.toFields())

/** [jg] */
fun WinboxSession.setNetwatch(id: M2Field, input: NetwatchInput): Boolean =
    doSet(WinboxPaths.NETWATCH, id, *input.toFields())

/** [jg] */
fun WinboxSession.removeNetwatch(id: M2Field): Boolean =
    doRemove(WinboxPaths.NETWATCH, id)

// ================= DHCP Client [43,1] — [jg] =================

data class DhcpClientInput(
    val interfaceIdx: Int? = null, // enm → index interface
    val usePeerDns: Boolean? = null,
    val addDefaultRoute: Int? = null, // enm
    val comment: String? = null,
    val disabled: Boolean? = null,
)

/** [jg] */
fun WinboxSession.addDhcpClient(input: DhcpClientInput): Boolean = doAdd(
    WinboxPaths.IP_DHCP_CLIENT,
    u8F(0x2, input.interfaceIdx),
    boolF(0xBD, input.usePeerDns),
    u8F(0x12, input.addDefaultRoute),
    strF(0xFE0009, input.comment),
    boolF(0xFE000A, input.disabled),
)

/** [jg] */
fun WinboxSession.setDhcpClient(id: M2Field, input: DhcpClientInput): Boolean = doSet(
    WinboxPaths.IP_DHCP_CLIENT, id,
    u8F(0x2, input.interfaceIdx),
    boolF(0xBD, input.usePeerDns),
    u8F(0x12, input.addDefaultRoute),
    strF(0xFE0009, input.comment),
    boolF(0xFE000A, input.disabled),
)

/** [jg] */
fun WinboxSession.removeDhcpClient(id: M2Field): Boolean =
    doRemove(WinboxPaths.IP_DHCP_CLIENT, id)

// ================= Bridge Port [16,2] — [jg] =================

data class BridgePortInput(
    val interfaceIdx: Int? = null, // enm → index interface
    val bridgeIdx: Int? = null, // enm → index bridge
    val comment: String? = null,
    val disabled: Boolean? = null,
)

/** [jg] */
fun WinboxSession.addBridgePort(input: BridgePortInput): Boolean = doAdd(
    WinboxPaths.BRIDGE_PORT,
    u8F(0x3, input.interfaceIdx),
    u8F(0x4, input.bridgeIdx),
    strF(0xFE0009, input.comment),
    boolF(0xFE000A, input.disabled),
)

/** [jg] */
fun WinboxSession.setBridgePort(id: M2Field, input: BridgePortInput): Boolean = doSet(
    WinboxPaths.BRIDGE_PORT, id,
    u8F(0x3, input.interfaceIdx),
    u8F(0x4, input.bridgeIdx),
    strF(0xFE0009, input.comment),
    boolF(0xFE000A, input.disabled),
)

/** [jg] */
fun WinboxSession.removeBridgePort(id: M2Field): Boolean =
    doRemove(WinboxPaths.BRIDGE_PORT, id)
