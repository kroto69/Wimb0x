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

/** "192.0.2.99/24" → Pair("192.0.2.99", 24). Prefix default 32 bila tak ada. */
fun parseNetwork(s: String): Pair<String, Int> {
    val parts = s.trim().split("/")
    val ip = parts[0]
    val prefix = if (parts.size > 1) parts[1].toIntOrNull() ?: 32 else 32
    require(prefix in 0..32) { "prefix invalid: $s" }
    return ip to prefix
}

/** Prefix length → netmask U32 ala octet-LSB (cth. /24 → 16777215). */
fun prefixToNetmaskU32(prefix: Int): Long {
    require(prefix in 0..32)
    val mask = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
    val b0 = (mask shr 24) and 0xFF
    val b1 = (mask shr 16) and 0xFF
    val b2 = (mask shr 8) and 0xFF
    val b3 = mask and 0xFF
    return b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)
}

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
    /** Rate upload, mis. "7M"/"512k" — digabung jadi "7M/9M" (0x16 Str). */
    val rateUp: String? = null,
    /** Rate download, mis. "9M" — digabung jadi "7M/9M" (0x16 Str). */
    val rateDown: String? = null,
    /** DNS server, maks 2 (0x15 U32Array) [live v6, 2026-10-17]. */
    val dnsServers: List<String>? = null,
    /** Only-one (0x19): YES=u8:1, NO=u8:0, DEFAULT=u32:max [live v6]. */
    val onlyOne: OnlyOne? = null,
    val comment: String? = null,
    val disabled: Boolean? = null,
)

internal fun PppProfileInput.toFields() = arrayOf(
    strF(PppProfileFields.NAME, name),
    u8F(PppProfileFields.LOCAL_ADDRESS, localAddress),
    u8F(PppProfileFields.REMOTE_ADDRESS, remoteAddress),
    rateLimitField(rateUp, rateDown),
    dnsServersField(dnsServers),
    onlyOneField(onlyOne),
    strF(PppProfileFields.COMMENT, comment),
    boolF(PppProfileFields.DISABLED, disabled),
)

/** "7M"+"9M" -> Str "7M/9M". Validasi: keduanya positif via parseRateToBps. */
internal fun rateLimitField(rateUp: String?, rateDown: String?): M2Field? {
    if (rateUp == null && rateDown == null) return null
    val up = rateUp?.let { parseRateToBps(it) } ?: 0L
    val down = rateDown?.let { parseRateToBps(it) } ?: 0L
    require(up > 0 && down > 0) { "rateUp/rateDown harus positif" }
    val upStr = rateUp!!.trim()
    val downStr = rateDown!!.trim()
    return M2Field(PppProfileFields.RATE_LIMIT, M2Value.Str("$upStr/$downStr"))
}

/** List IPv4 -> U32Array. Validasi: IPv4 valid, maks 2. */
internal fun dnsServersField(servers: List<String>?): M2Field? {
    if (servers == null) return null
    require(servers.size <= 2) { "maks 2 DNS server" }
    val ips = servers.map { s ->
        require(isValidIpv4(s)) { "DNS tidak valid: $s" }
        ipToU32(s)
    }
    return M2Field(PppProfileFields.DNS_SERVER, M2Value.U32Array(ips))
}

/** OnlyOne -> tipe wire persis dump: YES=u8:1, NO=u8:0, DEFAULT=u32:max. */
internal fun onlyOneField(v: OnlyOne?): M2Field? = when (v) {
    OnlyOne.YES -> M2Field(PppProfileFields.ONLY_ONE, M2Value.U8(1))
    OnlyOne.NO -> M2Field(PppProfileFields.ONLY_ONE, M2Value.U8(0))
    OnlyOne.DEFAULT -> M2Field(PppProfileFields.ONLY_ONE, M2Value.U32(4294967295L))
    OnlyOne.UNKNOWN, null -> null
}

private val IPV4_RE = Regex("""^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$""")
internal fun isValidIpv4(s: String): Boolean {
    val m = IPV4_RE.matchEntire(s.trim()) ?: return false
    return m.groupValues.drop(1).all { (it.toIntOrNull() ?: 256) in 0..255 }
}

/** [jg] — struktur terkonfirmasi di dump v7 */
fun WinboxSession.addPppProfile(input: PppProfileInput): Boolean =
    doAdd(WinboxPaths.PPP_PROFILE, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.addPppProfileResult(input: PppProfileInput): WriteResult =
    writeCatching { addRow(WinboxPaths.PPP_PROFILE, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.setPppProfile(id: M2Field, input: PppProfileInput): Boolean =
    doSet(WinboxPaths.PPP_PROFILE, id, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.setPppProfileResult(id: M2Field, input: PppProfileInput): WriteResult =
    writeCatching { setRow(WinboxPaths.PPP_PROFILE, id, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.removePppProfile(id: M2Field): Boolean =
    doRemove(WinboxPaths.PPP_PROFILE, id)

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.removePppProfileResult(id: M2Field): WriteResult =
    writeCatching { removeRow(WinboxPaths.PPP_PROFILE, id) }

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

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.setInterfaceResult(
    id: M2Field,
    name: String? = null,
    comment: String? = null,
    disabled: Boolean? = null,
): WriteResult = writeCatching {
    setRow(
        WinboxPaths.INTERFACE, id, listOf(
            strF(InterfaceFields.NAME, name),
            strF(InterfaceFields.COMMENT, comment),
            boolF(InterfaceFields.DISABLED, disabled),
        ).filterNotNull()
    )
}

// ================= Interface options (untuk dropdown) =================

/** Satu opsi dropdown interface: index enum + nama tampilan. */
data class InterfaceOption(val index: Int, val name: String)

/**
 * Daftar interface untuk dropdown (mis. form tambah IP Address / DHCP Client).
 *
 * Index = itemId interface (0xFE0001). Nilai enum field interface di tabel
 * lain (mis. IpAddrFields.INTERFACE = 0xA) merujuk ke itemId ini.
 *
 * Terverifikasi live 2026-10-17: 111/111 baris IP (v7) + 37/38 (v6)
 * nilai 0xA-nya == itemId tepat satu interface.
 *
 * 🟡 Jalur TULIS (addIpAddress): kirim u8 bila index <= 255, u32 bila lebih
 * besar (wire: router kirim 0xA sebagai U8/U32 tergantung nilai).
 * Tes tulis 192.0.2.x/24 menunggu user.
 */
fun WinboxSession.getInterfaceOptions(): List<InterfaceOption> =
    runCatching {
        getAllRows(WinboxPaths.INTERFACE).mapNotNull { row ->
            val name = row.str(InterfaceFields.NAME) ?: return@mapNotNull null
            val idVal = row.itemId()?.value ?: return@mapNotNull null
            val idx = when (idVal) {
                is M2Value.U8 -> idVal.v
                is M2Value.U32 -> idVal.v.toInt()
                else -> return@mapNotNull null
            }
            InterfaceOption(idx, name)
        }
    }.getOrDefault(emptyList())

// ================= IP Address [20,1] — [jg] =================

data class IpAddressInput(
    val address: String? = null, // "192.168.88.1/24" — prefix ikut dikirim apa adanya
    /** 🟡 itemId interface target (0xFE0001). Encoding u8/u32 menunggu tes tulis user. */
    val interfaceIdx: Int? = null,
    val comment: String? = null,
    val disabled: Boolean? = null,
)

internal fun IpAddressInput.toFields(): Array<M2Field?> {
    val (ip, prefix) = address?.let { parseNetwork(it) } ?: (null to 32)
    // Interface 0xA: lebar variabel seperti di wire (u8 bila ≤255, u32 bila lebih).
    // Live 2026-10-17: 12 baris u8, 99 baris u32.
    val ifaceField = interfaceIdx?.let {
        if (it <= 255) M2Field(IpAddrFields.INTERFACE, M2Value.U8(it))
        else M2Field(IpAddrFields.INTERFACE, M2Value.U32(it.toLong()))
    }
    return arrayOf(
        ip?.let { M2Field(IpAddrFields.ADDRESS, M2Value.U32(ipToU32(it))) },
        ip?.let { M2Field(IpAddrFields.NETMASK, M2Value.U32(prefixToNetmaskU32(prefix))) },
        ifaceField,
        strF(IpAddrFields.COMMENT, comment),
        boolF(IpAddrFields.DISABLED, disabled),
    )
}

/** [jg] */
fun WinboxSession.addIpAddress(input: IpAddressInput): Boolean =
    doAdd(WinboxPaths.IP_ADDRESS, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.addIpAddressResult(input: IpAddressInput): WriteResult =
    writeCatching { addRow(WinboxPaths.IP_ADDRESS, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.setIpAddress(id: M2Field, input: IpAddressInput): Boolean =
    doSet(WinboxPaths.IP_ADDRESS, id, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.setIpAddressResult(id: M2Field, input: IpAddressInput): WriteResult =
    writeCatching { setRow(WinboxPaths.IP_ADDRESS, id, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.removeIpAddress(id: M2Field): Boolean =
    doRemove(WinboxPaths.IP_ADDRESS, id)

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.removeIpAddressResult(id: M2Field): WriteResult =
    writeCatching { removeRow(WinboxPaths.IP_ADDRESS, id) }

// ================= IP Route [44,1] — [jg] =================

data class IpRouteInput(
    val dst: String? = null, // "0.0.0.0/0"
    val gateway: String? = null, // IP gateway
    val distance: Long? = null,
    val comment: String? = null,
    val disabled: Boolean? = null,
)

internal fun IpRouteInput.toFields(): Array<M2Field?> {
    val gwMsg = gateway?.let {
        M2Field(IpRouteFields.GATEWAY, M2Value.MsgArray(listOf(
            M2Message(listOf(
                M2Field(0x6, M2Value.U32Array(listOf(ipToU32(it)))),
                M2Field(0x8, M2Value.U32Array(listOf(1L))),
                M2Field(0x5, M2Value.U8(2)),
            ))
        )))
    }
    return arrayOf(
        strF(IpRouteFields.DST, dst),
        gwMsg,
        u32F(IpRouteFields.DISTANCE, distance),
        strF(IpRouteFields.COMMENT, comment),
        boolF(IpRouteFields.DISABLED, disabled),
    )
}

/** [jg] */
fun WinboxSession.addIpRoute(input: IpRouteInput): Boolean =
    doAdd(WinboxPaths.IP_ROUTE, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.addIpRouteResult(input: IpRouteInput): WriteResult =
    writeCatching { addRow(WinboxPaths.IP_ROUTE, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.setIpRoute(id: M2Field, input: IpRouteInput): Boolean =
    doSet(WinboxPaths.IP_ROUTE, id, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.setIpRouteResult(id: M2Field, input: IpRouteInput): WriteResult =
    writeCatching { setRow(WinboxPaths.IP_ROUTE, id, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.removeIpRoute(id: M2Field): Boolean =
    doRemove(WinboxPaths.IP_ROUTE, id)

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.removeIpRouteResult(id: M2Field): WriteResult =
    writeCatching { removeRow(WinboxPaths.IP_ROUTE, id) }

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

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.setIpServiceResult(
    id: M2Field,
    port: Long? = null,
    disabled: Boolean? = null,
): WriteResult = writeCatching {
    setRow(
        WinboxPaths.IP_SERVICE, id, listOf(
            u32F(IpServiceFields.PORT, port),
            boolF(IpServiceFields.DISABLED, disabled),
        ).filterNotNull()
    )
}

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

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.addFwFilterResult(input: FwRuleInput): WriteResult =
    writeCatching { addRow(WinboxPaths.FIREWALL_FILTER, input.toFilterFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.setFwFilter(id: M2Field, input: FwRuleInput): Boolean =
    doSet(WinboxPaths.FIREWALL_FILTER, id, *input.toFilterFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.setFwFilterResult(id: M2Field, input: FwRuleInput): WriteResult =
    writeCatching { setRow(WinboxPaths.FIREWALL_FILTER, id, input.toFilterFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.removeFwFilter(id: M2Field): Boolean =
    doRemove(WinboxPaths.FIREWALL_FILTER, id)

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.removeFwFilterResult(id: M2Field): WriteResult =
    writeCatching { removeRow(WinboxPaths.FIREWALL_FILTER, id) }

/** [jg] */
fun WinboxSession.addFwNat(input: FwRuleInput): Boolean =
    doAdd(WinboxPaths.FIREWALL_NAT, *input.toNatFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.addFwNatResult(input: FwRuleInput): WriteResult =
    writeCatching { addRow(WinboxPaths.FIREWALL_NAT, input.toNatFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.setFwNat(id: M2Field, input: FwRuleInput): Boolean =
    doSet(WinboxPaths.FIREWALL_NAT, id, *input.toNatFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.setFwNatResult(id: M2Field, input: FwRuleInput): WriteResult =
    writeCatching { setRow(WinboxPaths.FIREWALL_NAT, id, input.toNatFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.removeFwNat(id: M2Field): Boolean =
    doRemove(WinboxPaths.FIREWALL_NAT, id)

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.removeFwNatResult(id: M2Field): WriteResult =
    writeCatching { removeRow(WinboxPaths.FIREWALL_NAT, id) }

/** [jg] */
fun WinboxSession.addFwMangle(input: FwRuleInput): Boolean =
    doAdd(WinboxPaths.FIREWALL_MANGLE, *input.toMangleFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.addFwMangleResult(input: FwRuleInput): WriteResult =
    writeCatching { addRow(WinboxPaths.FIREWALL_MANGLE, input.toMangleFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.setFwMangle(id: M2Field, input: FwRuleInput): Boolean =
    doSet(WinboxPaths.FIREWALL_MANGLE, id, *input.toMangleFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.setFwMangleResult(id: M2Field, input: FwRuleInput): WriteResult =
    writeCatching { setRow(WinboxPaths.FIREWALL_MANGLE, id, input.toMangleFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.removeFwMangle(id: M2Field): Boolean =
    doRemove(WinboxPaths.FIREWALL_MANGLE, id)

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.removeFwMangleResult(id: M2Field): WriteResult =
    writeCatching { removeRow(WinboxPaths.FIREWALL_MANGLE, id) }

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

internal fun QueueInput.toFields(): Array<M2Field?> {
    val targetMsg = target?.let {
        val (ip, prefix) = parseNetwork(it)
        M2Field(QueueFields.TARGET, M2Value.MsgArray(listOf(
            M2Message(listOf(
                M2Field(0x1, M2Value.U32(ipToU32(ip))),
                M2Field(0x2, M2Value.U32(prefixToNetmaskU32(prefix))),
            ))
        )))
    }
    return arrayOf(
        strF(QueueFields.NAME, name),
        targetMsg,
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
}

/** [jg] */
fun WinboxSession.addQueue(input: QueueInput): Boolean =
    doAdd(WinboxPaths.QUEUE_SIMPLE, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.addQueueResult(input: QueueInput): WriteResult =
    writeCatching { addRow(WinboxPaths.QUEUE_SIMPLE, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.setQueue(id: M2Field, input: QueueInput): Boolean =
    doSet(WinboxPaths.QUEUE_SIMPLE, id, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.setQueueResult(id: M2Field, input: QueueInput): WriteResult =
    writeCatching { setRow(WinboxPaths.QUEUE_SIMPLE, id, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.removeQueue(id: M2Field): Boolean =
    doRemove(WinboxPaths.QUEUE_SIMPLE, id)

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.removeQueueResult(id: M2Field): WriteResult =
    writeCatching { removeRow(WinboxPaths.QUEUE_SIMPLE, id) }

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

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.addHsUserResult(input: HsUserInput): WriteResult =
    writeCatching { addRow(WinboxPaths.HOTSPOT_USER, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.setHsUser(id: M2Field, input: HsUserInput): Boolean =
    doSet(WinboxPaths.HOTSPOT_USER, id, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.setHsUserResult(id: M2Field, input: HsUserInput): WriteResult =
    writeCatching { setRow(WinboxPaths.HOTSPOT_USER, id, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.removeHsUser(id: M2Field): Boolean =
    doRemove(WinboxPaths.HOTSPOT_USER, id)

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.removeHsUserResult(id: M2Field): WriteResult =
    writeCatching { removeRow(WinboxPaths.HOTSPOT_USER, id) }

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

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.addHsServerResult(input: HsServerInput): WriteResult =
    writeCatching { addRow(WinboxPaths.HOTSPOT_SERVER, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.setHsServer(id: M2Field, input: HsServerInput): Boolean =
    doSet(WinboxPaths.HOTSPOT_SERVER, id, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.setHsServerResult(id: M2Field, input: HsServerInput): WriteResult =
    writeCatching { setRow(WinboxPaths.HOTSPOT_SERVER, id, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.removeHsServer(id: M2Field): Boolean =
    doRemove(WinboxPaths.HOTSPOT_SERVER, id)

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.removeHsServerResult(id: M2Field): WriteResult =
    writeCatching { removeRow(WinboxPaths.HOTSPOT_SERVER, id) }

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
    address?.let { M2Field(HsBindingFields.ADDRESS, M2Value.U32(ipToU32(parseNetwork(it).first))) },
    ipF(HsBindingFields.TO_ADDRESS, toAddress),
    u8F(HsBindingFields.SERVER, serverIdx),
    u8F(HsBindingFields.TYPE, type),
    strF(HsBindingFields.COMMENT, comment),
    boolF(HsBindingFields.DISABLED, disabled),
)

/** [jg] */
fun WinboxSession.addHsBinding(input: HsBindingInput): Boolean =
    doAdd(WinboxPaths.HOTSPOT_IP_BINDING, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.addHsBindingResult(input: HsBindingInput): WriteResult =
    writeCatching { addRow(WinboxPaths.HOTSPOT_IP_BINDING, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.setHsBinding(id: M2Field, input: HsBindingInput): Boolean =
    doSet(WinboxPaths.HOTSPOT_IP_BINDING, id, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.setHsBindingResult(id: M2Field, input: HsBindingInput): WriteResult =
    writeCatching { setRow(WinboxPaths.HOTSPOT_IP_BINDING, id, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.removeHsBinding(id: M2Field): Boolean =
    doRemove(WinboxPaths.HOTSPOT_IP_BINDING, id)

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.removeHsBindingResult(id: M2Field): WriteResult =
    writeCatching { removeRow(WinboxPaths.HOTSPOT_IP_BINDING, id) }

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
    u8F(NetwatchFields.INTERVAL, intervalSec?.toInt()),
    u32F(NetwatchFields.TIMEOUT, timeoutMs),
    strF(NetwatchFields.UP_SCRIPT, upScript),
    strF(NetwatchFields.DOWN_SCRIPT, downScript),
    boolF(NetwatchFields.DISABLED, disabled),
)

/** [jg] */
fun WinboxSession.addNetwatch(input: NetwatchInput): Boolean =
    doAdd(WinboxPaths.NETWATCH, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.addNetwatchResult(input: NetwatchInput): WriteResult =
    writeCatching { addRow(WinboxPaths.NETWATCH, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.setNetwatch(id: M2Field, input: NetwatchInput): Boolean =
    doSet(WinboxPaths.NETWATCH, id, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.setNetwatchResult(id: M2Field, input: NetwatchInput): WriteResult =
    writeCatching { setRow(WinboxPaths.NETWATCH, id, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.removeNetwatch(id: M2Field): Boolean =
    doRemove(WinboxPaths.NETWATCH, id)

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.removeNetwatchResult(id: M2Field): WriteResult =
    writeCatching { removeRow(WinboxPaths.NETWATCH, id) }

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

/** [jg] Result variant — 🟡 belum live-test. */
fun WinboxSession.addDhcpClientResult(input: DhcpClientInput): WriteResult = writeCatching {
    addRow(
        WinboxPaths.IP_DHCP_CLIENT, listOf(
            u8F(0x2, input.interfaceIdx),
            boolF(0xBD, input.usePeerDns),
            u8F(0x12, input.addDefaultRoute),
            strF(0xFE0009, input.comment),
            boolF(0xFE000A, input.disabled),
        ).filterNotNull()
    )
}

/** [jg] */
fun WinboxSession.setDhcpClient(id: M2Field, input: DhcpClientInput): Boolean = doSet(
    WinboxPaths.IP_DHCP_CLIENT, id,
    u8F(0x2, input.interfaceIdx),
    boolF(0xBD, input.usePeerDns),
    u8F(0x12, input.addDefaultRoute),
    strF(0xFE0009, input.comment),
    boolF(0xFE000A, input.disabled),
)

/** [jg] Result variant — 🟡 belum live-test. */
fun WinboxSession.setDhcpClientResult(id: M2Field, input: DhcpClientInput): WriteResult = writeCatching {
    setRow(
        WinboxPaths.IP_DHCP_CLIENT, id, listOf(
            u8F(0x2, input.interfaceIdx),
            boolF(0xBD, input.usePeerDns),
            u8F(0x12, input.addDefaultRoute),
            strF(0xFE0009, input.comment),
            boolF(0xFE000A, input.disabled),
        ).filterNotNull()
    )
}

/** [jg] */
fun WinboxSession.removeDhcpClient(id: M2Field): Boolean =
    doRemove(WinboxPaths.IP_DHCP_CLIENT, id)

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.removeDhcpClientResult(id: M2Field): WriteResult =
    writeCatching { removeRow(WinboxPaths.IP_DHCP_CLIENT, id) }

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

/** [jg] Result variant — 🟡 belum live-test. */
fun WinboxSession.addBridgePortResult(input: BridgePortInput): WriteResult = writeCatching {
    addRow(
        WinboxPaths.BRIDGE_PORT, listOf(
            u8F(0x3, input.interfaceIdx),
            u8F(0x4, input.bridgeIdx),
            strF(0xFE0009, input.comment),
            boolF(0xFE000A, input.disabled),
        ).filterNotNull()
    )
}

/** [jg] */
fun WinboxSession.setBridgePort(id: M2Field, input: BridgePortInput): Boolean = doSet(
    WinboxPaths.BRIDGE_PORT, id,
    u8F(0x3, input.interfaceIdx),
    u8F(0x4, input.bridgeIdx),
    strF(0xFE0009, input.comment),
    boolF(0xFE000A, input.disabled),
)

/** [jg] Result variant — 🟡 belum live-test. */
fun WinboxSession.setBridgePortResult(id: M2Field, input: BridgePortInput): WriteResult = writeCatching {
    setRow(
        WinboxPaths.BRIDGE_PORT, id, listOf(
            u8F(0x3, input.interfaceIdx),
            u8F(0x4, input.bridgeIdx),
            strF(0xFE0009, input.comment),
            boolF(0xFE000A, input.disabled),
        ).filterNotNull()
    )
}

/** [jg] */
fun WinboxSession.removeBridgePort(id: M2Field): Boolean =
    doRemove(WinboxPaths.BRIDGE_PORT, id)

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.removeBridgePortResult(id: M2Field): WriteResult =
    writeCatching { removeRow(WinboxPaths.BRIDGE_PORT, id) }

// ================= DNS Static [14,3] — [jg] =================

data class DnsStaticInput(
    val name: String? = null,
    val regexp: String? = null,
    val type: Int? = null, // enm
    val ttlSec: Long? = null,
    val comment: String? = null,
    val disabled: Boolean? = null,
)

private fun DnsStaticInput.toFields() = arrayOf(
    strF(DnsStaticFields.NAME, name),
    strF(DnsStaticFields.REGEXP, regexp),
    u8F(DnsStaticFields.TYPE, type),
    u32F(DnsStaticFields.TTL, ttlSec),
    strF(DnsStaticFields.COMMENT, comment),
    boolF(DnsStaticFields.DISABLED, disabled),
)

/** [jg] */
fun WinboxSession.addDnsStatic(input: DnsStaticInput): Boolean =
    doAdd(WinboxPaths.DNS_STATIC, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.addDnsStaticResult(input: DnsStaticInput): WriteResult =
    writeCatching { addRow(WinboxPaths.DNS_STATIC, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.setDnsStatic(id: M2Field, input: DnsStaticInput): Boolean =
    doSet(WinboxPaths.DNS_STATIC, id, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.setDnsStaticResult(id: M2Field, input: DnsStaticInput): WriteResult =
    writeCatching { setRow(WinboxPaths.DNS_STATIC, id, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.removeDnsStatic(id: M2Field): Boolean =
    doRemove(WinboxPaths.DNS_STATIC, id)

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.removeDnsStaticResult(id: M2Field): WriteResult =
    writeCatching { removeRow(WinboxPaths.DNS_STATIC, id) }

// ================= DHCP Server [23,0] — [jg] =================

data class DhcpServerInput(
    val name: String? = null,
    val interfaceId: Int? = null, // enm → row ID interface
    val leaseTimeSec: Long? = null,
    val comment: String? = null,
    val disabled: Boolean? = null,
)

private fun DhcpServerInput.toFields() = arrayOf(
    strF(DhcpServerFields.NAME, name),
    u8F(DhcpServerFields.INTERFACE, interfaceId),
    u32F(DhcpServerFields.LEASE_TIME, leaseTimeSec),
    strF(DhcpServerFields.COMMENT, comment),
    boolF(DhcpServerFields.DISABLED, disabled),
)

/** [jg] */
fun WinboxSession.addDhcpServer(input: DhcpServerInput): Boolean =
    doAdd(WinboxPaths.DHCP_SERVER, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.addDhcpServerResult(input: DhcpServerInput): WriteResult =
    writeCatching { addRow(WinboxPaths.DHCP_SERVER, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.setDhcpServer(id: M2Field, input: DhcpServerInput): Boolean =
    doSet(WinboxPaths.DHCP_SERVER, id, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.setDhcpServerResult(id: M2Field, input: DhcpServerInput): WriteResult =
    writeCatching { setRow(WinboxPaths.DHCP_SERVER, id, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.removeDhcpServer(id: M2Field): Boolean =
    doRemove(WinboxPaths.DHCP_SERVER, id)

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.removeDhcpServerResult(id: M2Field): WriteResult =
    writeCatching { removeRow(WinboxPaths.DHCP_SERVER, id) }

// ================= DHCP Network [23,2] — [jg] =================

data class DhcpNetworkInput(
    val address: String? = null, // "192.168.88.0/24"
    val gateway: String? = null,
    val dnsServers: List<String>? = null,
    val comment: String? = null,
    val disabled: Boolean? = null,
)

private fun DhcpNetworkInput.toFields(): Array<M2Field?> {
    val (ip, prefix) = address?.let { parseNetwork(it) } ?: (null to 24)
    return arrayOf(
        ip?.let { M2Field(DhcpNetworkFields.ADDRESS, M2Value.U32(ipToU32(it))) },
        ip?.let { M2Field(DhcpNetworkFields.NETMASK, M2Value.U32(prefixToNetmaskU32(prefix))) },
        gateway?.let { M2Field(DhcpNetworkFields.GATEWAY, M2Value.U32(ipToU32(it))) },
        dnsServers?.let { M2Field(DhcpNetworkFields.DNS_SERVERS,
            M2Value.U32Array(it.map { s -> ipToU32(s) })) },
        strF(DhcpNetworkFields.COMMENT, comment),
        boolF(DhcpNetworkFields.DISABLED, disabled),
    )
}

/** [jg] */
fun WinboxSession.addDhcpNetwork(input: DhcpNetworkInput): Boolean =
    doAdd(WinboxPaths.DHCP_NETWORK, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.addDhcpNetworkResult(input: DhcpNetworkInput): WriteResult =
    writeCatching { addRow(WinboxPaths.DHCP_NETWORK, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.setDhcpNetwork(id: M2Field, input: DhcpNetworkInput): Boolean =
    doSet(WinboxPaths.DHCP_NETWORK, id, *input.toFields())

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.setDhcpNetworkResult(id: M2Field, input: DhcpNetworkInput): WriteResult =
    writeCatching { setRow(WinboxPaths.DHCP_NETWORK, id, input.toFields().filterNotNull()) }

/** [jg] */
fun WinboxSession.removeDhcpNetwork(id: M2Field): Boolean =
    doRemove(WinboxPaths.DHCP_NETWORK, id)

/** [live] Result variant — 🟡 belum live-test. */
fun WinboxSession.removeDhcpNetworkResult(id: M2Field): WriteResult =
    writeCatching { removeRow(WinboxPaths.DHCP_NETWORK, id) }
