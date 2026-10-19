package tik.foundation.winbox

/**
 * Parser murni (M2Message → model) + WinboxSession.getXxx() — 🟡 belum live-test.
 *
 * Semua parser fungsi murni, dites offline dengan M2Message buatan tangan.
 */

// ================= PPP =================

/** Parse baris [27,101] → PppSecret. */
fun parsePppSecretRow(row: M2Message): PppSecret? {
    val name = row.str(VersionedKeys.PPP_NAME) ?: return null
    val rowId = row.itemId() ?: return null
    // profileRef terima u8 ATAU u32
    val profileRef = row.uint(m2Key(5, M2Ns.USER))
    return PppSecret(
        rowId = rowId,
        name = name,
password = row.str(m2Key(2, M2Ns.USER)) ?: "",
        service = row.uint(m2Key(3, M2Ns.USER))?.toInt(),
        profileRef = profileRef,
        callerId = row.str(m2Key(0xF, M2Ns.USER)),
        comment = row.str(0xFE0009),
        disabled = row.bool(m2Key(0x6f, M2Ns.USER)) ?: false,
    )
}

fun WinboxSession.getPppSecrets(): List<PppSecret> =
    getAllRows(WinboxPaths.PPP_SECRET).mapNotNull { parsePppSecretRow(it) }

/**
 * Kompatibilitas mundur: parse + resolve nama profile dari map.
 *
 * App lama memanggil `parsePppSecret(row, profileNames)`. Fungsi ini tetap
 * ada agar app tidak rusak; diisi via [parsePppSecretRow] + resolve.
 */
fun parsePppSecret(row: M2Message, profileNames: Map<Long, String>): PppSecret? {
    val base = parsePppSecretRow(row) ?: return null
    val resolved = base.profileRef?.let { profileNames[it] }
    return base.copy(profileName = resolved)
}

/** Parse baris [27,102] → PppProfile. */
fun parsePppProfileRow(row: M2Message): PppProfile? {
    val name = row.str(VersionedKeys.PPP_NAME) ?: return null
    val rowId = row.itemId() ?: return null
    val rateLimit = row.str(PppProfileFields.RATE_LIMIT)
    // Ambil pasangan rx/tx pertama: "7M/9M" -> rx=7M (up), tx=9M (down).
    val (rateUp, rateDown) = parseRateLimitFirstPair(rateLimit)
    val dnsServers = (row.first(PppProfileFields.DNS_SERVER)?.value as? M2Value.U32Array)
        ?.vs?.map { ipU32ToString(it) } ?: emptyList()
    return PppProfile(
        rowId = rowId,
        name = name,
        localAddressEnum = row.uint(m2Key(2, M2Ns.USER))?.toInt(),
        remoteAddressEnum = row.uint(m2Key(3, M2Ns.USER))?.toInt(),
        comment = row.str(0xFE0009),
        disabled = row.bool(0xFE000A) ?: false,
        rateLimit = rateLimit,
        rateUpBps = rateUp,
        rateDownBps = rateDown,
        dnsServers = dnsServers,
        onlyOne = parseOnlyOne(row.first(PppProfileFields.ONLY_ONE)?.value),
    )
}

/**
 * Parse pasangan rx/tx pertama dari string rate-limit.
 * "7M/9M" -> (7000000, 9000000); "8M/10M 12M/16M ..." -> (8000000, 10000000).
 * Urutan rx/tx menurut dump: rx=upload klien, tx=download klien.
 */
fun parseRateLimitFirstPair(rateLimit: String?): Pair<Long?, Long?> {
    if (rateLimit.isNullOrBlank()) return null to null
    val first = rateLimit.trim().split(Regex("\\s+")).firstOrNull() ?: return null to null
    val parts = first.split("/")
    if (parts.size != 2) return null to null
    val rx = parseRateToBps(parts[0]).takeIf { it > 0 }
    val tx = parseRateToBps(parts[1]).takeIf { it > 0 }
    return rx to tx
}

/** Parse nilai only-one dari wire: u8:1=YES, u8:0=NO, u32:max=DEFAULT. */
fun parseOnlyOne(v: M2Value?): OnlyOne = when (v) {
    is M2Value.U8 -> when (v.v) {
        1 -> OnlyOne.YES
        0 -> OnlyOne.NO
        else -> OnlyOne.UNKNOWN
    }
    is M2Value.U32 -> if (v.v == 4294967295L) OnlyOne.DEFAULT else OnlyOne.UNKNOWN
    else -> OnlyOne.UNKNOWN
}

fun WinboxSession.getPppProfiles(): List<PppProfile> =
    getAllRows(WinboxPaths.PPP_PROFILE).mapNotNull { parsePppProfileRow(it) }

/** Parse baris [27,103] → PppActive. Arah bytesA/B belum disimpulkan. */
fun parsePppActiveRow(row: M2Message): PppActive? {
    val name = row.str(VersionedKeys.PPP_NAME) ?: return null
    val rowId = row.itemId() ?: return null
    return PppActive(
        rowId = rowId,
        name = name,
        callerId = row.str(m2Key(3, M2Ns.USER)),
        bytesA = (row.u64(m2Key(9, M2Ns.USER))?.toLong()) ?: 0L,
        bytesB = (row.u64(m2Key(10, M2Ns.USER))?.toLong()) ?: 0L,
    )
}

fun WinboxSession.getPppActive(): List<PppActive> =
    getAllRows(WinboxPaths.PPP_ACTIVE).mapNotNull { parsePppActiveRow(it) }

/** Alias kompatibel — app lama memanggil parsePppActive. */
fun parsePppActive(row: M2Message): PppActive? = parsePppActiveRow(row)

// ================= Interface =================

fun parseInterfaceRow(row: M2Message): InterfaceInfo? {
    val name = row.str(0x10006) ?: return null
    val rowId = row.itemId() ?: return null
    val macRaw = row.raw(InterfaceFields.MAC_ADDRESS)
    return InterfaceInfo(
        rowId = rowId,
        name = name,
        defaultName = row.str(0x10005),
        type = row.str(0x1001E),
        comment = row.str(0xFE0009),
        disabled = row.bool(0xFE000A) ?: false,
        running = row.bool(InterfaceFields.RUNNING),
        mac = macRaw?.let { formatMac(it) },
        mtu = row.uint(InterfaceFields.MTU)?.toInt(),
        l2mtu = row.uint(InterfaceFields.L2MTU)?.toInt(),
        speed = row.uint(InterfaceFields.SPEED)?.let { parseInterfaceSpeed(it) },
        vlanId = row.uint(InterfaceFields.VLAN_ID)?.toInt(),
        vlanParentId = row.uint(InterfaceFields.VLAN_PARENT),
        // Counter & rate: hanya terisi bila getAllRows withStats=true.
        // 0x100FD/0x100FC live-verified (PPPoE) 2026-10-17; 0x100D4/0x100D3 dari .jg.
        txBytes = u64s(row.u64(InterfaceFields.TX_BYTES)),
        rxBytes = u64s(row.u64(InterfaceFields.RX_BYTES)),
        txRateBps = u64s(row.u64(InterfaceFields.TX_RATE)),
        rxRateBps = u64s(row.u64(InterfaceFields.RX_RATE)),
    )
}

/** ULong -> Long aman (null bila overflow); salinan lokal u64safe (private di WinboxParse.kt). */
private fun u64s(v: ULong?): Long? =
    v?.let { if (it > Long.MAX_VALUE.toULong()) null else it.toLong() }

/**
 * Speed enum 0x3F2 → label. Live 2026-10-17: 2 di semua ether 1G,
 * 3 di sfp-sfpplus1. Mapping lengkap butuh port 100M — belum teramati.
 */
fun parseInterfaceSpeed(code: Long): String = when (code) {
    2L -> "1G"
    3L -> "10G"
    else -> "enum-$code"
}

fun WinboxSession.getInterfaces(): List<InterfaceInfo> =
    getAllRows(WinboxPaths.INTERFACE).mapNotNull { parseInterfaceRow(it) }

/** Alias kompatibel — app lama memanggil parseInterface. */
fun parseInterface(row: M2Message): InterfaceInfo? = parseInterfaceRow(row)

// ================= Bridge port =================

/**
 * Parse satu baris bridge port [16,2].
 * Live-verified 2026-10-17 (v6): 0x1=bridge itemId, 0x3=interface itemId.
 */
fun parseBridgePortRow(row: M2Message): BridgePortRow? {
    val rowId = row.itemId() ?: return null
    return BridgePortRow(
        rowId = rowId,
        bridgeId = row.uint(BridgePortFields.BRIDGE),
        interfaceId = row.uint(BridgePortFields.INTERFACE),
        interfaceName = null, // resolve via getInterfaceOptions bila perlu
        bridgeName = null,
        comment = row.str(BridgePortFields.COMMENT),
        disabled = row.bool(BridgePortFields.DISABLED) ?: false,
    )
}

fun WinboxSession.getBridgePorts(): List<BridgePortRow> =
    getAllRows(WinboxPaths.BRIDGE_PORT).mapNotNull { parseBridgePortRow(it) }

// ================= DHCP client =================

/**
 * Parse satu baris DHCP client [43,1].
 * Live-verified 2026-10-17 (v6+v7): 0x2=interface itemId,
 * 0xFE0010=nama interface, 0xFE001C=status.
 */
fun parseDhcpClientRow(row: M2Message): DhcpClientRow? {
    val rowId = row.itemId() ?: return null
    return DhcpClientRow(
        rowId = rowId,
        interfaceId = row.uint(DhcpClientFields.INTERFACE),
        interfaceName = row.str(DhcpClientFields.IFACE_NAME),
        ipAddress = null, // UNMAPPED: butuh lease aktif
        gateway = null, // UNMAPPED: butuh lease aktif
        dns = null, // UNMAPPED: butuh lease aktif
        status = row.strArray(DhcpClientFields.STATUS) ?: emptyList(),
        comment = row.str(DhcpClientFields.COMMENT),
        disabled = row.bool(DhcpClientFields.DISABLED) ?: false,
    )
}

fun WinboxSession.getDhcpClients(): List<DhcpClientRow> =
    getAllRows(WinboxPaths.IP_DHCP_CLIENT).mapNotNull { parseDhcpClientRow(it) }

/**
 * Daftar sesi PPPoE aktif dari tabel interface — pengganti [27,103].
 *
 * [27,103] counter-nya selalu 0 (tidak live). Interface `<pppoe-USERNAME>`
 * sudah memuat semua yang dibutuhkan: nama user, Tx/Rx bytes, rate.
 * Tinggal filter dari [20,0].
 *
 * @return list (username, txBytes, rxBytes, rowId)
 */
fun WinboxSession.getPppoeSessions(): List<PppoeSession> {
    val rows = getAllRows(WinboxPaths.INTERFACE, withStats = true)
    return rows.mapNotNull { row ->
        val ifName = row.str(0x10006) ?: return@mapNotNull null
        if (!ifName.startsWith("<pppoe-") || !ifName.endsWith(">")) return@mapNotNull null
        val username = row.str(InterfaceFields.PPPOE_USER) ?: ifName.removePrefix("<pppoe-").removeSuffix(">")
        val tx = row.u64(InterfaceFields.TX_BYTES)?.toLong() ?: 0L
        val rx = row.u64(InterfaceFields.RX_BYTES)?.toLong() ?: 0L
        val rowId = row.itemId() ?: return@mapNotNull null
        PppoeSession(
            username = username,
            interfaceName = ifName,
            txBytes = tx,
            rxBytes = rx,
            rowId = rowId,
            callerId = row.str(InterfaceFields.PPPOE_CALLER_ID),
            localAddress = row.u32(InterfaceFields.PPPOE_LOCAL_ADDR)?.let { ipU32ToString(it) },
            remoteAddress = row.u32(InterfaceFields.PPPOE_REMOTE_ADDR)?.let { ipU32ToString(it) },
            uptimeSec = row.u32(InterfaceFields.PPPOE_UPTIME),
            status = row.str(InterfaceFields.PPPOE_STATUS),
        )
    }
}

/** Sesi PPPoE dari tabel interface. */
data class PppoeSession(
    val username: String,
    val interfaceName: String,
    /** Tx bytes (0x100FD) = download klien. */
    val txBytes: Long,
    /** Rx bytes (0x100FC) = upload klien. */
    val rxBytes: Long,
    val rowId: M2Field,
    /** Rate download bps (dihitung app via polling). */
    val rateInBps: Long? = null,
    /** Rate upload bps (dihitung app via polling). */
    val rateOutBps: Long? = null,
    /** Caller ID / MAC (0xB0006). */
    val callerId: String? = null,
    /** Local address (0xB0009). */
    val localAddress: String? = null,
    /** Remote address (0xB000A). */
    val remoteAddress: String? = null,
    /** Uptime detik (0xB0002). */
    val uptimeSec: Long? = null,
    /** Status (0xB0004), mis. "connected". */
    val status: String? = null,
) {
    /** Alias untuk UI: name = username. */
    val name: String get() = username
}

// getInterfaceOptions sudah ada di WinboxCrud.kt (return List<InterfaceOption>) — pakai itu.

// ================= IP =================

fun parseIpAddressRow(row: M2Message, ifaceNames: Map<Long, String> = emptyMap()): IpAddressRow? {
    val rowId = row.itemId() ?: return null
    val ip = row.u32(m2Key(1, M2Ns.USER)) ?: return null
    val mask = row.u32(m2Key(3, M2Ns.USER)) ?: 0xFFFFFFFFL
    val prefix = netmaskU32ToPrefix(mask) ?: return null // mask tidak kontigu → baris invalid
    // 0xA = enum interface → itemId interface (0xFE0001).
    // Terverifikasi live 2026-10-17: 111/111 (v7) + 37/38 (v6, 1 sisa IP yatim).
    // JANGAN pakai 0x2 (itu NETWORK, bukan interface) — bug lama.
    val ifaceRef = row.uint(IpAddrFields.INTERFACE)
    return IpAddressRow(
        rowId = rowId,
        address = "${formatIpv4U32(ip)}/$prefix",
        interfaceRef = ifaceRef?.toInt(),
        interfaceName = ifaceRef?.let { ifaceNames[it] },
        comment = row.str(0xFE0009),
        disabled = row.bool(0xFE000A) ?: false,
    )
}

/**
 * Resolve nama interface dari nilai enum 0xA tabel IP.
 *
 * Pure function — tidak menyentuh router. Enum 0xA == itemId (0xFE0001)
 * baris interface; terverifikasi live 2026-10-17 (148/149 pasangan).
 */
fun resolveInterfaceName(enumValue: Long, options: List<InterfaceOption>): String? =
    options.firstOrNull { it.index.toLong() == enumValue }?.name

fun WinboxSession.getIpAddresses(): List<IpAddressRow> {
    val ifaceMap = getInterfaceOptions().associate { it.index.toLong() to it.name }
    return getAllRows(WinboxPaths.IP_ADDRESS).mapNotNull { parseIpAddressRow(it, ifaceMap) }
}

/** Parse gateway dari MsgArray 0x2E: sub-key 0x6 U32Array → elemen pertama → ip. */
private fun parseGateway(row: M2Message): String? {
    val arr = row.fields.firstOrNull { it.key == m2Key(0x2E, M2Ns.USER) }?.value
        as? M2Value.MsgArray ?: return null
    val first = arr.vs.firstOrNull() ?: return null
    val u32arr = first.fields.firstOrNull { it.key == m2Key(6, M2Ns.USER) }?.value
        as? M2Value.U32Array ?: return null
    return u32arr.vs.firstOrNull()?.let { formatIpv4U32(it) }
}

fun parseRouteRow(row: M2Message): RouteRow? {
    val rowId = row.itemId() ?: return null
    return RouteRow(
        rowId = rowId,
        dst = row.str(m2Key(1, M2Ns.USER)),
        gateway = parseGateway(row),
        distance = row.uint(0x3F0)?.toInt(),
        comment = row.str(0xFE0009),
        disabled = row.bool(0xFE000A) ?: false,
    )
}

fun WinboxSession.getRoutes(): List<RouteRow> =
    getAllRows(WinboxPaths.IP_ROUTE).mapNotNull { parseRouteRow(it) }

/**
 * Parse service — toleran tipe (docs bertentangan string/number vs u8).
 * Coba str dulu, lalu uint.
 */
fun parseServiceRow(row: M2Message): ServiceRow? {
    val rowId = row.itemId() ?: return null
    // name: coba str lalu uint→string
    val name = row.str(m2Key(1, M2Ns.USER))
        ?: row.uint(m2Key(1, M2Ns.USER))?.toString()
        ?: return null
    // port: coba uint lalu str→int
    val port = row.uint(m2Key(2, M2Ns.USER))?.toInt()
        ?: row.str(m2Key(2, M2Ns.USER))?.toIntOrNull()
    return ServiceRow(
        rowId = rowId,
        name = name,
        port = port,
        disabled = row.bool(0xFE000A) ?: false,
    )
}

fun WinboxSession.getServices(): List<ServiceRow> =
    getAllRows(WinboxPaths.IP_SERVICE).mapNotNull { parseServiceRow(it) }

// ================= Queue =================

/** Parse target dari MsgArray 0x72: sub 0x1 u32 ip + sub 0x2 u32 netmask → "ip/prefix". */
private fun parseQueueTarget(row: M2Message): String? {
    val arr = row.fields.firstOrNull { it.key == m2Key(0x72, M2Ns.USER) }?.value
        as? M2Value.MsgArray ?: return null
    val first = arr.vs.firstOrNull() ?: return null
    val ip = first.u32(m2Key(1, M2Ns.USER)) ?: return null
    val mask = first.u32(m2Key(2, M2Ns.USER)) ?: 0xFFFFFFFFL
    val prefix = netmaskU32ToPrefix(mask) ?: return null
    return "${formatIpv4U32(ip)}/$prefix"
}

fun parseQueueRow(row: M2Message): QueueRow? {
    val name = row.str(m2Key(2, M2Ns.USER)) ?: return null
    val rowId = row.itemId() ?: return null
    // Rate via FieldKey: v7 u64, v6 u32
    val upV7 = row.u64fk(VersionedKeys.QUEUE_RATE_UP)?.toLong()
    val upV6 = if (upV7 == null) row.uint(VersionedKeys.QUEUE_RATE_UP) else null
    val downV7 = row.u64fk(VersionedKeys.QUEUE_RATE_DOWN)?.toLong()
    val downV6 = if (downV7 == null) row.uint(VersionedKeys.QUEUE_RATE_DOWN) else null
    return QueueRow(
        rowId = rowId,
        name = name,
        target = parseQueueTarget(row),
        maxUpBps = upV7 ?: upV6,
        maxDownBps = downV7 ?: downV6,
        priority = row.uint(m2Key(0x36, M2Ns.USER))?.toInt(),
        comment = row.str(0xFE0009),
        disabled = row.bool(0xFE000A) ?: false,
    )
}

fun WinboxSession.getQueues(): List<QueueRow> =
    getAllRows(WinboxPaths.QUEUE_SIMPLE).mapNotNull { parseQueueRow(it) }

// ================= Firewall =================

/** Parse rule firewall generik (filter/nat/mangle) — key dari FwFilterFields. */
fun parseFwRuleRow(row: M2Message): FwRule? {
    val rowId = row.itemId() ?: return null
    return FwRule(
        rowId = rowId,
        chain = row.str(FwFilterFields.CHAIN),
        action = row.uint(FwFilterFields.ACTION)?.toInt(),
        srcAddress = row.str(FwFilterFields.SRC_ADDRESS),
        dstAddress = row.str(FwFilterFields.DST_ADDRESS),
        protocol = row.uint(FwFilterFields.PROTOCOL)?.toString(),
        srcPort = row.str(FwFilterFields.SRC_PORT),
        dstPort = row.str(FwFilterFields.DST_PORT),
        inInterface = row.str(FwFilterFields.IN_INTERFACE),
        outInterface = row.str(FwFilterFields.OUT_INTERFACE),
        bytes = row.u64(FwFilterFields.BYTES)?.toLong(),
        packets = row.u64(FwFilterFields.PACKETS)?.toLong(),
        comment = row.str(0xFE0009),
        disabled = row.bool(0xFE000A) ?: false,
    )
}

fun WinboxSession.getFwFilter(): List<FwRule> =
    getAllRows(WinboxPaths.FIREWALL_FILTER, withStats = true).mapNotNull { parseFwRuleRow(it) }

fun WinboxSession.getFwNat(): List<FwRule> =
    getAllRows(WinboxPaths.FIREWALL_NAT, withStats = true).mapNotNull { parseFwRuleRow(it) }

fun WinboxSession.getFwMangle(): List<FwRule> =
    getAllRows(WinboxPaths.FIREWALL_MANGLE, withStats = true).mapNotNull { parseFwRuleRow(it) }

// ================= Netwatch / DHCP / Bridge / Neighbor =================

fun parseNetwatchRow(row: M2Message): NetwatchRow? {
    val rowId = row.itemId() ?: return null
    return NetwatchRow(
        rowId = rowId,
        host = row.u32(m2Key(1, M2Ns.USER))?.let { formatIpv4U32(it) },
        intervalSec = row.uint(m2Key(2, M2Ns.USER))?.toInt(),
        status = row.uint(m2Key(4, M2Ns.USER))?.toInt(),
        comment = row.str(0xFE0009),
        disabled = row.bool(0xFE000A) ?: false,
    )
}

fun WinboxSession.getNetwatch(): List<NetwatchRow> =
    getAllRows(WinboxPaths.NETWATCH).mapNotNull { parseNetwatchRow(it) }

fun parseNeighborRow(row: M2Message): NeighborRow? {
    val rowId = row.itemId() ?: return null
    return NeighborRow(
        rowId = rowId,
        ip = row.u32(m2Key(1, M2Ns.USER))?.let { formatIpv4U32(it) },
        mac = row.raw(m2Key(2, M2Ns.USER))?.let { formatMac(it) },
        identity = row.str(m2Key(6, M2Ns.USER)),
    )
}

fun WinboxSession.getNeighbors(): List<NeighborRow> =
    getAllRows(WinboxPaths.IP_NEIGHBOR).mapNotNull { parseNeighborRow(it) }

// ================= System =================

fun parseSystemInfo(res: M2Message?, ident: M2Message?): SystemInfo {
    return SystemInfo(
        uptimeSec = res?.u32(0x1),
        freeMemKb = res?.u32(0x3),
        cpuLoad = res?.u8(0x9)?.toInt() ?: res?.u32(0x9)?.toInt(),
        board = res?.str(0x2c) ?: res?.str(0x19),
        arch = res?.str(0x1a),
        version = res?.str(0x16)?.substringBefore(" "),
        identity = ident?.str(0xc),
    )
}

fun WinboxSession.getSystemInfo(): SystemInfo {
    val res = getSingleton(listOf(24, 2))
    val ident = getSingleton(listOf(24, 1))
    return parseSystemInfo(res, ident)
}
