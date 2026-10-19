package tik.foundation.winbox

/**
 * Konstanta field key M2 per tabel.
 *
 * Sumber otoritas:
 * - [jg] = definisi resmi dari file .jg MikroTik (roteros.jg/hotspot.jg/dhcp.jg/advtool.jg),
 *   hasil parse 2026-10-15 — 353 handler terekstrak.
 * - [live] = terverifikasi via tes live ke RB750Gr3 (CRUD 10/10, dump 20 tabel).
 *
 * Key user-namespace dipakai mentah (m2Key(k, M2Ns.USER) == k karena ns=0x00).
 * Key 0xFE.... = session namespace (mis. K_SESSION_ID = 0xFE0001).
 */

// ================= PPP — [live] =================

/** [27,101] — [live] CRUD 10/10. */
object PppSecretFields {
    const val NAME = 0x1
    const val PASSWORD = 0x2
    const val SERVICE = 0x3 // u8 numeric; 3 = PPPoE (teramati)
    const val PROFILE = 0x5 // u8 numeric → resolve ke nama via tabel profile
    const val CALLER_ID = 0xF // str format MAC
    const val DISABLED = 0x6F // bool
    const val COMMENT = 0xFE0009
    const val ROW_ID = 0xFE0001 // wajib untuk SET/REMOVE
}

/** [27,102] — [live] 9 rows ter-dump di v7. */
object PppProfileFields {
    const val NAME = 0x1 // str — "default" teramati [live v7]
    const val LOCAL_ADDRESS = 0x2 // u8 enm
    const val REMOTE_ADDRESS = 0x3 // u8 enm
    /** Rate-limit: string "rx/tx" mis. "7M/9M" [live v6, 2026-10-17]. */
    const val RATE_LIMIT = 0x16 // str
    /** DNS server: array u32 IP [live v6, 2026-10-17]. */
    const val DNS_SERVER = 0x15 // u32array
    /**
     * Only-one: yes=u8:1, no=u8:0, default=u32:4294967295 [live v6, 2026-10-17].
     * v7 belum diverifikasi.
     */
    const val ONLY_ONE = 0x19 // u8/u32
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

/** [27,103] — [live] 27 rows ter-dump. */
object PppActiveFields {
    const val NAME = 0x1  // live v7: 0x1 = str name ("HOME"); 0xFE0009 kosong
    const val CALLER_ID = 0x3 // str format MAC
    const val BYTES_UP = 0x9 // u64
    const val BYTES_DOWN = 0xA // u64
    const val ROW_ID = 0xFE0001
}

// ================= FIREWALL — [jg] =================

/** [20,3] Firewall Rule — [jg] 84 fields terdefinisi. */
object FwFilterFields {
    const val CHAIN = 0x27 // string
    const val ACTION = 0x28 // enm
    const val SRC_ADDRESS = 0x1A2 // Src. Address [opt]
    const val DST_ADDRESS = 0x1A3 // Dst. Address [opt]
    const val PROTOCOL = 0x194 // Protocol [opt]
    const val SRC_PORT = 0x1B7 // Src. Port [opt]
    const val DST_PORT = 0x1B8 // Dst. Port [opt]
    const val IN_INTERFACE = 0x190 // In. Interface [opt]
    const val OUT_INTERFACE = 0x191 // Out. Interface [opt]
    const val BYTES = 0x2710 // bigbytes — perlu stats bit di getall
    const val PACKETS = 0x2711 // bigdecimal — perlu stats bit di getall
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

/** [20,5] NAT — [jg]. */
object FwNatFields {
    const val CHAIN = 0x27
    const val ACTION = 0x28
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

/** [20,7] Mangle — [jg]. */
object FwMangleFields {
    const val CHAIN = 0x27
    const val ACTION = 0x28
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

// ================= QUEUE — [jg] =================

/** [20,9] Simple Queue — [jg] 55 fields terdefinisi. */
object QueueFields {
    const val NAME = 0x2 // string
    const val TARGET = 0x72 // Target [multi] — "192.168.88.0/24"
    const val DST = 0x73 // Dst. [opt] — "192.168.90.21/32"
    const val PARENT = 0x1 // Parent [enm] — index queue parent / global
    const val UP_MAX = 0x3C // Upload Max Limit [enm] — 20000000 = 20 Mbps teramati [live v6]
    // NOTE v7: rate aktual terbaca di u64 0xD8 (up) / 0x13C (down), mis. 600000000 = 600 Mbps [live v7]
    const val DOWN_MAX = 0x47 // Download Max Limit [enm]
    const val UP_LIMIT_AT = 0x32 // Upload Limit At
    const val DOWN_LIMIT_AT = 0x46 // Download Limit At
    const val UP_PRIORITY = 0x36 // Upload Priority
    const val DOWN_PRIORITY = 0x4C // Download Priority
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

// ================= INTERFACE — [live v7] =================

/**
 * [20,0] Interface list — [live] 163 rows ter-dump di v7.
 * Interface fisik tidak bisa add/remove — hanya SET (rename/comment/disable).
 */
object InterfaceFields {
    const val NAME = 0x10006 // str — "ether1" teramati [live v7]
    const val DEFAULT_NAME = 0x10005 // str — "eth0" teramati [live v7]
    const val TYPE = 0x1001E // str — "ether" teramati [live v7]
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
    // Detail [.jg]
    // MAC: .jg bilang 0x26D — SALAH untuk data live (0 baris punya 0x26D di v6/v7).
    // Live-verified 2026-10-17: MAC aktual di 0x404 (raw 6 byte).
    const val MAC_ADDRESS = 0x404 // raw 6 byte
    const val MAC_FACTORY = 0x3E9 // raw 6 byte — duplikat 0x404 di semua baris
    const val MTU = 0x10064 // u32 — 1500 teramati
    const val L2MTU = 0x10065 // u32 — 1596/1592 teramati
    const val SPEED = 0x3F2 // u8 enum: 2≈1G, 3≈10G/SFP+ (bukan bps)
    const val RUNNING = 0x1000E // bool — true = link up
    // VLAN (live-verified 2026-10-17)
    const val VLAN_ID = 0x7D1 // u8/u32 — vlan id
    const val VLAN_PARENT = 0x7D2 // u8 → itemId parent interface
    // Traffic rate/counter [.jg]: q-prefix = 64-bit quantity
    const val TX_RATE = 0x100D4 // bigbitrate — "Tx" (upload)
    const val RX_RATE = 0x100D3 // bigbitrate — "Rx" (download)
    const val TX_BYTES = 0x100FD // bigbytes — "Tx Bytes"
    const val RX_BYTES = 0x100FC // bigbytes — "Rx Bytes"
    const val TX_PACKETS = 0x100FF // bigdecimal — "Tx Packets"
    const val RX_PACKETS = 0x100FE // bigdecimal — "Rx Packets"
    // PPPoE session info (live-verified 2026-10-17 di RB4011iGS+ v7)
    const val PPPOE_USER = 0xB0005 // str — username (tanpa <pppoe->)
    const val PPPOE_CALLER_ID = 0xB0006 // str — MAC caller
    const val PPPOE_UPTIME = 0xB0002 // u32 — uptime detik
    const val PPPOE_STATUS = 0xB0004 // str — "connected"
    const val PPPOE_LOCAL_ADDR = 0xB0009 // u32 — IP lokal (octet-LSB)
    const val PPPOE_REMOTE_ADDR = 0xB000A // u32 — IP remote (octet-LSB)
}

// ================= IP — [jg] =================

/** [20,1] Address — [jg]. */
object IpAddrFields {
    const val ADDRESS = 0x1 // network → U32 IP
    const val NETMASK = 0x3 // netmask → U32 (16777215 = /24, teramati [live v7])
    const val NETWORK = 0x2 // ipaddr (u32) — derived oleh router
    const val INTERFACE = 0xA // enm → resolve ke nama interface
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

/** [44,1] Route — [jg]. */
object IpRouteFields {
    const val DST = 0x1 // Dst. Address [network]
    const val GATEWAY = 0x2E // Gateway [multi] — kompleks, pakai string IP bila didukung
    const val DISTANCE = 0x3F0 // Distance [opt number]
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

/** [68,1] Service — [jg]. */
object IpServiceFields {
    const val NAME = 0x1 // string
    const val PORT = 0x2 // number
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

// ================= HOTSPOT — [jg] =================

/** [63,1] Hotspot User — [jg]. */
object HsUserFields {
    const val NAME = 0x1 // string
    const val PASSWORD = 0x2 // secret
    const val PROFILE = 0x5 // enm → resolve via [63,14]
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

/** [63,11] Hotspot Server — [jg]. */
object HsServerFields {
    const val NAME = 0x10 // string (id sfe0010)
    const val INTERFACE = 0x1 // enm → resolve ke nama interface
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

/** [63,10] IP Binding — [jg]. */
object HsBindingFields {
    const val MAC = 0x1 // macaddr
    const val ADDRESS = 0x7 // network
    const val TO_ADDRESS = 0x3 // ipaddr
    const val SERVER = 0x5 // enm → resolve via [63,11]
    const val TYPE = 0x6 // enm (bypassed/regular/blocked)
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

// ================= LAINNYA =================

/** [51] Netwatch Host — [jg]. */
object NetwatchFields {
    const val HOST = 0x1 // ipaddr — host yang dipantau
    const val NAME = 0xFE0009 // nama pakai COMMENT (tidak ada field nama khusus di .jg)
    const val INTERVAL = 0x2 // interval
    const val TIMEOUT = 0x3 // number
    const val STATUS = 0x4 // enm (read-only)
    const val UP_SCRIPT = 0x6 // script
    const val DOWN_SCRIPT = 0x7 // script
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

// ================= DNS — [jg] =================

/** [14,3] DNS Static Entry — [jg]. */
object DnsStaticFields {
    const val NAME = 0x1 // string
    const val REGEXP = 0x16 // string
    const val TYPE = 0x17 // enm (A/AAAA/CNAME...)
    const val TTL = 0x4 // interval
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

/** [14,2] DNS Settings — singleton, SET saja — [jg]. */
object DnsSettingsFields {
    const val SERVERS = 0xA // multi — daftar DNS server
    const val ALLOW_REMOTE = 0x3 // bool
    const val ROW_ID = 0xFE0001
}

// ================= DHCP SERVER — [jg] =================

/** [23,0] DHCP Server — [jg]. */
object DhcpServerFields {
    const val NAME = 0x9 // string
    const val INTERFACE = 0x7 // enm → id interface
    const val LEASE_TIME = 0x5 // interval
    const val ADDRESS_POOL = 0x8 // enm
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

/** [23,2] DHCP Network — [jg]. */
object DhcpNetworkFields {
    const val ADDRESS = 0x1 // network → U32 + netmask
    const val NETMASK = 0x9 // netmask → U32
    const val GATEWAY = 0x3 // multiipaddr
    const val DNS_SERVERS = 0x4 // multiipaddr
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

/** [24,2] System Resource — [live] via polling 3 detik. */
object SystemResourceFields {
    const val UPTIME = 0x1
    const val FREE_MEM_KB = 0x3
    const val CPU_LOAD = 0x9 // persen
}

// ================= DHCP Client / Bridge / Traceroute — [jg] =================

/** [43,1] DHCP Client — [jg]. */
object DhcpClientFields {
    const val INTERFACE = 0x2 // enm → interface row ID
    // Live-verified 2026-10-17: 0x2 = interface itemId (u8), 0xFE0010 = nama interface
    const val IFACE_NAME = 0xFE0010 // str — nama interface
    const val STATUS = 0xFE001C // StrArray — mis. ["Interface not active"]
    const val USE_PEER_DNS = 0xBD // bool
    const val USE_PEER_NTP = 0xBE // bool
    const val ADD_DEFAULT_ROUTE = 0x12 // enm: 0=no, 1=yes, 2=special-classless
    const val DEFAULT_ROUTE_DISTANCE = 0xF // number
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
    // Status (read-only)
    const val IP_ADDRESS = 0x66 // network → U32 + netmask (0x67)
    const val IP_NETMASK = 0x67
    const val GATEWAY = 0x68 // ipaddr → U32
    const val DHCP_SERVER = 0x69 // ipaddr → U32
    const val EXPIRES_AFTER = 0x6C // age → detik
}

/** [16,2] Bridge Port — [jg]. */
object BridgePortFields {
    // Live-verified 2026-10-17: 0x1=bridge itemId, 0x3=interface itemId (.jg 0x4 SALAH)
    const val BRIDGE = 0x1 // u8 → itemId bridge
    const val INTERFACE = 0x3 // enm → interface row ID
    const val HORIZON = 0xD // number
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

/** [26] Traceroute — [jg] query tool. */
object TracerouteFields {
    // Request
    const val TARGET = 0x1 // ipaddr → U32
    const val PACKET_SIZE = 0x5 // number, def 56
    const val TIMEOUT_MS = 0x3 // number, def 1000
    const val PROTOCOL = 0x7 // enm: 0=icmp, 1=udp
    const val PORT = 0x4 // number, def 33434
    const val USE_DNS = 0xBE // bool
    const val MAX_HOPS = 0x10 // number
    const val SRC_ADDRESS = 0x8 // ipaddr → U32 (opt)
    // Response (hasil per hop) — field aktual perlu verifikasi live
}

/** Log [3,4] — live-verified 2026-10-17 (v6+v7). */
object LogFields {
    const val TIME = 0x1 // u32 — unix timestamp
    const val MESSAGE = 0x3 // str
    const val TOPICS = 0x4 // U32Array — enum topics (nama belum dipetakan)
    const val ACCOUNT = 0x5 // str — info akun (v7, baris account saja)
}
