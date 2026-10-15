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

/** [27,102] — [live] 7 rows ter-dump. */
object PppProfileFields {
    const val NAME = 0xFE0009
    const val ROW_ID = 0xFE0001
}

/** [27,103] — [live] 27 rows ter-dump. */
object PppActiveFields {
    const val NAME = 0xFE0009
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

// ================= IP — [jg] =================

/** [20,1] Address — [jg]. */
object IpAddrFields {
    const val ADDRESS = 0x1 // network (u32)
    const val NETWORK = 0x2 // ipaddr (u32)
    const val INTERFACE = 0xA // enm → resolve ke nama interface
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

/** [44,1] Route — [jg]. */
object IpRouteFields {
    const val DST = 0x1 // Dst. Address [network]
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
    const val COMMENT = 0xFE0009
    const val DISABLED = 0xFE000A
    const val ROW_ID = 0xFE0001
}

// ================= LAINNYA =================

/** [51] Netwatch Host — [jg]. */
object NetwatchFields {
    const val INTERVAL = 0x2 // interval
    const val TIMEOUT = 0x3 // number
    const val STATUS = 0x4 // enm
    const val SINCE = 0x5 // date
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
