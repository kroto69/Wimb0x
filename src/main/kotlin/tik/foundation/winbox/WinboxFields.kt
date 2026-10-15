package tik.foundation.winbox

/**
 * Konstanta field key M2 per tabel — hasil dump live 2026-10-15 ke RB750Gr3
 * (lihat docs/FIELD-MAP-2026-10-15.md untuk struktur lengkap).
 *
 * Status per field:
 * - ✅ terverifikasi dipakai app / CRUD live
 * - 🔍 teramati di dump, semantik disimpulkan dari nilai (butuh konfirmasi fase 2)
 *
 * Key user-namespace dipakai mentah (m2Key(k, M2Ns.USER) == k karena ns=0x00).
 * Key 0xFE.... = session namespace (pakai langsung, mis. K_SESSION_ID).
 */

// ================= PPP =================

/** [27,101] — ✅ CRUD live 10/10. */
object PppSecretFields {
    const val NAME = 0x1
    const val PASSWORD = 0x2
    const val SERVICE = 0x3 // 🔍 u8 numeric; 3 = PPPoE teramati
    const val PROFILE = 0x5 // ✅ u8 numeric → resolve ke nama via tabel profile
    const val CALLER_ID = 0xF // 🔍 str format MAC
    const val DISABLED = 0x6F // ✅ bool
    const val COMMENT = 0xFE0009 // 🔍 str
    const val ROW_ID = 0xFE0001 // ✅ wajib untuk SET/REMOVE
}

/** [27,102] — 🔍 7 rows ter-dump. */
object PppProfileFields {
    const val NAME = 0xFE0009 // 🔍 str
    const val RATE_LIMIT_1 = 0x17 // 🔍 u32 family rate-limit
    const val RATE_LIMIT_2 = 0x18
    const val RATE_LIMIT_3 = 0x19
    const val RATE_LIMIT_4 = 0x1C
    const val RATE_LIMIT_5 = 0x1F
    const val ROW_ID = 0xFE0001
}

/** [27,103] — 🔍 27 rows ter-dump. */
object PppActiveFields {
    const val NAME = 0xFE0009 // 🔍 str
    const val CALLER_ID = 0x3 // 🔍 str format MAC "XX:XX:XX:XX:XX:XX"
    const val BYTES_UP = 0x9 // 🔍 u64
    const val BYTES_DOWN = 0xA // 🔍 u64
    const val ROW_ID = 0xFE0001
}

// ================= FIREWALL =================

/** [20,3] — 🔍 22 rows ter-dump. */
object FirewallFilterFields {
    const val ACTION = 0x28 // 🔍 u8; 10 teramati
    const val PACKETS = 0x2710 // 🔍 u64 — perlu stats bit 0x2 di flag getall
    const val BYTES = 0x2711 // 🔍 u64 — perlu stats bit 0x2 di flag getall
    const val COMMENT = 0xFE0009 // 🔍 str
    const val DISABLED = 0xFE000A // 🔍 bool
    const val ROW_ID = 0xFE0001
}

/** [20,5] — 🔍 33 rows ter-dump. */
object FirewallNatFields {
    const val COMMENT = 0xFE0009 // 🔍 str
    const val DISABLED = 0xFE000A // 🔍 bool
    const val ROW_ID = 0xFE0001
}

/** [20,7] — 🔍 42 rows ter-dump, field set terkaya. */
object FirewallMangleFields {
    const val COMMENT = 0xFE0009 // 🔍 str
    const val DISABLED = 0xFE000A // 🔍 bool
    const val ROW_ID = 0xFE0001
}

// ================= QUEUE =================

/** [20,9] — 🔍 56 rows ter-dump. */
object QueueSimpleFields {
    const val NAME = 0x2 // 🔍 str
    const val MAX_LIMIT_A = 0x3C // 🔍 u32; 20000000 (=20 Mbps) teramati
    const val MAX_LIMIT_B = 0x47 // 🔍 u32; 20000000 (=20 Mbps) teramati
    // NOTE: A/B belum dipastikan mana up vs down — butuh korelasi fase 2.
    const val COMMENT = 0xFE0009 // 🔍 str
    const val DISABLED = 0xFE000A // 🔍 bool
    const val ROW_ID = 0xFE0001
}

// ================= HOTSPOT =================

/** [63,11] — 🔍 1 row ter-dump. */
object HotspotServerFields {
    const val NAME = 0xFE0009 // 🔍 str (pola umum)
    const val ROW_ID = 0xFE0001
}

/** [63,10] — 🔍 25 rows ter-dump. */
object HotspotIpBindingFields {
    const val TYPE = 0x2 // 🔍 u8 numeric
    const val COMMENT = 0xFE0009 // 🔍 str
    const val DISABLED = 0xFE000A // 🔍 bool
    const val ROW_ID = 0xFE0001
}

// ================= IP / SYSTEM =================

/** [68,1] — 🔍 8 rows ter-dump. */
object IpServiceFields {
    const val ROW_ID = 0xFE0001
}

/** [51] — 🔍 15 rows ter-dump. */
object NetwatchFields {
    const val HOST = 0x6 // 🔍 str (host / script family)
    const val SCRIPT = 0x7 // 🔍 str
    const val COMMENT = 0xFE0009 // 🔍 str
    const val DISABLED = 0xFE000A // 🔍 bool
    const val ROW_ID = 0xFE0001
}

/** [24,2] — ✅ dipakai app via polling 3 detik (router tidak push perubahan nilai). */
object SystemResourceFields {
    const val UPTIME = 0x1 // ✅
    const val FREE_MEM_KB = 0x3 // ✅
    const val CPU_LOAD = 0x9 // ✅ persen
}
