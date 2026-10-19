package tik.foundation.winbox

/**
 * Typed read models — 🟡 belum live-test (kecuali yang sudah ada di roadmap).
 *
 * Aturan:
 * - Semua model punya [rowId]: M2Field (0xFE0001 dari getAllRows).
 * - Field yang belum dipetakan = nullable + KDoc "UNMAPPED", nilai null.
 * - Jangan mengarang key — hanya dari Fields.kt/docs.
 */

// ================= PPP =================

/** Secret PPP [27,101] — 🟡. */
data class PppSecret(
    val rowId: M2Field,
    val name: String,
    val password: String,
    /** service numerik mentah (0x3); 3=PPPoE terkonfirmasi; jangan menebak lainnya. */
    val service: Int?,
    /** ref profile (0x5); terima u8 ATAU u32. */
    val profileRef: Long?,
    val callerId: String?,
    val comment: String?,
    val disabled: Boolean,
    /** UNMAPPED: local address belum dipetakan. */
    val localAddress: String? = null,
    /** UNMAPPED: remote address belum dipetakan. */
    val remoteAddress: String? = null,
    /**
     * Nama profile (resolved dari profileRef via map).
     * Diisi oleh [parsePppSecret]; null bila pakai [parsePppSecretRow] langsung.
     */
    val profileName: String? = null,
) {
    /** Alias kompatibel: nama profile untuk UI. */
    val profile: String get() = profileName ?: ""
}

/** Profile PPP [27,102] — 🟡. */
/** Nilai only-one pada PPP profile [live v6, 2026-10-17]. */
enum class OnlyOne {
    /** u32:4294967295 (unset). */
    DEFAULT,
    /** u8:1. */
    YES,
    /** u8:0. */
    NO,
    /** Tidak dikenali / tidak ada data. */
    UNKNOWN,
}

data class PppProfile(
    val rowId: M2Field,
    /** nama via FieldKey (v7=0x1, v6=0xFE0009). */
    val name: String,
    /** local address enum mentah (0x2). */
    val localAddressEnum: Int?,
    /** remote address enum mentah (0x3). */
    val remoteAddressEnum: Int?,
    val comment: String?,
    val disabled: Boolean,
    /** Rate-limit mentah, mis. "7M/9M" (0x16) [live v6, 2026-10-17]. */
    val rateLimit: String? = null,
    /**
     * Upload bps dari pasangan rx/tx pertama rate-limit.
     * Urutan rx/tx menurut dump: rx=upload klien, tx=download klien.
     */
    val rateUpBps: Long? = null,
    /** Download bps dari pasangan rx/tx pertama rate-limit. */
    val rateDownBps: Long? = null,
    /** DNS server (0x15) [live v6, 2026-10-17]. */
    val dnsServers: List<String> = emptyList(),
    /** Only-one (0x19) [live v6, 2026-10-17]. */
    val onlyOne: OnlyOne = OnlyOne.UNKNOWN,
    /** UNMAPPED: parent queue belum dipetakan. */
    val parentQueue: String? = null,
)

/**
 * Sesi PPP aktif [27,103] — 🟡.
 *
 * Arah bytes BELUM terverifikasi — pakai nama netral bytesA/bytesB.
 */
data class PppActive(
    val rowId: M2Field,
    /** nama via FieldKey (v7=0x1, v6=0xFE0009). */
    val name: String,
    val callerId: String?,
    /** counter bytes 0x9 (u64) — arah belum terverifikasi. */
    val bytesA: Long,
    /** counter bytes 0xA (u64) — arah belum terverifikasi. */
    val bytesB: Long,
    /**
     * Rate bps dari interface PPPoE (bukan dari [27,103]).
     * Diisi app via polling getPppoeTraffic; null bila belum ada data.
     */
    val rateInBps: Long? = null,
    val rateOutBps: Long? = null,
) {
    /** Alias: bytesIn = bytesA (kompatibel app lama). */
    val bytesIn: Long get() = bytesA
    /** Alias: bytesOut = bytesB (kompatibel app lama). */
    val bytesOut: Long get() = bytesB

    companion object {
        /**
         * null = belum diketahui mana yang down. Jangan disimpulkan.
         * (const tidak bisa nullable, pakai val biasa)
         */
        val BYTES_A_IS_DOWN: Boolean? = null
    }
}

/** Resolve nama profile dari secret via itemId profile — 🟡. */
fun resolveProfileName(secret: PppSecret, profiles: List<PppProfile>): String? {
    val ref = secret.profileRef ?: return null
    return profiles.firstOrNull { p ->
        when (val v = p.rowId.value) {
            is M2Value.U8 -> v.v.toLong() == ref
            is M2Value.U32 -> v.v == ref
            else -> false
        }
    }?.name
}

// ================= Interface =================

/** Interface [20,0] — 🟡. */
data class InterfaceInfo(
    val rowId: M2Field,
    val name: String, // 0x10006
    val defaultName: String?,
    val type: String?,
    val comment: String?,
    val disabled: Boolean,
    /** Running/link-up (0x1000E bool) — live-verified 2026-10-17. */
    val running: Boolean? = null,
    /** MAC address (0x404 raw 6 byte) — live-verified 2026-10-17. */
    val mac: String? = null,
    /** MTU (0x10064 u32) — live-verified 2026-10-17. */
    val mtu: Int? = null,
    /** L2MTU (0x10065 u32) — live-verified 2026-10-17. */
    val l2mtu: Int? = null,
    /** Speed (0x3F2 u8 enum): "1G", "10G", atau "enum-N" bila tak dikenal. */
    val speed: String? = null,
    /** VLAN ID (0x7D1) — hanya interface type vlan. */
    val vlanId: Int? = null,
    /** Parent interface itemId (0x7D2) — hanya vlan. */
    val vlanParentId: Long? = null,
    /**
     * Tx bytes (0x100FD "Tx Bytes") — terisi bila getAllRows withStats=true.
     * Live-verified 2026-10-17 untuk interface <pppoe-*>; untuk tipe lain
     * mengikuti pemetaan .jg resmi.
     */
    val txBytes: Long? = null,
    /**
     * Rx bytes (0x100FC "Rx Bytes") — sama seperti txBytes.
     */
    val rxBytes: Long? = null,
    /**
     * Tx rate bps (0x100D4 "Tx" bigbitrate, dari .jg resmi).
     * Rate hitungan router; app boleh menghitung sendiri dari delta bytes.
     */
    val txRateBps: Long? = null,
    /**
     * Rx rate bps (0x100D3 "Rx" bigbitrate, dari .jg resmi).
     */
    val rxRateBps: Long? = null,
)

// ================= IP =================

/** Baris /ip address [20,1] — 🟡. */
data class IpAddressRow(
    val rowId: M2Field,
    /** "a.b.c.d/N" dari 0x1 (u32 ip) + 0x3 (u32 netmask). */
    val address: String,
    /** ref interface — asumsi index belum terverifikasi. */
    val interfaceRef: Int?,
    /** nama interface (resolve via getInterfaceOptions). */
    val interfaceName: String?,
    val comment: String?,
    val disabled: Boolean,
    /** UNMAPPED: dynamic belum dipetakan. */
    val dynamic: Boolean? = null,
)

/** Baris /ip route [44,1] — 🟡. */
data class RouteRow(
    val rowId: M2Field,
    /** dst 0x1 str. */
    val dst: String?,
    /** gateway: parse MsgArray 0x2E → U32Array sub-key 0x6 → elemen pertama → ip. */
    val gateway: String?,
    /** distance 0x3F0. */
    val distance: Int?,
    val comment: String?,
    val disabled: Boolean,
    /** UNMAPPED: active belum dipetakan. */
    val active: Boolean? = null,
    /** UNMAPPED: dynamic belum dipetakan. */
    val dynamic: Boolean? = null,
)

/** Baris /ip service [68,1] — 🟡. */
data class ServiceRow(
    val rowId: M2Field,
    /** name 0x1 — docs bertentangan (string vs u8); parser toleran. */
    val name: String,
    /** port 0x2 — docs bertentangan (number vs u8); parser toleran. */
    val port: Int?,
    val disabled: Boolean,
)

// ================= Queue =================

/** Baris /queue simple [20,9] — 🟡. */
data class QueueRow(
    val rowId: M2Field,
    val name: String, // 0x2
    /** target: MsgArray 0x72 (sub 0x1 u32 ip + sub 0x2 u32 netmask → "ip/prefix"). */
    val target: String?,
    /** max up via FieldKey (v7 u64 0xD8, v6 u32 0x3C). */
    val maxUpBps: Long?,
    /** max down via FieldKey (v7 u64 0x13C, v6 u32 0x47). */
    val maxDownBps: Long?,
    val priority: Int?, // 0x36
    val comment: String?,
    val disabled: Boolean,
)

// ================= Firewall =================

/** Rule firewall (filter/nat/mangle) — 🟡. */
data class FwRule(
    val rowId: M2Field,
    val chain: String?, // 0x27 str
    /** action numerik mentah 0x28; mapping ke nama = UNMAPPED. */
    val action: Int?,
    val srcAddress: String?,
    val dstAddress: String?,
    val protocol: String?,
    val srcPort: String?,
    val dstPort: String?,
    val inInterface: String?,
    val outInterface: String?,
    /** bytes (bila withStats=true). */
    val bytes: Long?,
    /** packets (bila withStats=true). */
    val packets: Long?,
    val comment: String?,
    val disabled: Boolean,
)

// ================= Netwatch =================

/** Baris /tool netwatch [51] — 🟡. */
data class NetwatchRow(
    val rowId: M2Field,
    /** host 0x1 ip. */
    val host: String?,
    /** interval detik 0x2. */
    val intervalSec: Int?,
    /** status mentah 0x4. */
    val status: Int?,
    val comment: String?,
    val disabled: Boolean,
)

// ================= DHCP / Bridge / Neighbor =================

/** Baris /ip dhcp-client [43,1] — live-verified 2026-10-17 (v6+v7). */
data class DhcpClientRow(
    val rowId: M2Field,
    /** Interface itemId (0x2). */
    val interfaceId: Long?,
    val interfaceName: String?,
    /** UNMAPPED: butuh lease aktif. */
    val ipAddress: String?,
    /** UNMAPPED: butuh lease aktif. */
    val gateway: String?,
    /** UNMAPPED: butuh lease aktif. */
    val dns: String?,
    /** Status (0xFE001C StrArray), mis. ["Interface not active"]. */
    val status: List<String> = emptyList(),
    val comment: String?,
    val disabled: Boolean,
)

/** Baris /interface bridge port [16,2] — live-verified 2026-10-17 (v6). */
data class BridgePortRow(
    val rowId: M2Field,
    /** Bridge itemId (0x1). */
    val bridgeId: Long?,
    /** Interface itemId (0x3). */
    val interfaceId: Long?,
    val interfaceName: String?,
    val bridgeName: String?,
    val comment: String?,
    val disabled: Boolean,
)

/** Baris /ip neighbor [10,1] — 🟡. */
data class NeighborRow(
    val rowId: M2Field,
    /** ip 0x1 u32. */
    val ip: String?,
    /** mac 0x2 raw 6 byte. */
    val mac: String?,
    /** identity 0x6 str. */
    val identity: String?,
)

// ================= System =================

/** Info sistem — 🟡. */
data class SystemInfo(
    /** uptime detik 0x1 [24,2]. */
    val uptimeSec: Long?,
    /** free memory KB 0x3 [24,2]. */
    val freeMemKb: Long?,
    /** cpu load % 0x9 [24,2]. */
    val cpuLoad: Int?,
    /** board 0x2c fallback 0x19 [24,2]. */
    val board: String?,
    /** arch 0x1a [24,2]. */
    val arch: String?,
    /** version 0x16 [24,2]. */
    val version: String?,
    /** identity [24,1] key 0xc. */
    val identity: String?,
)
