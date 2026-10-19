package tik.foundation.winbox

/**
 * Versi RouterOS — 🟡 belum live-test (parse dari string versi).
 *
 * v7: baca dari [24,2] key 0x16 (mis. "7.24.4 (stable)").
 * v6: baca dari [24,1] key 0xd (mis. "6.49.19").
 */
data class RouterVersion(
    val major: Int,
    val minor: Int,
    val patch: Int,
    /** string mentah apa adanya dari router */
    val raw: String,
) {
    companion object {
        /** Parse "7.24.4 (stable)" atau "6.49.19" → RouterVersion. Null bila gagal. */
        fun parse(raw: String?): RouterVersion? {
            if (raw.isNullOrBlank()) return null
            // Ambil "7.24.4" dari "7.24.4 (stable)"
            val ver = raw.trim().split(" ", "(").firstOrNull() ?: return null
            val parts = ver.split(".")
            if (parts.size < 2) return null
            return try {
                RouterVersion(
                    major = parts[0].toInt(),
                    minor = parts[1].toInt(),
                    patch = parts.getOrNull(2)?.toInt() ?: 0,
                    raw = raw.trim(),
                )
            } catch (_: NumberFormatException) {
                null
            }
        }
    }

    val isV7: Boolean get() = major >= 7
    val isV6: Boolean get() = major == 6
}

/**
 * Baca versi RouterOS — 🟡 belum live-test.
 *
 * Cache per sesi (WeakHashMap). Coba [24,2]/0x16 dulu (v7),
 * fallback ke [24,1]/0xd (v6). Return null bila gagal.
 */
fun WinboxSession.routerVersion(): RouterVersion? {
    versionCache[this]?.let { return it }

    val version = try {
        // v7: [24,2] key 0x16 = "7.24.4 (stable)"
        val res = getSingleton(listOf(24, 2))
        val v7raw = res?.str(0x16)
        RouterVersion.parse(v7raw) ?: run {
            // v6: [24,1] key 0xd = "6.49.19"
            val ident = getSingleton(listOf(24, 1))
            RouterVersion.parse(ident?.str(0xd))
        }
    } catch (_: Exception) {
        null
    }

    if (version != null) {
        versionCache[this] = version
    }
    return version
}

private val versionCache = java.util.WeakHashMap<WinboxSession, RouterVersion>()

// ================= FieldKey — resolver key lintas versi =================

/**
 * Key field yang beda antara RouterOS v7 dan v6 — 🟡 belum live-test.
 *
 * Coba [v7] dulu, fallback ke [v6] bila ada. Jangan bergantung pada
 * deteksi versi — coba v7 dulu selalu.
 */
data class FieldKey(val v7: Int, val v6: Int?)

/** Baca string via FieldKey: coba v7 dulu, fallback v6. */
fun M2Message.str(key: FieldKey): String? =
    str(key.v7) ?: key.v6?.let { str(it) }

/** Baca uint (u8/u32) via FieldKey: coba v7 dulu, fallback v6. */
fun M2Message.uint(key: FieldKey): Long? =
    uint(key.v7) ?: key.v6?.let { uint(it) }

/** Baca u64 via FieldKey: coba v7 dulu, fallback v6. */
fun M2Message.u64fk(key: FieldKey): ULong? =
    u64(key.v7) ?: key.v6?.let { u64(it) }

// Key yang sudah terdokumentasi perbedaannya:
object VersionedKeys {
    /** PPP active & profile name: v7=0x1, v6=0xFE0009 */
    val PPP_NAME = FieldKey(v7 = 0x1, v6 = 0xFE0009)

    /** Queue rate up: v7=u64 0xD8, v6=u32 0x3C */
    val QUEUE_RATE_UP = FieldKey(v7 = 0xD8, v6 = 0x3C)

    /** Queue rate down: v7=u64 0x13C, v6=u32 0x47 */
    val QUEUE_RATE_DOWN = FieldKey(v7 = 0x13C, v6 = 0x47)
}
