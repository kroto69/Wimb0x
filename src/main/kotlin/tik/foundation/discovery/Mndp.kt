package tik.foundation.discovery

/**
 * MNDP — MikroTik Neighbor Discovery Protocol.
 *
 * Format paket (hasil reverse-engineering, terverifikasi dari kode client resmi):
 * - Solicitation: 4 byte nol ke 255.255.255.255:5678 (UDP)
 * - Respons: deretan TLV; tiap tag dikode sebagai `00 <tag> 00 <len:1 byte> <data>`
 *
 * Catatan Android: socket ini butuh `WifiManager.MulticastLock`
 * + permission `CHANGE_WIFI_MULTICAST_STATE`, dan jangan lupa release lock.
 */
object Mndp {
    const val PORT = 5678
    const val BROADCAST = "255.255.255.255"

    /** Tag TLV MNDP (id numerik sesuai protokol). */
    enum class Tag(val id: Int) {
        MACADDR(1),
        IDENTITY(5),
        VERSION(7),
        PLATFORM(8),
        UPTIME(10),
        SOFTWAREID(11),
        BOARDNAME(12);

        companion object {
            fun of(id: Int): Tag? = entries.firstOrNull { it.id == id }
        }
    }

    /** Paket solicitation: {0,0,0,0}. */
    fun solicitPacket(): ByteArray = ByteArray(4)

    fun encodeTlv(tag: Tag, data: ByteArray): ByteArray {
        require(data.size <= 255) { "TLV data too long" }
        return byteArrayOf(0, tag.id.toByte(), 0, data.size.toByte()) + data
    }

    /**
     * Parse deretan TLV → map Tag → data mentah.
     * Tag tak dikenal / data terpotong diabaikan (robust terhadap paket aneh).
     */
    fun decodeTlvs(packet: ByteArray, length: Int = packet.size): Map<Tag, ByteArray> {
        val out = LinkedHashMap<Tag, ByteArray>()
        var i = 0
        while (i + 4 <= length) {
            if (packet[i] == 0.toByte() && packet[i + 2] == 0.toByte()) {
                val tag = Tag.of(packet[i + 1].toInt() and 0xFF)
                val len = packet[i + 3].toInt() and 0xFF
                val start = i + 4
                if (tag != null && start + len <= length) {
                    out[tag] = packet.copyOfRange(start, start + len)
                    i = start + len
                    continue
                }
            }
            i++
        }
        return out
    }

    fun formatMac(bytes: ByteArray): String =
        bytes.joinToString(":") { "%02X".format(it) }
}

/** Satu router yang ditemukan via MNDP. */
data class Neighbor(
    val address: String,
    val mac: String,
    val identity: String,
    val version: String,
    val boardName: String,
    val platform: String? = null,
    val uptimeSec: Long? = null,
    val lastSeenMs: Long = System.currentTimeMillis(),
) {
    val displayName: String get() = identity.ifEmpty { mac }
}

/** Bangun [Neighbor] dari paket respons MNDP + alamat IP pengirim. Null bila tak ada MAC. */
fun parseNeighbor(address: String, data: ByteArray, length: Int = data.size): Neighbor? {    val t = Mndp.decodeTlvs(data, length)
    val macBytes = t[Mndp.Tag.MACADDR] ?: return null
    fun str(tag: Mndp.Tag): String =
        t[tag]?.toString(Charsets.UTF_8)?.trimEnd('\u0000') ?: ""
    return Neighbor(
        address = address,
        mac = Mndp.formatMac(macBytes),
        identity = str(Mndp.Tag.IDENTITY),
        version = str(Mndp.Tag.VERSION),
        boardName = str(Mndp.Tag.BOARDNAME),
        platform = str(Mndp.Tag.PLATFORM).takeIf { it.isNotEmpty() },
        uptimeSec = null, // tag 10 biner, diabaikan di v1
    )
}

/**
 * Normalisasi MAC dari berbagai format penulisan ke kanonis "AA:BB:CC:DD:EE:FF".
 * Menerima "aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aabbccddeeff", dll.
 * Null bila bukan tepat 12 digit hex.
 */
fun normalizeMac(raw: String): String? {
    val hex = raw.filter { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }
    if (hex.length != 12) return null
    return hex.uppercase().chunked(2).joinToString(":")
}

/**
 * Cari neighbor berdasar MAC (format penulisan bebas) di daftar.
 * Dipakai alur login "ketuk MAC di daftar neighbor" → resolve ke IP → connect TCP.
 */
fun lookupMac(neighbors: List<Neighbor>, mac: String): Neighbor? {
    val norm = normalizeMac(mac) ?: return null
    return neighbors.firstOrNull { it.mac == norm }
}
