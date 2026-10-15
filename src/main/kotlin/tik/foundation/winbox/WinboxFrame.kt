package tik.foundation.winbox

import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.InputStream

/**
 * Framing WinBox di atas TCP 8291.
 *
 * - Frame handshake: `[len 1B][tag 1B] + payload`, TIDAK di-chunk.
 * - Frame data: chunk `[len 1B][tag 1B][payload]`; chunk pertama bawa tag frame
 *   (0x06 terenkripsi / 0x01 mentah), lanjutan bawa tag 0xFF.
 *   `len = 0xFF` → 255 byte, masih ada lanjutan; len lebih kecil → chunk terakhir.
 *
 * Seluk-beluk penting: frame terenkripsi yang panjangnya kelipatan 255 TIDAK
 * diakhiri chunk pendek oleh RouterOS — frame berakhir saat payload rakitan
 * mencapai panjang yang dideklarasikan 2 byte pertamanya.
 */
object WinboxFrame {
    const val TAG_ENCRYPTED = 0x06
    const val TAG_RAW = 0x01
    const val TAG_CONT = 0xFF

    /** Frame handshake: [len][tag] + payload (maks 255 byte), tidak di-chunk. */
    fun encodeHandshake(payload: ByteArray, tag: Int = TAG_ENCRYPTED): ByteArray {
        require(payload.size <= 255) { "handshake > 255 byte" }
        return byteArrayOf(payload.size.toByte(), tag.toByte()) + payload
    }

    /** Frame data: payload di-chunk per 255 byte. */
    fun encodeData(payload: ByteArray, tag: Int): ByteArray {
        val out = ByteArrayOutputStream()
        if (payload.isEmpty()) {
            out.write(0)
            out.write(tag)
            return out.toByteArray()
        }
        var off = 0
        var first = true
        while (off < payload.size) {
            val n = minOf(255, payload.size - off)
            out.write(n)
            out.write(if (first) tag else TAG_CONT)
            out.write(payload, off, n)
            off += n
            first = false
        }
        return out.toByteArray()
    }

    /**
     * Baca satu frame data dari stream → (tag, payload rakitan).
     * Berhenti saat chunk pendek (<255) ATAU payload mencapai panjang deklarasi.
     */
    fun decodeFrame(input: InputStream): Pair<Int, ByteArray> {
        val assembled = ByteArrayOutputStream()
        var tag = -1
        while (true) {
            val len = input.read().also { if (it < 0) throw EOFException("stream putus") }
            val t = input.read().also { if (it < 0) throw EOFException("stream putus") }
            if (tag == -1) tag = t
            val buf = ByteArray(len)
            readFully(input, buf)
            assembled.write(buf)
            val a = assembled.toByteArray()
            val done = len < 255 || (a.size >= 2 && a.size >= 2 + declaredExtra(tag, a))
            if (done) {
                val total = if (a.size >= 2) 2 + declaredExtra(tag, a) else a.size
                return tag to if (a.size > total) a.copyOf(total) else a
            }
        }
    }

    /**
     * Payload rakitan → body M2 untuk frame mentah (`[len 2B BE][M2...]`).
     */
    fun decodeRawBody(assembled: ByteArray): ByteArray {
        if (assembled.size < 2) throw WinboxException("payload mentah terlalu pendek")
        val len = ((assembled[0].toInt() and 0xFF) shl 8) or (assembled[1].toInt() and 0xFF)
        if (assembled.size < 2 + len) throw WinboxException("body M2 terpotong")
        return assembled.copyOfRange(2, 2 + len)
    }

    /** Sisa setelah 2 byte deklarasi: 16 (IV) + enc_len untuk terenkripsi, inner-len untuk mentah. */
    private fun declaredExtra(tag: Int, a: ByteArray): Int {
        val inner = ((a[0].toInt() and 0xFF) shl 8) or (a[1].toInt() and 0xFF)
        return if (tag == TAG_ENCRYPTED) 16 + inner else inner
    }
}

internal fun readFully(input: InputStream, buf: ByteArray, off: Int = 0, len: Int = buf.size - off) {
    var o = off
    while (o < off + len) {
        val r = input.read(buf, o, off + len - o)
        if (r < 0) throw EOFException("stream putus")
        o += r
    }
}

class WinboxException(msg: String) : Exception(msg)
