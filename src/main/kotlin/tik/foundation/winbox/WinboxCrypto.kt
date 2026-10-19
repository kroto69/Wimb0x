package tik.foundation.winbox

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Kripto sesi WinBox (jalur baru / EC-SRP5).
 *
 * - AES-128-CBC, IV acak 16 byte PER FRAME, kunci tetap sepanjang sesi.
 * - Tiap frame didekripsi independen (tanpa state/sequence) — aman di-multiplex.
 * - HMAC-SHA1 dihitung & ditempel, tapi TIDAK diverifikasi saat dekripsi
 *   (sesuai kedua implementasi referensi — untuk interop, bukan integritas).
 */
object WinboxCrypto {

    fun sha256(d: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(d)

    fun sha1(d: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-1").digest(d)

    fun hmacSha1(key: ByteArray, msg: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(key, "HmacSHA1"))
        return mac.doFinal(msg)
    }

    fun md5(d: ByteArray): ByteArray =
        MessageDigest.getInstance("MD5").digest(d)

    /**
     * HKDF kustom WinBox → 36 byte.
     * h1 = HMAC-SHA1(key=64×0x00, message);
     * round_i = HMAC-SHA1(key=h1, prev ‖ i) untuk i=1,2.
     */
    fun hkdf(message: ByteArray): ByteArray {
        val h1 = hmacSha1(ByteArray(64), message)
        var prev = ByteArray(0)
        val res = ByteArrayOutputStream()
        for (i in 1..2) {
            val round = hmacSha1(h1, prev + byteArrayOf(i.toByte()))
            prev = round
            res.write(round)
        }
        return res.toByteArray().copyOf(36)
    }

    data class StreamKeys(
        val sendAes: ByteArray, // 16
        val sendHmac: ByteArray, // 20
        val recvAes: ByteArray, // 16
        val recvHmac: ByteArray, // 20
    )

    /**
     * Derivasi kunci dari `secret` 32-byte hasil EC-SRP5.
     * [isServer] = true bila menghitung dari sisi server (m2/m3 ditukar).
     */
    fun deriveKeys(secret: ByteArray, isServer: Boolean = false): StreamKeys {
        val m2 = "On the client side, this is the send key; on the server side, it is the receive key."
            .toByteArray(Charsets.UTF_8)
        val m3 = "On the client side, this is the receive key; on the server side, it is the send key."
            .toByteArray(Charsets.UTF_8)
        val (txMagic, rxMagic) = if (isServer) m3 to m2 else m2 to m3
        val txEnc = sha1(secret + ByteArray(40) + txMagic + ByteArray(40) { 0xF2.toByte() }).copyOf(16)
        val rxEnc = sha1(secret + ByteArray(40) + rxMagic + ByteArray(40) { 0xF2.toByte() }).copyOf(16)
        val sk = hkdf(txEnc)
        val rk = hkdf(rxEnc)
        return StreamKeys(
            sendAes = sk.copyOf(16), sendHmac = sk.copyOfRange(16, 36),
            recvAes = rk.copyOf(16), recvHmac = rk.copyOfRange(16, 36),
        )
    }

    /**
     * Enkripsi satu pesan M2 → payload frame `[enc_len 2B BE][IV 16B][ciphertext]`.
     * Padding kustom: padByte = 0x0F − (len % 16), tambah padByte+1 salinan
     * (bukan PKCS#7 — tak pernah menghasilkan byte > 0x0F).
     */
    fun encryptFrame(
        m2: ByteArray,
        sendAes: ByteArray,
        sendHmac: ByteArray,
        rng: SecureRandom = SecureRandom(),
    ): ByteArray {
        val body = m2 + hmacSha1(sendHmac, m2)
        val padByte = 0x0F - (body.size % 16)
        val padded = body + ByteArray(padByte + 1) { padByte.toByte() }
        val iv = ByteArray(16).also { rng.nextBytes(it) }
        val ct = aes(sendAes, iv, padded, Cipher.ENCRYPT_MODE)
        val out = ByteArrayOutputStream()
        out.write((ct.size shr 8) and 0xFF)
        out.write(ct.size and 0xFF)
        out.write(iv)
        out.write(ct)
        return out.toByteArray()
    }

    /** Dekripsi payload frame rakitan → pesan M2 (HMAC dilepas tanpa verifikasi). */
    fun decryptFrame(payload: ByteArray, recvAes: ByteArray): ByteArray {
        if (payload.size < 18) throw WinboxException("payload terenkripsi terlalu pendek")
        val encLen = ((payload[0].toInt() and 0xFF) shl 8) or (payload[1].toInt() and 0xFF)
        if (payload.size < 18 + encLen) throw WinboxException("ciphertext terpotong")
        val iv = payload.copyOfRange(2, 18)
        val ct = payload.copyOfRange(18, 18 + encLen)
        val pt = aes(recvAes, iv, ct, Cipher.DECRYPT_MODE)
        val padTotal = (pt.last().toInt() and 0xFF) + 1
        if (padTotal > pt.size || padTotal > 16) throw WinboxException("padding tak valid")
        val noPad = pt.copyOf(pt.size - padTotal)
        if (noPad.size < 20) throw WinboxException("HMAC hilang")
        return noPad.copyOf(noPad.size - 20)
    }

    private fun aes(key: ByteArray, iv: ByteArray, data: ByteArray, mode: Int): ByteArray {
        val c = Cipher.getInstance("AES/CBC/NoPadding")
        c.init(mode, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        return c.doFinal(data)
    }

    /**
     * RC4 — hanya untuk referensi jalur legacy "secure mode" app asli.
     * Derivasi kuncinya tidak terdokumentasi publik; implementasi publik
     * menempuh jalur legacy sebagai plaintext.
     */
    class Rc4(key: ByteArray) {
        private val s = IntArray(256) { it }
        private var i = 0
        private var j = 0

        init {
            var jj = 0
            for (ii in 0..255) {
                jj = (jj + s[ii] + (key[ii % key.size].toInt() and 0xFF)) and 0xFF
                val tmp = s[ii]; s[ii] = s[jj]; s[jj] = tmp
            }
        }

        /** Lewati n byte keystream (cf. RC4::skip di native lib). */
        fun skip(n: Int) {
            repeat(n) { nextByte() }
        }

        private fun nextByte(): Int {
            i = (i + 1) and 0xFF
            j = (j + s[i]) and 0xFF
            val tmp = s[i]; s[i] = s[j]; s[j] = tmp
            return s[(s[i] + s[j]) and 0xFF]
        }

        fun crypt(data: ByteArray): ByteArray =
            ByteArray(data.size) { k -> (data[k].toInt() xor nextByte()).toByte() }
    }
}
