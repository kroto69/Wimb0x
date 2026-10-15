package tik.foundation.winbox

import tik.foundation.winbox.WinboxCrypto.sha256
import java.math.BigInteger
import java.security.SecureRandom

/**
 * Matematika EC-SRP5 WinBox: Curve25519 dalam bentuk Weierstrass.
 * y² = x³ + ax + b (mod p), ekuivalen Montgomery y² = x³ + 486662x² + x.
 *
 * Port setia dari implementasi referensi publik (WCurve), diverifikasi
 * melawan vektor tetap dari referensi tersebut (lihat SmokeTest).
 */
object WinboxCurve {
    val P: BigInteger = BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
    val R: BigInteger = BigInteger("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
    private val MONT_A: BigInteger = BigInteger.valueOf(486662)
    private val WA: BigInteger = BigInteger("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144", 16)
    private val WB: BigInteger = BigInteger("7b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864", 16)
    private val INV3: BigInteger = BigInteger.valueOf(3).modInverse(P)

    /** Offset Montgomery-x → Weierstrass-x. */
    val CONV_FROM_M: BigInteger = (MONT_A * INV3).mod(P)

    /** Offset Weierstrass-x → Montgomery-x. */
    val CONV: BigInteger = (P - (MONT_A * INV3).mod(P)).mod(P)

    class WPoint(val x: BigInteger, val y: BigInteger, val inf: Boolean = false) {
        companion object {
            val INF = WPoint(BigInteger.ZERO, BigInteger.ZERO, true)
        }
    }

    val G: WPoint = liftX(BigInteger.valueOf(9), 0)
        ?: error("titik generator tak valid")

    /** Tonelli-Shanks; null bila bukan residu kuadratik. */
    fun modSqrt(a: BigInteger): BigInteger? {
        val n = a.mod(P)
        if (n == BigInteger.ZERO) return BigInteger.ZERO
        val half = (P - BigInteger.ONE) / BigInteger.TWO
        if (n.modPow(half, P) != BigInteger.ONE) return null
        if (P.mod(BigInteger.valueOf(4)) == BigInteger.valueOf(3)) {
            return n.modPow((P + BigInteger.ONE) / BigInteger.valueOf(4), P)
        }
        var q = P - BigInteger.ONE
        var s = 0
        while (q.mod(BigInteger.TWO) == BigInteger.ZERO) {
            q /= BigInteger.TWO
            s++
        }
        var z = BigInteger.ONE
        while (z.modPow(half, P) != P - BigInteger.ONE) z += BigInteger.ONE
        var c = z.modPow(q, P)
        var x = n.modPow((q + BigInteger.ONE) / BigInteger.TWO, P)
        var t = n.modPow(q, P)
        var m = s
        val two = BigInteger.TWO
        while (t != BigInteger.ONE) {
            var i = m - 1 // default bila loop tak break (sesuai referensi)
            var e = two
            for (ii in 1 until m) {
                if (t.modPow(e, P) == BigInteger.ONE) {
                    i = ii
                    break
                }
                e *= two
            }
            val b = c.modPow(two.pow(m - i - 1), P)
            x = (x * b).mod(P)
            t = (t * b % P * b).mod(P)
            c = (b * b).mod(P)
            m = i
        }
        return x
    }

    /**
     * Angkat koordinat-x Montgomery menjadi titik Weierstrass,
     * pilih y sesuai [parity] (0 = genap, 1 = ganjil). Null bila tak liftable.
     */
    fun liftX(x: BigInteger, parity: Int): WPoint? {
        val xm = x.mod(P)
        val y2 = (xm.pow(3) + MONT_A * xm.pow(2) + xm).mod(P)
        val xw = (xm + CONV_FROM_M).mod(P)
        val r = modSqrt(y2) ?: return null
        val wantOdd = parity == 1
        val y = if (r.testBit(0) == wantOdd) r else P - r
        return WPoint(xw, y)
    }

    /** Titik Weierstrass → (x Montgomery 32B BE, parity y). */
    fun toMontgomery(pt: WPoint): Pair<ByteArray, Int> {
        require(!pt.inf)
        val x = (pt.x + CONV).mod(P)
        return x.toBytes32() to if (pt.y.testBit(0)) 1 else 0
    }

    fun add(p1: WPoint, p2: WPoint): WPoint {
        if (p1.inf) return p2
        if (p2.inf) return p1
        val x1 = p1.x
        val y1 = p1.y
        val x2 = p2.x
        val y2 = p2.y
        if (x1 == x2) {
            return if ((y1 + y2).mod(P) == BigInteger.ZERO) WPoint.INF else double(p1)
        }
        val lambda = ((y2 - y1).mod(P) * (x2 - x1).mod(P).modInverse(P)).mod(P)
        val x3 = (lambda * lambda - x1 - x2).mod(P)
        val y3 = (lambda * (x1 - x3) - y1).mod(P)
        return WPoint(x3, y3)
    }

    fun double(p: WPoint): WPoint {
        if (p.inf) return p
        if (p.y.mod(P) == BigInteger.ZERO) return WPoint.INF
        val lambda = ((BigInteger.valueOf(3) * p.x * p.x + WA).mod(P) *
            (BigInteger.TWO * p.y).mod(P).modInverse(P)).mod(P)
        val x3 = (lambda * lambda - BigInteger.TWO * p.x).mod(P)
        val y3 = (lambda * (p.x - x3) - p.y).mod(P)
        return WPoint(x3, y3)
    }

    fun multiply(k: BigInteger, p: WPoint): WPoint {
        var r = WPoint.INF
        var base = p
        var kk = k
        while (kk > BigInteger.ZERO) {
            if (kk.testBit(0)) r = add(r, base)
            base = double(base)
            kk = kk.shiftRight(1)
        }
        return r
    }

    /** Kunci publik Montgomery dari private 32 byte. */
    fun genPublicKey(priv: ByteArray): Pair<ByteArray, Int> {
        val pt = multiply(BigInteger(1, priv), G)
        return toMontgomery(pt)
    }

    /**
     * Titik deterministik dari bytes (loop double-SHA256) — cf. redp1 referensi.
     */
    fun redp1(x: ByteArray, parity: Int): WPoint {
        var cur = sha256(x)
        while (true) {
            val x2 = sha256(cur)
            val pt = liftX(BigInteger(1, x2), parity)
            if (pt != null) return pt
            cur = (BigInteger(1, cur) + BigInteger.ONE).toBytes32()
        }
    }

    fun BigInteger.toBytes32(): ByteArray {
        val b = toByteArray() // BE two's complement, bisa ada leading zero
        val raw = if (b.size > 32) b.copyOfRange(b.size - 32, b.size) else b
        return ByteArray(32 - raw.size) + raw
    }
}

/**
 * Alur autentikasi EC-SRP5 (RouterOS ≥ 6.43) sebagai fungsi murni
 * agar bisa diuji tanpa socket.
 */
object EcSrp5 {

    fun validatorPriv(username: String, password: String, salt: ByteArray): ByteArray =
        sha256(salt + sha256("$username:$password".toByteArray(Charsets.UTF_8)))

    data class Init(val privA: ByteArray, val xWA: ByteArray, val parityA: Int)

    fun init(rng: SecureRandom = SecureRandom()): Init {
        val privA = ByteArray(32).also { rng.nextBytes(it) }
        val (xWA, parityA) = WinboxCurve.genPublicKey(privA)
        return Init(privA, xWA, parityA)
    }

    /** Payload frame handshake pertama: username + 0x00 + xWA(32B) + parity(1B). */
    fun handshakePayload(username: String, init: Init): ByteArray =
        username.toByteArray(Charsets.UTF_8) +
            byteArrayOf(0) + init.xWA + byteArrayOf(init.parityA.toByte())

    data class Secret(
        val secret: ByteArray, // 32B — bahan kunci sesi
        val clientCc: ByteArray, // 32B — bukti untuk server
        val j: ByteArray,
        val zMont: ByteArray,
    )

    /**
     * Olah challenge server (xWB 32B + parity + salt 16B) → secret & bukti client.
     */
    fun processChallenge(
        init: Init,
        xWB: ByteArray,
        parityB: Int,
        salt: ByteArray,
        username: String,
        password: String,
    ): Secret {
        val c = WinboxCurve
        val valPriv = validatorPriv(username, password, salt)
        val (xGamma, _) = c.genPublicKey(valPriv)
        val v = c.redp1(xGamma, 1)
        val wB = c.liftX(BigInteger(1, xWB), parityB)
            ?: throw WinboxException("lift_x gagal untuk xWB server")
        val sum = c.add(wB, v)
        val j = sha256(init.xWA + xWB)
        val vh = (BigInteger(1, valPriv) * BigInteger(1, j) + BigInteger(1, init.privA))
            .mod(WinboxCurve.R)
        val zPt = c.multiply(vh, sum)
        val (zMont, _) = c.toMontgomery(zPt)
        val secret = sha256(zMont)
        val clientCc = sha256(j + zMont)
        return Secret(secret, clientCc, j, zMont)
    }

    /** Verifikasi konfirmasi server: serverCc == SHA256(j ‖ clientCc ‖ zMont). */
    fun verifyServer(serverCc: ByteArray, s: Secret): Boolean =
        sha256(s.j + s.clientCc + s.zMont).contentEquals(serverCc)
}
