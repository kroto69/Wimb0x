package tik.foundation

import tik.foundation.discovery.Mndp
import tik.foundation.discovery.MndpDiscovery
import tik.foundation.discovery.parseNeighbor
import tik.foundation.winbox.EcSrp5
import tik.foundation.winbox.K_SESSION_ID
import tik.foundation.winbox.K_SYS_CMD
import tik.foundation.winbox.K_SYS_REQID
import tik.foundation.winbox.K_SYS_REQUEST
import tik.foundation.winbox.K_SYS_TO
import tik.foundation.winbox.M2Message
import tik.foundation.winbox.M2Ns
import tik.foundation.winbox.M2Value
import tik.foundation.winbox.WinboxCrypto
import tik.foundation.winbox.WinboxCurve
import tik.foundation.winbox.WinboxFrame
import tik.foundation.winbox.m2Key
import tik.foundation.winbox.sysCmd
import tik.foundation.winbox.sysFrom
import tik.foundation.winbox.sysReqId
import tik.foundation.winbox.sysRequest
import tik.foundation.winbox.sysTo
import tik.foundation.winbox.formatIpv4U32
import tik.foundation.winbox.formatMac
import tik.foundation.winbox.M2Field
import tik.foundation.winbox.parseHotspotRow
import tik.foundation.winbox.parseLogRow
import tik.foundation.winbox.userRaw
import tik.foundation.winbox.userStr
import tik.foundation.winbox.userU8
import tik.foundation.winbox.userU32
import tik.foundation.winbox.ipToU32
import tik.foundation.winbox.itemId
import tik.foundation.winbox.WinboxPaths
import tik.foundation.winbox.LiveTable
import tik.foundation.winbox.isDeleteMarker
import java.io.ByteArrayInputStream

private var failures = 0

private fun check(name: String, cond: Boolean) {
    if (cond) {
        println("PASS: $name")
    } else {
        println("FAIL: $name")
        failures++
    }
}

private fun hex(s: String): ByteArray {
    val c = s.replace(" ", "")
    return ByteArray(c.length / 2) { i ->
        ((c[i * 2].digitToInt(16) shl 4) + c[i * 2 + 1].digitToInt(16)).toByte()
    }
}

private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

/** Smoke test tanpa framework: `java -cp ... tik.foundation.SmokeTestKt`. */
fun main() {
    // ============ MNDP ============
    val pkt = Mndp.encodeTlv(Mndp.Tag.IDENTITY, "MikroTik".toByteArray()) +
        Mndp.encodeTlv(Mndp.Tag.VERSION, "7.16 (stable)".toByteArray()) +
        Mndp.encodeTlv(Mndp.Tag.BOARDNAME, "RB5009".toByteArray()) +
        Mndp.encodeTlv(
            Mndp.Tag.MACADDR,
            byteArrayOf(0x48, 0xA9.toByte(), 0x8A.toByte(), 0x11, 0x22, 0x33),
        )
    val n = parseNeighbor("192.168.88.1", pkt)
    check("mndp identity", n?.identity == "MikroTik")
    check("mndp version", n?.version == "7.16 (stable)")
    check("mndp board", n?.boardName == "RB5009")
    check("mndp mac", n?.mac == "48:A9:8A:11:22:33")
    check("mndp displayName", n?.displayName == "MikroTik")
    check("mndp unknown tag ignored", parseNeighbor("1.1.1.1", byteArrayOf(0, 99, 0, 1, 7)) == null)

    // Regression 2026-10-15: di dalam apply{}, `port` polos resolve ke
    // DatagramSocket.getPort() (= -1) bukan MndpDiscovery.port -> crash saat bind.
    // Tes ini gagal sebelum fix (IllegalArgumentException: port out of range: -1).
    try {
        MndpDiscovery().use { d ->
            d.start()
            Thread.sleep(300)
            check("mndp discovery instantiate+start", d.neighbors().isEmpty())
            d.stop()
        }
        check("mndp discovery close", true)
    } catch (e: Exception) {
        check("mndp discovery instantiate+start", false)
        check("mndp discovery close", false)
    }

    // ============ M2: byte persis contoh referensi (PROTOCOL.md §6) ============
    val initReq = M2Message(
        listOf(sysTo(13, 4), sysFrom(0, 1), sysRequest(true), sysReqId(0), sysCmd(7)),
    ).encode()
    val expectedInitReq = hex(
        "4d32 0100ff88 0200 0d000000 04000000 " +
            "0200ff88 0200 00000000 01000000 " +
            "0500ff01 0600ff09 00 0700ff09 07",
    )
    check("m2 init-request bytes", initReq.contentEquals(expectedInitReq))

    // M2 roundtrip semua tipe
    val allTypes = M2Message(
        listOf(
            tik.foundation.winbox.M2Field(K_SYS_TO, M2Value.U32Array(listOf(13, 4))),
            tik.foundation.winbox.M2Field(K_SYS_REQUEST, M2Value.Bool(true)),
            tik.foundation.winbox.M2Field(K_SYS_REQID, M2Value.U8(42)),
            tik.foundation.winbox.M2Field(K_SYS_CMD, M2Value.U32(0xFE0004)),
            tik.foundation.winbox.M2Field(K_SESSION_ID, M2Value.U8(7)),
            tik.foundation.winbox.M2Field(m2Key(1, M2Ns.USER), M2Value.Str("admin")),
            tik.foundation.winbox.M2Field(m2Key(2, M2Ns.USER), M2Value.Raw(byteArrayOf(1, 2, 3))),
            tik.foundation.winbox.M2Field(m2Key(3, M2Ns.USER), M2Value.U64(0xFFFFFFFFFFFFFFFFu)),
            tik.foundation.winbox.M2Field(m2Key(4, M2Ns.USER), M2Value.Addr6(ByteArray(16) { it.toByte() })),
            tik.foundation.winbox.M2Field(m2Key(5, M2Ns.USER), M2Value.Str("x".repeat(300))),
            tik.foundation.winbox.M2Field(m2Key(6, M2Ns.USER), M2Value.U32Array(listOf(1, 2, 3))),
            tik.foundation.winbox.M2Field(m2Key(7, M2Ns.USER), M2Value.StrArray(listOf("a", "bb"))),
            tik.foundation.winbox.M2Field(
                m2Key(8, M2Ns.USER),
                M2Value.Embedded(M2Message(listOf(userStr(1, "inner")))),
            ),
            tik.foundation.winbox.M2Field(m2Key(9, M2Ns.USER), M2Value.Bool(false)),
        ),
    )
    val rt = M2Message.decode(allTypes.encode())
    check("m2 roundtrip semua tipe", rt.encode().contentEquals(allTypes.encode()))
    check("m2 decode u32array", rt.u32Array(K_SYS_TO) == listOf(13L, 4L))
    check("m2 decode u64", rt.u64(m2Key(3, M2Ns.USER)) == 0xFFFFFFFFFFFFFFFFu)
    check("m2 decode bool", rt.bool(K_SYS_REQUEST) == true && rt.bool(m2Key(9, M2Ns.USER)) == false)

    // ============ Framing ============
    for (size in listOf(10, 254, 255, 256, 510, 511, 600)) {
        val body = ByteArray(size) { (it % 251).toByte() }
        // payload frame mentah = [len 2B BE][body]
        val payload = byteArrayOf(((size shr 8) and 0xFF).toByte(), (size and 0xFF).toByte()) + body
        val enc = WinboxFrame.encodeData(payload, WinboxFrame.TAG_RAW)
        val (t, got) = WinboxFrame.decodeFrame(ByteArrayInputStream(enc))
        check("frame roundtrip $size", t == WinboxFrame.TAG_RAW && got.contentEquals(payload))
    }
    // Handshake tidak di-chunk
    val hs = WinboxFrame.encodeHandshake(byteArrayOf(1, 2, 3))
    check("frame handshake", hs.contentEquals(byteArrayOf(3, 0x06, 1, 2, 3)))

    // Kasus tepi: frame terenkripsi kelipatan 255 — berhenti via panjang deklarasi
    val inner = ByteArray(492) { it.toByte() }
    val encPayload = byteArrayOf(0x01, 0xEC.toByte()) + ByteArray(16) + inner // enc_len=492
    val encFrame = WinboxFrame.encodeData(encPayload, WinboxFrame.TAG_ENCRYPTED)
    val stream = encFrame + byteArrayOf(0x03, 0x06, 0xAA.toByte(), 0xBB.toByte(), 0xCC.toByte())
    val inp = ByteArrayInputStream(stream)
    val (et, edec) = WinboxFrame.decodeFrame(inp)
    check("frame enc-510 berhenti tepat", et == 0x06 && edec.size == 510)
    check("frame enc-510 tak menelan frame berikut", inp.available() == 5)

    // ============ Kripto ============
    val hk1 = WinboxCrypto.hkdf(ByteArray(16) { 0x01 })
    val hk2 = WinboxCrypto.hkdf(ByteArray(16) { 0x01 })
    check("hkdf 36B deterministik", hk1.size == 36 && hk1.contentEquals(hk2))

    val secretProbe = ByteArray(32) { 0x07 }
    val ck = WinboxCrypto.deriveKeys(secretProbe, false)
    val sk = WinboxCrypto.deriveKeys(secretProbe, true)
    check(
        "deriveKeys simetri c-s",
        ck.sendAes.contentEquals(sk.recvAes) && ck.sendHmac.contentEquals(sk.recvHmac) &&
            ck.recvAes.contentEquals(sk.sendAes),
    )
    val m2sample = M2Message(listOf(sysTo(13, 4), sysRequest(true))).encode()
    val encM2 = WinboxCrypto.encryptFrame(m2sample, ck.sendAes, ck.sendHmac)
    val decM2 = WinboxCrypto.decryptFrame(encM2, sk.recvAes)
    check("aes frame roundtrip", decM2.contentEquals(m2sample))

    val rc4 = WinboxCrypto.Rc4("Key".toByteArray())
    check("rc4 vektor", rc4.crypt("Plaintext".toByteArray()).hex() == "bbf316e8d940af0ad3")

    // ============ EC-SRP5: vektor tetap dari implementasi referensi ============
    // privA = 32×0x42, salt = 16×0x11, xWB = xWA (self-point), admin/test123
    val privA = ByteArray(32) { 0x42 }
    val (xWA, parityA) = WinboxCurve.genPublicKey(privA)
    check("ec xWA", xWA.hex() == "5baef10ac1c562586d49115d49ca9992c54bd78b265293a076ed11391a0c9cb4")
    check("ec parityA", parityA == 1)
    val salt = ByteArray(16) { 0x11 }
    val init = EcSrp5.Init(privA, xWA, parityA)
    val sec = EcSrp5.processChallenge(init, xWA, parityA, salt, "admin", "test123")
    check(
        "ec clientCc",
        sec.clientCc.hex() == "6dbc53fdc81b02fde094bcc4470cf1cfcc061a3093654984bf6f50deb966680c",
    )
    check(
        "ec verifyServer",
        EcSrp5.verifyServer(hex("86e02986932c9ff4eabacdf6566c25dae23aa85b7768bf0ff89218a79aa33c47"), sec),
    )
    val eck = WinboxCrypto.deriveKeys(sec.secret)
    check("ec sendAes", eck.sendAes.hex() == "2986a98fed9da6c93ddbf1c8e254646d")
    check("ec recvAes", eck.recvAes.hex() == "5e09d5f1ebd42eaa1f7c85f13209e1ff")
    check("ec sendHmac", eck.sendHmac.hex() == "4bdf8a6e601b742f82d17de388f45eeb5f226cda")
    check("ec recvHmac", eck.recvHmac.hex() == "2c52c76ea7697279d441ec5b3fd298429d635aa9")

    // ============ Fitur: Hotspot Active [63,13] & Logs [3,4] ============
    // IPv4 u32 = octet-LSB (oktet pertama = byte paling rendah; encoder webfig)
    check("ip octet-LSB", formatIpv4U32(0x0158A8C0L) == "192.168.88.1")
    check("ip loopback", formatIpv4U32(0x0100007FL) == "127.0.0.1")
    check("ip nol", formatIpv4U32(0L) == "0.0.0.0")
    check(
        "mac format",
        formatMac(byteArrayOf(0xDC.toByte(), 0x2C, 0x6E, 0x66, 0x44, 0x61)) == "DC:2C:6E:66:44:61",
    )
    val hsRow = M2Message(
        listOf(
            userStr(1, "budi"),
            userU32(2, 0x0158A8C0L),
            userU32(3, 3661),
            userRaw(0x0B, byteArrayOf(0xDC.toByte(), 0x2C, 0x6E, 0x66, 0x44, 0x61)),
            userU8(0x12, 2),
            userStr(0x13, "http-chap"),
        ),
    )
    val hot = parseHotspotRow(hsRow)
    check("hotspot user", hot.user == "budi")
    check("hotspot address", hot.address == "192.168.88.1")
    check("hotspot uptime", hot.uptimeSec == 3661L)
    check("hotspot mac", hot.mac == "DC:2C:6E:66:44:61")
    check("hotspot server", hot.server == 2)
    check("hotspot loginBy", hot.loginBy == "http-chap")
    val hsRowU8 = M2Message(listOf(userStr(1, "x"), userU32(2, 0x0100007FL), userU8(3, 42)))
    val hot2 = parseHotspotRow(hsRowU8)
    check("hotspot uptime u8-toleran", hot2.uptimeSec == 42L)
    check("hotspot field opsional null", hot2.server == null && hot2.loginBy == null)
    val logRow = M2Message(
        listOf(
            userU32(1, 1760486400L),
            userStr(2, "memory"),
            userStr(3, "user budi logged in from 192.168.88.10 via winbox"),
            M2Field(m2Key(4, M2Ns.USER), M2Value.U32Array(listOf(1L, 2L))),
        ),
    )
    val lg = parseLogRow(logRow)
    check("log time", lg.timeUnix == 1760486400L)
    check("log buffer", lg.buffer == "memory")
    check("log topics", lg.topics == listOf(1L, 2L))
    check("log message", lg.message == "user budi logged in from 192.168.88.10 via winbox")
    val logRowMin = M2Message(listOf(userU32(1, 1), userStr(3, "m")))
    val lg2 = parseLogRow(logRowMin)
    check("log buffer null aman", lg2.buffer == null && lg2.topics.isEmpty())

    // ============ WinboxOps: IP, item id, paths ============
    check("ipToU32", ipToU32("192.168.88.1") == 0x0158A8C0L)
    check("ip roundtrip", formatIpv4U32(ipToU32("10.3.30.119")) == "10.3.30.119")
    val idRow = M2Message(listOf(M2Field(0xFE0001, M2Value.U8(7)), userStr(1, "x")))
    check("itemId u8", idRow.itemId()?.let { (it.value as M2Value.U8).v } == 7)
    val idRow32 = M2Message(listOf(M2Field(0xFE0001, M2Value.U32(1234)), userStr(1, "x")))
    check("itemId u32", idRow32.itemId()?.let { (it.value as M2Value.U32).v } == 1234L)
    check("paths", WinboxPaths.PPP_SECRET == listOf(27, 101) && WinboxPaths.LOG == listOf(3, 4))

    // ============ LiveTable: apply add/update/delete ============
    fun row(id: Int, name: String?) = M2Message(
        listOf(M2Field(0xFE0001, M2Value.U8(id))) +
            (if (name != null) listOf(userStr(1, name)) else emptyList()),
    )
    fun delRow(id: Int) = M2Message(
        listOf(M2Field(0xFE0013, M2Value.U8(1)), M2Field(0xFE0001, M2Value.U8(id))),
    )
    val lt = LiveTable { m: M2Message -> m.str(m2Key(1, M2Ns.USER)) }
    lt.setInitial(listOf(row(1, "a"), row(2, "b")))
    check("livetable initial", lt.snapshot() == listOf("a", "b"))
    check("livetable add", lt.applyUpdate(listOf(row(3, "c"))) && lt.snapshot() == listOf("a", "b", "c"))
    check("livetable update", lt.applyUpdate(listOf(row(2, "b2"))) && lt.snapshot()[1] == "b2")
    check("livetable delete", lt.applyUpdate(listOf(delRow(1))) && lt.snapshot() == listOf("b2", "c"))
    check("livetable delete-marker", delRow(9).isDeleteMarker() && !row(9, "x").isDeleteMarker())
    check("livetable noop", !lt.applyUpdate(listOf(delRow(99))) && !lt.applyUpdate(emptyList()))

    println(if (failures == 0) "ALL SMOKE TESTS PASSED" else "$failures FAILURES")
    if (failures > 0) kotlin.system.exitProcess(1)
}
