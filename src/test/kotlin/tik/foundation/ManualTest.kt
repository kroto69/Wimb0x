package tik.foundation

import tik.foundation.winbox.*

/**
 * Test runner manual (tanpa JUnit) — untuk sandbox tanpa akses SSL.
 * Jalankan: kotlinc ... && kotlin TikFoundationManualTestKt
 */
fun main() {
    var passed = 0
    var failed = 0

    fun test(name: String, block: () -> Unit) {
        try {
            block()
            passed++
            println("PASS: $name")
        } catch (e: AssertionError) {
            failed++
            println("FAIL: $name — ${e.message}")
        } catch (e: Exception) {
            failed++
            println("ERROR: $name — ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    fun assertEq(expected: Any?, actual: Any?, msg: String = "") {
        if (expected != actual) throw AssertionError("expected=$expected actual=$actual $msg")
    }

    fun assertNull(actual: Any?, msg: String = "") {
        if (actual != null) throw AssertionError("expected null, got=$actual $msg")
    }

    fun assertTrue(actual: Boolean, msg: String = "") {
        if (!actual) throw AssertionError("expected true $msg")
    }

    // ---------- RouterVersion ----------
    test("parse v7 dengan channel") {
        val v = RouterVersion.parse("7.24.4 (stable)")!!
        assertEq(7, v.major); assertEq(24, v.minor); assertEq(4, v.patch)
        assertTrue(v.isV7)
    }
    test("parse v6 polos") {
        val v = RouterVersion.parse("6.49.19")!!
        assertEq(6, v.major); assertTrue(v.isV6)
    }
    test("parse gagal return null") {
        assertNull(RouterVersion.parse(null))
        assertNull(RouterVersion.parse(""))
        assertNull(RouterVersion.parse("bukan-versi"))
    }

    // ---------- netmask ----------
    test("netmask 16777215 jadi 24") { assertEq(24, netmaskU32ToPrefix(16777215)) }
    test("netmask ffffff00 jadi 24") { assertEq(24, netmaskU32ToPrefix(0xFFFFFF00)) }
    test("netmask ffff0000 jadi 16") { assertEq(16, netmaskU32ToPrefix(0xFFFF0000)) }

    // ---------- FieldKey ----------
    fun msg(vararg fields: M2Field) = M2Message(fields.toList())
    test("FieldKey coba v7 dulu") {
        val row = msg(M2Field(0x1, M2Value.Str("v7name")), M2Field(0xFE0009, M2Value.Str("v6name")))
        assertEq("v7name", row.str(VersionedKeys.PPP_NAME))
    }
    test("FieldKey fallback v6") {
        val row = msg(M2Field(0xFE0009, M2Value.Str("v6name")))
        assertEq("v6name", row.str(VersionedKeys.PPP_NAME))
    }

    // ---------- escapeTerminalArg ----------
    test("escapeTerminalArg") {
        assertEq("hello", escapeTerminalArg("hello"))
        assertEq("a\\\"b", escapeTerminalArg("a\"b"))
        assertEq("a\\\\b", escapeTerminalArg("a\\b"))
        assertEq("a\\\$b", escapeTerminalArg("a\$b"))
        assertEq("a\\[b\\]", escapeTerminalArg("a[b]"))
        assertEq("a\\;b", escapeTerminalArg("a;b"))
    }

    // ---------- WriteResult ----------
    test("toWriteResult Ok") {
        val resp = msg(M2Field(0xFF0008, M2Value.U8(0)), M2Field(0xFE0001, M2Value.U8(42)))
        assertTrue(resp.toWriteResult() is WriteResult.Ok)
    }
    test("toWriteResult Err") {
        val resp = msg(M2Field(0xFF0008, M2Value.U8(6)), M2Field(0xFF0009, M2Value.Str("invalid")))
        val r = resp.toWriteResult()
        assertTrue(r is WriteResult.Err)
        assertEq("invalid", (r as WriteResult.Err).message)
    }

    // ---------- PPP Active v7/v6 ----------
    test("parse PPP active v7-style") {
        val row = msg(
            M2Field(0xFE0001, M2Value.U8(5)),
            M2Field(0x1, M2Value.Str("user1")),
            M2Field(0x9, M2Value.U64(1000u)),
            M2Field(0xA, M2Value.U64(2000u)),
        )
        val p = parsePppActiveRow(row)!!
        assertEq("user1", p.name)
        assertEq(1000L, p.bytesA); assertEq(2000L, p.bytesB)
        assertNull(PppActive.BYTES_A_IS_DOWN)
    }
    test("parse PPP active v6-style") {
        val row = msg(
            M2Field(0xFE0009, M2Value.Str("v6user")),
            M2Field(0xFE0001, M2Value.U8(6)),
        )
        val p = parsePppActiveRow(row)!!
        assertEq("v6user", p.name)
    }
    test("FieldKey null bila tidak ada") {
        val row = msg()
        assertNull(row.str(VersionedKeys.PPP_NAME))
    }

    // ---------- Queue v7/v6 ----------
    test("parse queue v7-style") {
        val row = msg(
            M2Field(0xFE0001, M2Value.U8(1)),
            M2Field(0x2, M2Value.Str("q1")),
            M2Field(0xD8, M2Value.U64(1000000u)),
            M2Field(0x13C, M2Value.U64(2000000u)),
        )
        val q = parseQueueRow(row)!!
        assertEq("q1", q.name)
        assertEq(1000000L, q.maxUpBps); assertEq(2000000L, q.maxDownBps)
    }
    test("parse queue v6-style") {
        val row = msg(
            M2Field(0xFE0001, M2Value.U8(1)),
            M2Field(0x2, M2Value.Str("q1")),
            M2Field(0x3C, M2Value.U32(500000)),
            M2Field(0x47, M2Value.U32(1000000)),
        )
        val q = parseQueueRow(row)!!
        assertEq(500000L, q.maxUpBps); assertEq(1000000L, q.maxDownBps)
    }

    // ---------- writeCatching ----------
    test("writeCatching exception jadi Err") {
        val r = writeCatching { throw RuntimeException("boom") }
        assertTrue(r is WriteResult.Err)
        assertEq("boom", (r as WriteResult.Err).message)
    }
    test("writeCatching null jadi Timeout") {
        val r = writeCatching { null }
        assertTrue(r is WriteResult.Timeout)
    }

    // ---------- Service toleran ----------
    test("parse service toleran str") {
        val row = msg(
            M2Field(0xFE0001, M2Value.U8(1)),
            M2Field(0x1, M2Value.Str("www")),
            M2Field(0x2, M2Value.U32(80)),
        )
        val s = parseServiceRow(row)!!
        assertEq("www", s.name); assertEq(80, s.port)
    }
    test("parse service toleran uint") {
        val row = msg(
            M2Field(0xFE0001, M2Value.U8(1)),
            M2Field(0x1, M2Value.U8(5)),
            M2Field(0x2, M2Value.U8(80)),
        )
        val s = parseServiceRow(row)!!
        assertEq("5", s.name); assertEq(80, s.port)
    }

    // ---------- helpers ----------
    test("ipU32ToString") {
        assertEq("192.168.88.1", ipU32ToString(0x0158A8C0))
    }
    test("macToString") {
        val mac = byteArrayOf(0xDC.toByte(), 0x2C, 0x6E, 0x66, 0x44, 0x61)
        assertEq("DC:2C:6E:66:44:61", macToString(mac))
    }
    test("netmask tidak kontigu return null") {
        assertNull(netmaskU32ToPrefix(0xFF00FF00))
    }

    // ---------- Paging (pure functions) ----------
    test("extractRows dari MsgArray 0xFE0002") {
        val row1 = msg(M2Field(0x1, M2Value.Str("a")))
        val row2 = msg(M2Field(0x1, M2Value.Str("b")))
        val resp = msg(M2Field(0xFE0002, M2Value.MsgArray(listOf(row1, row2))))
        val rows = extractRows(resp)
        assertEq(2, rows.size)
        assertEq("a", rows[0].str(1))
    }
    test("extractRows kosong bila tidak ada 0xFE0002") {
        val resp = msg(M2Field(0x1, M2Value.Str("x")))
        assertEq(0, extractRows(resp).size)
    }
    test("extractContinuation u32") {
        val resp = msg(
            M2Field(0xFE0002, M2Value.MsgArray(emptyList())),
            M2Field(0xFE0003, M2Value.U32(12345)),
        )
        val (u32, raw) = extractContinuation(resp)
        assertTrue(u32 != null)
        assertEq(12345L, (u32!!.value as M2Value.U32).v)
        assertNull(raw)
    }
    test("extractContinuation raw") {
        val resp = msg(
            M2Field(0xFE0015, M2Value.Raw(byteArrayOf(1, 2, 3))),
        )
        val (u32, raw) = extractContinuation(resp)
        assertNull(u32)
        assertTrue(raw != null)
    }
    test("extractContinuation null bila halaman terakhir") {
        val resp = msg(M2Field(0xFE0002, M2Value.MsgArray(emptyList())))
        val (u32, raw) = extractContinuation(resp)
        assertNull(u32); assertNull(raw)
    }
    test("extractContinuation abaikan tipe salah") {
        // 0xFE0003 tapi bukan U32 → diabaikan
        val resp = msg(M2Field(0xFE0003, M2Value.Str("bukan-u32")))
        val (u32, _) = extractContinuation(resp)
        assertNull(u32)
    }

    // ---------- resolveInterfaceName (enum 0xA → itemId) ----------
    // Data sintetis meniru dump live 2026-10-17 (v7 RB4011 + v6 hEX).
    test("resolveInterfaceName cocokkan itemId kecil") {
        val opts = listOf(
            InterfaceOption(1, "ether1"),
            InterfaceOption(2, "ether2"),
            InterfaceOption(13, "lo"),
        )
        assertEq("ether1", resolveInterfaceName(1, opts))
        assertEq("ether2", resolveInterfaceName(2, opts))
        assertEq("lo", resolveInterfaceName(13, opts))
    }

    test("resolveInterfaceName cocokkan itemId besar (PPPoE)") {
        val opts = listOf(
            InterfaceOption(15729114, "<pppoe-RMWARU015@WIDI>"),
            InterfaceOption(15728660, "<pppoe-001TYAS@LAWE>"),
        )
        assertEq("<pppoe-RMWARU015@WIDI>", resolveInterfaceName(15729114, opts))
        assertEq("<pppoe-001TYAS@LAWE>", resolveInterfaceName(15728660, opts))
    }

    test("resolveInterfaceName null bila tidak ada") {
        val opts = listOf(InterfaceOption(1, "ether1"))
        assertNull(resolveInterfaceName(999, opts))
        assertNull(resolveInterfaceName(7, opts)) // itemId 7 tidak ada (kasus v6)
        assertNull(resolveInterfaceName(1, emptyList()))
    }

    test("resolveInterfaceName tidak tertukar dengan 0x10004") {
        // ether2: itemId=2, 0x10004=7. Enum 7 milik interface lain (atau yatim),
        // bukan ether2 — buktikan tidak salah resolve.
        val opts = listOf(
            InterfaceOption(1, "ether1"),
            InterfaceOption(2, "ether2"),
        )
        assertNull(resolveInterfaceName(7, opts))
    }

    test("parseIpAddressRow baca 0xA bukan 0x2") {
        // Baris IP: address=192.0.2.99 (0x1), network=192.0.2.0 (0x2),
        // interface=ether1 itemId 1 (0xA sebagai U8).
        val row = msg(
            M2Field(0xFE0001, M2Value.U32(4242)),
            M2Field(0x1, M2Value.U32(192L + 2L * 65536 + 99L * 16777216)), // 99.2.0.192 octet-LSB
            M2Field(0x3, M2Value.U32(16777215)), // /24
            M2Field(0x2, M2Value.U32(192L + 2L * 65536)), // network 192.0.2.0
            M2Field(0xA, M2Value.U8(1)), // interface = ether1
        )
        val names = mapOf(1L to "ether1", 2L to "ether2")
        val parsed = parseIpAddressRow(row, names)
        assertEq(1, parsed?.interfaceRef)
        assertEq("ether1", parsed?.interfaceName)
    }

    test("parseIpAddressRow 0xA U32 besar (PPPoE)") {
        val row = msg(
            M2Field(0xFE0001, M2Value.U32(777)),
            M2Field(0x1, M2Value.U32(10L * 16777216 + 19L * 65536 + 120L * 256 + 161L)),
            M2Field(0x3, M2Value.U32(16777215)),
            M2Field(0xA, M2Value.U32(15729114)), // PPPoE itemId
        )
        val names = mapOf(15729114L to "<pppoe-RMWARU015@WIDI>")
        val parsed = parseIpAddressRow(row, names)
        assertEq(15729114, parsed?.interfaceRef)
        assertEq("<pppoe-RMWARU015@WIDI>", parsed?.interfaceName)
    }

    // ---------- PPP Profile: rate-limit / dns / only-one ----------
    // Fixture dari dump nyata v6 2026-10-17 (zz-map; nama pelanggan disanitasi).
    test("parsePppProfileRow rate-limit/dns/only-one") {
        val row = msg(
            M2Field(0xFE0001, M2Value.U32(100)),
            M2Field(0x1, M2Value.Str("zz-map")),
            M2Field(0x16, M2Value.Str("7M/9M")),
            M2Field(0x15, M2Value.U32Array(listOf(151587082L, 134744074L))),
            M2Field(0x19, M2Value.U8(1)),
        )
        val p = parsePppProfileRow(row)
        assertEq("7M/9M", p?.rateLimit)
        assertEq(7000000L, p?.rateUpBps)
        assertEq(9000000L, p?.rateDownBps)
        assertEq(listOf("10.9.9.9", "10.8.8.8"), p?.dnsServers)
        assertEq(OnlyOne.YES, p?.onlyOne)
    }

    test("parsePppProfileRow only-one no/default/unknown") {
        fun oo(v: M2Value?) = parsePppProfileRow(msg(
            M2Field(0xFE0001, M2Value.U32(1)),
            M2Field(0x1, M2Value.Str("x")),
            M2Field(0x19, v!!),
        ))?.onlyOne
        assertEq(OnlyOne.NO, oo(M2Value.U8(0)))
        assertEq(OnlyOne.DEFAULT, oo(M2Value.U32(4294967295L)))
        assertEq(OnlyOne.UNKNOWN, oo(M2Value.U8(7)))
        // tanpa 0x19 -> UNKNOWN
        val p = parsePppProfileRow(msg(
            M2Field(0xFE0001, M2Value.U32(1)),
            M2Field(0x1, M2Value.Str("x")),
        ))
        assertEq(OnlyOne.UNKNOWN, p?.onlyOne)
        assertEq(emptyList<String>(), p?.dnsServers)
        assertEq(null, p?.rateUpBps)
    }

    test("parseRateLimitFirstPair multi-burst") {
        // Format lengkap MikroTik: ambil pasangan pertama saja
        val (up, down) = parseRateLimitFirstPair("8M/10M 12M/16M 6M/7500K 32/35 8 1M/1250K")
        assertEq(8000000L, up)
        assertEq(10000000L, down)
        val (u2, d2) = parseRateLimitFirstPair("")
        assertEq(null, u2); assertEq(null, d2)
        val (u3, d3) = parseRateLimitFirstPair("64k/64k")
        assertEq(64000L, u3); assertEq(64000L, d3)
    }

    test("toFields rate-limit/dns/only-one tipe wire benar") {
        val fields = PppProfileInput(
            name = "zz-test",
            rateUp = "7M", rateDown = "9M",
            dnsServers = listOf("10.9.9.9", "10.8.8.8"),
            onlyOne = OnlyOne.YES,
        ).toFields().filterNotNull().associate { it.key to it.value }

        val rl = fields[PppProfileFields.RATE_LIMIT] as M2Value.Str
        assertEq("7M/9M", rl.s)
        val dns = fields[PppProfileFields.DNS_SERVER] as M2Value.U32Array
        assertEq(listOf(151587082L, 134744074L), dns.vs)
        val oo = fields[PppProfileFields.ONLY_ONE] as M2Value.U8
        assertEq(1, oo.v)

        val fieldsNo = PppProfileInput(onlyOne = OnlyOne.NO).toFields()
            .filterNotNull().associate { it.key to it.value }
        assertEq(0, (fieldsNo[PppProfileFields.ONLY_ONE] as M2Value.U8).v)

        val fieldsDef = PppProfileInput(onlyOne = OnlyOne.DEFAULT).toFields()
            .filterNotNull().associate { it.key to it.value }
        assertEq(4294967295L, (fieldsDef[PppProfileFields.ONLY_ONE] as M2Value.U32).v)
    }

    test("toFields validasi rate/dns") {
        // rate negatif -> exception
        try {
            PppProfileInput(rateUp = "0", rateDown = "9M").toFields()
            throw AssertionError("harus throw")
        } catch (e: IllegalArgumentException) { /* ok */ }
        // dns invalid -> exception
        try {
            PppProfileInput(dnsServers = listOf("999.1.1.1")).toFields()
            throw AssertionError("harus throw")
        } catch (e: IllegalArgumentException) { /* ok */ }
        // >2 dns -> exception
        try {
            PppProfileInput(dnsServers = listOf("1.1.1.1", "8.8.8.8", "9.9.9.9")).toFields()
            throw AssertionError("harus throw")
        } catch (e: IllegalArgumentException) { /* ok */ }
    }

    test("round-trip rate 7M -> 7000000") {
        assertEq(7000000L, parseRateToBps("7M"))
        assertEq(9000000L, parseRateToBps("9M"))
        assertEq(512000L, parseRateToBps("512k"))
        // parser: "7M/9M" -> (7000000, 9000000)
        val (up, down) = parseRateLimitFirstPair("7M/9M")
        assertEq(7000000L, up); assertEq(9000000L, down)
    }

    // ---- Items 4-8: interface detail, bridge port, vlan, dhcp client, log ----

    test("parseInterfaceRow: mac/mtu/l2mtu/speed/running") {
        val r = msg(
            M2Field(0xFE0001, M2Value.U32(3)),
            M2Field(0x10006, M2Value.Str("ether1")),
            M2Field(0x1001E, M2Value.Str("ether")),
            M2Field(InterfaceFields.MAC_ADDRESS, M2Value.Raw(byteArrayOf(0x08, 0x55, 0x31, 0x6C, 0x6F, 0x7A.toByte()))),
            M2Field(InterfaceFields.MTU, M2Value.U32(1500)),
            M2Field(InterfaceFields.L2MTU, M2Value.U32(1596)),
            M2Field(InterfaceFields.SPEED, M2Value.U8(2)),
            M2Field(InterfaceFields.RUNNING, M2Value.Bool(true)),
        )
        val info = parseInterfaceRow(r) ?: throw AssertionError("null")
        assertEq("08:55:31:6C:6F:7A", info.mac)
        assertEq(1500, info.mtu)
        assertEq(1596, info.l2mtu)
        assertEq("1G", info.speed)
        assertEq(true, info.running)
    }

    test("parseInterfaceSpeed: enum mapping") {
        assertEq("1G", parseInterfaceSpeed(2))
        assertEq("10G", parseInterfaceSpeed(3))
        assertEq("enum-9", parseInterfaceSpeed(9))
    }

    test("parseInterfaceRow: vlan id + parent") {
        val r = msg(
            M2Field(0xFE0001, M2Value.U32(20)),
            M2Field(0x10006, M2Value.Str("v-30IN")),
            M2Field(0x1001E, M2Value.Str("vlan")),
            M2Field(InterfaceFields.VLAN_ID, M2Value.U8(30)),
            M2Field(InterfaceFields.VLAN_PARENT, M2Value.U8(3)),
        )
        val info = parseInterfaceRow(r) ?: throw AssertionError("null")
        assertEq(30, info.vlanId)
        assertEq(3L, info.vlanParentId)
    }

    test("parseInterfaceRow: traffic counters + rates") {
        val r = msg(
            M2Field(0xFE0001, M2Value.U32(3)),
            M2Field(0x10006, M2Value.Str("ether1")),
            M2Field(InterfaceFields.TX_BYTES, M2Value.U64(53_000_000_000u)),
            M2Field(InterfaceFields.RX_BYTES, M2Value.U64(2_700_000_000u)),
            M2Field(InterfaceFields.TX_RATE, M2Value.U64(12_500_000u)),
            M2Field(InterfaceFields.RX_RATE, M2Value.U64(1_250_000u)),
        )
        val info = parseInterfaceRow(r) ?: throw AssertionError("null")
        assertEq(53_000_000_000L, info.txBytes)
        assertEq(2_700_000_000L, info.rxBytes)
        assertEq(12_500_000L, info.txRateBps)
        assertEq(1_250_000L, info.rxRateBps)
    }

    test("parseInterfaceRow: tanpa stats -> traffic null") {
        val r = msg(
            M2Field(0xFE0001, M2Value.U32(3)),
            M2Field(0x10006, M2Value.Str("ether1")),
        )
        val info = parseInterfaceRow(r) ?: throw AssertionError("null")
        assertEq(null, info.txBytes)
        assertEq(null, info.rxBytes)
        assertEq(null, info.txRateBps)
        assertEq(null, info.rxRateBps)
    }

    test("parseBridgePortRow") {
        val r = msg(
            M2Field(0xFE0001, M2Value.U32(100)),
            M2Field(BridgePortFields.BRIDGE, M2Value.U8(10)),
            M2Field(BridgePortFields.INTERFACE, M2Value.U8(3)),
            M2Field(BridgePortFields.DISABLED, M2Value.Bool(false)),
        )
        val bp = parseBridgePortRow(r) ?: throw AssertionError("null")
        assertEq(10L, bp.bridgeId)
        assertEq(3L, bp.interfaceId)
        assertEq(false, bp.disabled)
    }

    test("parseDhcpClientRow") {
        val r = msg(
            M2Field(0xFE0001, M2Value.U32(7)),
            M2Field(DhcpClientFields.INTERFACE, M2Value.U8(10)),
            M2Field(DhcpClientFields.IFACE_NAME, M2Value.Str("ether10")),
            M2Field(DhcpClientFields.STATUS, M2Value.StrArray(listOf("Interface not active"))),
            M2Field(DhcpClientFields.DISABLED, M2Value.Bool(false)),
        )
        val dc = parseDhcpClientRow(r) ?: throw AssertionError("null")
        assertEq(10L, dc.interfaceId)
        assertEq("ether10", dc.interfaceName)
        assertEq(listOf("Interface not active"), dc.status)
    }

    test("parseLogRow: account info") {
        val r = msg(
            M2Field(m2Key(1, M2Ns.USER), M2Value.U32(1791876868)),
            M2Field(m2Key(3, M2Ns.USER), M2Value.Str("login ok")),
            M2Field(m2Key(4, M2Ns.USER), M2Value.U32Array(listOf(17, 1, 5))),
            M2Field(m2Key(5, M2Ns.USER), M2Value.Str("app=winbox duser=x outcome=success")),
        )
        val e = parseLogRow(r)
        assertEq(1791876868L, e.timeUnix)
        assertEq("login ok", e.message)
        assertEq(listOf(17L, 1L, 5L), e.topics)
        assertEq("app=winbox duser=x outcome=success", e.accountInfo)
    }

    test("cleanTerminalOutput: buang ANSI, echo, prompt") {
        // Simulasi output mentah dari router
        val raw = "\u001b[9999B\r\n[mUs3@Serper] > /system identity print\r\n" +
            "  name: Serper\r\n" +
            "[mUs3@Serper] > "
        val clean = WinboxSession("dummy", 0).cleanTerminalOutput(raw, "/system identity print")
        assertEq("name: Serper", clean)
    }

    test("cleanTerminalOutput: multi-baris") {
        val raw = "[u@h] > /system resource print\r\n" +
            "  uptime: 1d2h3m\r\n" +
            "  version: 6.49.19\r\n" +
            "[u@h] > "
        val clean = WinboxSession("dummy", 0).cleanTerminalOutput(raw, "/system resource print")
        assertEq("uptime: 1d2h3m\nversion: 6.49.19", clean)
    }

    test("cleanTerminalOutput: v7 per-karakter") {
        // v7 kirim tiap karakter di baris terpisah
        val raw = "[u@h] > /system identity print\r\n" +
            "  name: R\r\n        .\r\n        W\r\n        A\r\n        R\r\n        U\r\n" +
            "[u@h] > "
        val clean = WinboxSession("dummy", 0).cleanTerminalOutput(raw, "/system identity print")
        assertEq("name: R.WARU", clean)
    }

    println("\n=== $passed PASS, $failed FAIL ===")
    if (failed > 0) kotlin.system.exitProcess(1)
}