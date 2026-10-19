package tik.foundation

import tik.foundation.winbox.*

/**
 * TAHAP D LIVE: add -> baca -> verifiedSet -> baca -> remove.
 * HANYA profile "zz-live-test". READ hati-hati, WRITE hanya ke zz-*.
 */
fun main(args: Array<String>) {
    val (host, portStr, user, pass) = args
    val sess = WinboxSession(host = host, port = portStr.toInt())
    val tname = "zz-live-test"
    try {
        sess.connect()
        sess.login(user, pass)
        println("Login OK")

        // 1. ADD
        print("1. addPppProfileResult... ")
        val addR = sess.addPppProfileResult(PppProfileInput(
            name = tname,
            rateUp = "7M", rateDown = "9M",
            dnsServers = listOf("10.9.9.9", "10.8.8.8"),
            onlyOne = OnlyOne.YES,
        ))
        println(addR)
        if (addR !is WriteResult.Ok) { println("ADD gagal — stop"); return }
        Thread.sleep(800)

        // 2. BACA ULANG
        print("2. baca ulang... ")
        var p = sess.getPppProfiles().firstOrNull { it.name == tname }
        if (p == null) { println("TIDAK KETEMU — stop"); return }
        println("OK rateLimit=${p.rateLimit} up=${p.rateUpBps} down=${p.rateDownBps} dns=${p.dnsServers} onlyOne=${p.onlyOne}")
        val okAdd = p.rateLimit == "7M/9M" && p.rateUpBps == 7000000L && p.rateDownBps == 9000000L &&
            p.dnsServers == listOf("10.9.9.9", "10.8.8.8") && p.onlyOne == OnlyOne.YES
        println("   verifikasi ADD: ${if (okAdd) "OK" else "MISMATCH"}")

        // 3. VERIFIED SET
        print("3. verifiedSet (rate 5M/6M, dns 1.1.1.1, only-one NO)... ")
        val setR = sess.setPppProfileResult(p.rowId, PppProfileInput(
            rateUp = "5M", rateDown = "6M",
            dnsServers = listOf("1.1.1.1"),
            onlyOne = OnlyOne.NO,
        ))
        println(setR)
        Thread.sleep(800)

        // 4. BACA ULANG
        print("4. baca ulang... ")
        p = sess.getPppProfiles().firstOrNull { it.name == tname }
        if (p == null) { println("TIDAK KETEMU — stop"); return }
        println("OK rateLimit=${p.rateLimit} up=${p.rateUpBps} down=${p.rateDownBps} dns=${p.dnsServers} onlyOne=${p.onlyOne}")
        val okSet = p.rateLimit == "5M/6M" && p.rateUpBps == 5000000L && p.rateDownBps == 6000000L &&
            p.dnsServers == listOf("1.1.1.1") && p.onlyOne == OnlyOne.NO
        println("   verifikasi SET: ${if (okSet) "OK" else "MISMATCH"}")

        // 5. REMOVE
        print("5. remove... ")
        val delR = sess.removePppProfileResult(p.rowId)
        println(delR)
        Thread.sleep(500)
        val gone = sess.getPppProfiles().none { it.name == tname }
        println("   profile hilang: ${if (gone) "OK" else "MASIH ADA"}")

        println("\n=== HASIL: ${if (okAdd && okSet && gone) "SEMUA OK ✅" else "ADA MISMATCH 🟡"} ===")
    } catch (e: Exception) {
        println("ERROR: ${e.message}")
    } finally {
        runCatching { sess.close() }
    }
}
