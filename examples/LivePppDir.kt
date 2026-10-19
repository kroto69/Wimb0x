package tik.foundation

import tik.foundation.winbox.*

/** Tes 1 lanjutan: cari sesi dengan traffic, dump 2x untuk arah 0x9/0xA. */
fun main(args: Array<String>) {
    val (host, portStr, user, pass) = args
    val sess = WinboxSession(host = host, port = portStr.toInt())
    try {
        sess.connect()
        sess.login(user, pass)
        println("Login OK")

        // Cari sesi dengan bytes terbesar (paling aktif)
        val active = sess.getPppActive()
        println("Total sesi: ${active.size}")
        val top = active.sortedByDescending { it.bytesA + it.bytesB }.take(3)
        for (s in top) {
            println("  ${s.name}: A=${s.bytesA} B=${s.bytesB}")
        }

        val target = top.firstOrNull { it.bytesA + it.bytesB > 0 }
        if (target == null) {
            println("Tidak ada sesi dengan traffic — SKIP")
            return
        }

        println("\nPantau '${target.name}' selama 10 detik...")
        val a1 = target.bytesA; val b1 = target.bytesB
        Thread.sleep(10000)
        val after = sess.getPppActive().firstOrNull { it.name == target.name }
        if (after != null) {
            val dA = after.bytesA - a1
            val dB = after.bytesB - b1
            println("Delta 10 detik: 0x9=+$dA 0xA=+$dB")
            println()
            println("INTERPRETASI:")
            println("  Download klien = traffic dari router ke klien.")
            println("  Jika klien sedang download dan 0xA naik pesat -> 0xA = download klien.")
            println("  Jika 0x9 naik pesat -> 0x9 = download klien.")
        }
    } catch (e: Exception) {
        println("ERROR: ${e.message}")
    } finally {
        runCatching { sess.close() }
    }
}
