package tik.foundation

import tik.foundation.winbox.*

/** Cek tipe wire field 0xA di tabel IP (u8 vs u32). READ-ONLY. */
fun main(args: Array<String>) {
    val (host, portStr, user, pass) = args
    val sess = WinboxSession(host = host, port = portStr.toInt())
    try {
        sess.connect()
        sess.login(user, pass)
        val ipRows = sess.getAllRows(WinboxPaths.IP_ADDRESS, withStats = false)
        val types = mutableMapOf<String, Int>()
        var small = 0
        var large = 0
        for (row in ipRows) {
            val f = row.first(0xA) ?: continue
            val t = f.value.javaClass.simpleName
            types[t] = (types[t] ?: 0) + 1
            val v = row.uint(0xA) ?: continue
            if (v <= 255) small++ else large++
        }
        println("Tipe wire 0xA: $types")
        println("Nilai <=255: $small, >255: $large (dari ${ipRows.size} baris)")
    } catch (e: Exception) {
        println("ERROR: ${e.message}")
    } finally {
        runCatching { sess.close() }
    }
}
