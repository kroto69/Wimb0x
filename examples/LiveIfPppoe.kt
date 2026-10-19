package tik.foundation

import tik.foundation.winbox.*

/** Dump field interface PPPoE untuk verifikasi key byte counter. */
fun main(args: Array<String>) {
    val (host, portStr, user, pass) = args
    val sess = WinboxSession(host = host, port = portStr.toInt())
    try {
        sess.connect()
        sess.login(user, pass)

        // Ambil dengan stats (counter)
        val rows = sess.getAllRows(WinboxPaths.INTERFACE, withStats = true)
        println("Total interface: ${rows.size}")

        // Cari satu PPPoE interface
        val pppoe = rows.firstOrNull { (it.str(0x10006) ?: "").startsWith("<pppoe-") }
        if (pppoe == null) {
            println("Tidak ada interface PPPoE")
            return
        }
        println("\n=== ${pppoe.str(0x10006)} ===")
        for (f in pppoe.fields.sortedBy { it.key }) {
            // Hanya tampilkan yang numerik besar (kandidat counter)
            val vstr = when (val v = f.value) {
                is M2Value.U64 -> if (v.v > 0u) v.v.toString() else null
                is M2Value.U32 -> if (v.v > 0) v.v.toString() else null
                else -> null
            }
            if (vstr != null) {
                println("  0x${f.key.toString(16).uppercase().padStart(5, '0')} = $vstr")
            }
        }

        // Bandingkan dengan ether1 (fisik)
        val ether1 = rows.firstOrNull { it.str(0x10006) == "ether1" }
        if (ether1 != null) {
            println("\n=== ether1 (pembanding) ===")
            for (f in ether1.fields.sortedBy { it.key }) {
                val vstr = when (val v = f.value) {
                    is M2Value.U64 -> if (v.v > 0u) v.v.toString() else null
                    is M2Value.U32 -> if (v.v > 1000) v.v.toString() else null
                    else -> null
                }
                if (vstr != null) {
                    println("  0x${f.key.toString(16).uppercase().padStart(5, '0')} = $vstr")
                }
            }
        }
    } catch (e: Exception) {
        println("ERROR: ${e.message}")
    } finally {
        runCatching { sess.close() }
    }
}
