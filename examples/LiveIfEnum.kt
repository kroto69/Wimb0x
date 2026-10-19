package tik.foundation

import tik.foundation.winbox.*

/** Cari interface dengan rowId 131264, dan dump enum interface. */
fun main(args: Array<String>) {
    val (host, portStr, user, pass) = args
    val sess = WinboxSession(host = host, port = portStr.toInt())
    try {
        sess.connect()
        sess.login(user, pass)

        val rows = sess.getAllRows(WinboxPaths.INTERFACE)
        println("Total: ${rows.size} interface")
        println("\n=== Cari rowId 131264 ===")
        for (row in rows) {
            val rid = when (val v = row.itemId()?.value) {
                is M2Value.U8 -> v.v.toLong()
                is M2Value.U32 -> v.v
                else -> null
            }
            if (rid == 131264L) {
                println("KETEMU: ${row.str(0x10006)} (rowId=$rid)")
            }
        }

        println("\n=== 10 interface pertama (nama -> rowId) ===")
        rows.take(10).forEach { row ->
            val name = row.str(0x10006)
            val rid = when (val v = row.itemId()?.value) {
                is M2Value.U8 -> v.v.toString()
                is M2Value.U32 -> v.v.toString()
                else -> "?"
            }
            println("  $name -> $rid")
        }

        // Cek getInterfaceOptions (enum)
        println("\n=== getInterfaceOptions ===")
        try {
            val opts = sess.getInterfaceOptions()
            opts.take(10).forEach { println("  ${it.name} -> index=${it.index}") }
            val match = opts.firstOrNull { it.index == 131264 }
            println("Index 131264 = ${match?.name ?: "(tidak ketemu)"}")
        } catch (e: Exception) {
            println("getInterfaceOptions error: ${e.message}")
        }
    } catch (e: Exception) {
        println("ERROR: ${e.message}")
    } finally {
        runCatching { sess.close() }
    }
}
