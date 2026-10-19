import tik.foundation.winbox.*

// Dump detail path [20,1] s/d [20,5] — cari data SFP/monitor.
fun main(args: Array<String>) {
    val (host, port) = args[0].split(":").let { it[0] to it[1].toInt() }
    val sess = WinboxSession(host, port, connectTimeoutMs = 8000)
    sess.connect()
    sess.login(args[1], args[2])
    try {
        for (p in 1..5) {
            val path = listOf(20, p)
            println("\n===== Path $path =====")
            try {
                val rows = sess.getAllRows(path)
                for ((i, r) in rows.withIndex()) {
                    println("-- row $i --")
                    for (f in r.fields.sortedBy { it.key }.take(15)) {
                        val v = when (val x = f.value) {
                            is M2Value.Str -> "\"${x.s.take(30)}\""
                            is M2Value.U8 -> "${x.v}"
                            is M2Value.U32 -> "${x.v}"
                            is M2Value.Bool -> "${x.v}"
                            else -> "..."
                        }
                        println("  0x${f.key.toString(16).uppercase().padStart(5,'0')}=$v")
                    }
                    if (i >= 1) { println("  ..."); break }
                }
            } catch (e: Exception) {
                println("ERROR: ${e.message?.take(80)}")
            }
        }
    } finally {
        sess.close()
    }
}
