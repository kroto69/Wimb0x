import tik.foundation.winbox.*

// Scan path [20,6] s/d [20,30] — cari tabel ethernet/SFP.
fun main(args: Array<String>) {
    val (host, port) = args[0].split(":").let { it[0] to it[1].toInt() }
    val sess = WinboxSession(host, port, connectTimeoutMs = 8000)
    sess.connect()
    sess.login(args[1], args[2])
    try {
        for (p in 6..30) {
            val path = listOf(20, p)
            try {
                val rows = sess.getAllRows(path)
                if (rows.isEmpty()) {
                    println("[$path]: 0 rows")
                    continue
                }
                // tampilkan field pertama dari row pertama
                val r0 = rows[0]
                val sample = r0.fields.sortedBy { it.key }.take(8).joinToString(", ") { f ->
                    val v = when (val x = f.value) {
                        is M2Value.Str -> "\"${x.s.take(20)}\""
                        else -> x.toString().take(20)
                    }
                    "0x${f.key.toString(16)}=$v"
                }
                println("[$path]: ${rows.size} rows | $sample")
            } catch (e: Exception) {
                println("[$path]: ERR ${e.message?.take(40)}")
            }
        }
    } finally {
        sess.close()
    }
}
