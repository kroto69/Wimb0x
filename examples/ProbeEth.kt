import tik.foundation.winbox.*

// Probe path handler untuk data monitor ethernet/SFP.
fun main(args: Array<String>) {
    val (host, port) = args[0].split(":").let { it[0] to it[1].toInt() }
    val sess = WinboxSession(host, port, connectTimeoutMs = 8000)
    sess.connect()
    sess.login(args[1], args[2])
    try {
        // Kandidat path untuk ethernet monitor
        val candidates = listOf(
            listOf(20, 0),   // interface list (sudah tahu)
            listOf(20, 1),   // ?
            listOf(20, 2),   // ?
            listOf(20, 3),   // ?
            listOf(20, 4),   // ?
            listOf(20, 5),   // ?
        )
        for (path in candidates) {
            try {
                val rows = sess.getAllRows(path)
                println("Path $path: ${rows.size} rows")
                // cek apakah ada field sfp
                for (r in rows.take(2)) {
                    val sfpKeys = r.fields.filter { it.key in 0x400..0x500 }
                    if (sfpKeys.isNotEmpty()) {
                        println("  SFP-ish keys: ${sfpKeys.map { "0x${it.key.toString(16)}" }}")
                    }
                }
            } catch (e: Exception) {
                println("Path $path: ERROR ${e.message?.take(60)}")
            }
        }
    } finally {
        sess.close()
    }
}
