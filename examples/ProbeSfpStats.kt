import tik.foundation.winbox.*

// Bandingkan row SFP tanpa vs dengan stats — cari field DDM live.
fun main(args: Array<String>) {
    val (host, port) = args[0].split(":").let { it[0] to it[1].toInt() }
    val sess = WinboxSession(host, port, connectTimeoutMs = 8000)
    sess.connect()
    sess.login(args[1], args[2])
    try {
        for (withStats in listOf(false, true)) {
            println("\n===== withStats=$withStats =====")
            val rows = sess.getAllRows(listOf(20, 0), withStats)
            val sfp = rows.firstOrNull { it.str(0x10006)?.contains("sfp", true) == true }
            if (sfp == null) { println("SFP tidak ketemu"); continue }
            println("Jumlah field: ${sfp.fields.size}")
            // cari field yang tidak ada di dump sebelumnya atau yang nilainya berubah-ubah
            for (f in sfp.fields.sortedBy { it.key }) {
                val keyHex = "0x${f.key.toString(16).uppercase().padStart(5,'0')}"
                // fokus ke 0x400-0x4FF (ethernet/SFP area)
                if (f.key in 0x400..0x4FF) {
                    val v = when (val x = f.value) {
                        is M2Value.Str -> "\"${x.s.take(30)}\""
                        is M2Value.U8 -> "${x.v}"
                        is M2Value.U32 -> "${x.v}"
                        is M2Value.Bool -> "${x.v}"
                        is M2Value.Raw -> "Raw(${x.b.size}B)"
                        is M2Value.U32Array -> "${x.vs}"
                        else -> "..."
                    }
                    println("  $keyHex = $v")
                }
            }
        }
    } finally {
        sess.close()
    }
}
