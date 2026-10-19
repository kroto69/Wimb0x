import tik.foundation.winbox.*

// Dump baris interface SFP dari [20,0] di v7 — cari field DDM SFP.
fun main(args: Array<String>) {
    val (host, port) = args[0].split(":").let { it[0] to it[1].toInt() }
    val sess = WinboxSession(host, port, connectTimeoutMs = 8000)
    sess.connect()
    sess.login(args[1], args[2])
    try {
        val rows = sess.getAllRows(listOf(20, 0))
        println("Total rows: ${rows.size}")
        for (r in rows) {
            val name = r.str(0x10006) ?: continue
            if (!name.contains("sfp", ignoreCase = true)) continue
            println("=== SFP: $name ===")
            for (f in r.fields.sortedBy { it.key }) {
                val v = when (val x = f.value) {
                    is M2Value.Str -> "Str(\"${x.s}\")"
                    is M2Value.U8 -> "U8(${x.v})"
                    is M2Value.U32 -> "U32(${x.v})"
                    is M2Value.Bool -> "Bool(${x.v})"
                    is M2Value.Raw -> "Raw(${x.b.size}B: ${x.b.take(8).joinToString("") { "%02X".format(it) }}...)"
                    is M2Value.U32Array -> "U32Array(${x.vs})"
                    is M2Value.StrArray -> "StrArray(${x.vs})"
                    else -> x.toString()
                }
                println("  0x${f.key.toString(16).uppercase().padStart(5, '0')} = $v")
            }
        }
    } finally {
        sess.close()
    }
}
