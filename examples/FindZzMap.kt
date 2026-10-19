package tik.foundation

import tik.foundation.winbox.*

/** Dump [27,102] PPP Profile, cari "zz-map". READ-ONLY. */
fun main(args: Array<String>) {
    val (host, portStr, user, pass) = args
    val sess = WinboxSession(host = host, port = portStr.toInt())
    try {
        sess.connect()
        sess.login(user, pass)
        println("Login OK — ${sess.routerVersion()}")
        val rows = sess.getAllRows(WinboxPaths.PPP_PROFILE, withStats = false)
        println("Jumlah profile: ${rows.size}")
        var found = false
        for (row in rows) {
            // Nama profile: coba beberapa key umum
            val name = row.str(0x1) ?: row.str(0xFE0009) ?: "?"
            if (name == "zz-map") {
                found = true
                println("\n=== KETEMU zz-map ===")
                for (f in row.fields.sortedBy { it.key }) {
                    val vstr = when (val v = f.value) {
                        is M2Value.Str -> "\"${v.s.take(60)}\""
                        is M2Value.U8 -> "u8:${v.v}"
                        is M2Value.U32 -> "u32:${v.v}"
                        is M2Value.U64 -> "u64:${v.v}"
                        is M2Value.Bool -> "bool:${v.v}"
                        is M2Value.Raw -> "<raw ${v.b.size}b>"
                        is M2Value.U32Array -> "u32array:[${v.vs.joinToString(",")}]"
                        is M2Value.MsgArray -> "msgarray(${v.vs.size})"
                        else -> "<${v.javaClass.simpleName}>"
                    }
                    println("  0x${f.key.toString(16).uppercase().padStart(5, '0')} = $vstr")
                }
            }
        }
        if (!found) {
            println("\nzz-map TIDAK DITEMUKAN. Daftar nama profile:")
            for (row in rows) {
                val name = row.str(0x1) ?: row.str(0xFE0009) ?: "?"
                if (name.startsWith("zz-")) println("  - $name")
            }
        }
    } catch (e: Exception) {
        println("ERROR: ${e.message}")
    } finally {
        runCatching { sess.close() }
    }
}
