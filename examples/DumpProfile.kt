package tik.foundation

import tik.foundation.winbox.*

/** Dump [27,102] ke JSON (format sama dengan baseline). READ-ONLY. */
fun main(args: Array<String>) {
    val (host, portStr, user, pass, outPath) = args
    val sess = WinboxSession(host = host, port = portStr.toInt())
    try {
        sess.connect()
        sess.login(user, pass)
        val rows = sess.getAllRows(WinboxPaths.PPP_PROFILE, withStats = false)
        val json = buildString {
            append("[\n")
            rows.forEachIndexed { ri, row ->
                append("  {\"name\": \"${row.str(0x1) ?: "?"}\", \"fields\": [")
                append(row.fields.sortedBy { it.key }.joinToString(", ") { f ->
                    val v = when (val fv = f.value) {
                        is M2Value.Str -> "\"${fv.s.replace("\"", "'").take(80)}\""
                        is M2Value.U8 -> "${fv.v}"
                        is M2Value.U32 -> "${fv.v}"
                        is M2Value.U64 -> "${fv.v}"
                        is M2Value.Bool -> "${fv.v}"
                        is M2Value.U32Array -> "[${fv.vs.joinToString(",")}]"
                        is M2Value.MsgArray -> "\"<msgarray ${fv.vs.size}>\""
                        is M2Value.Raw -> "\"<raw ${fv.b.size}b>\""
                        else -> "\"<${fv.javaClass.simpleName}>\""
                    }
                    "{\"k\": ${f.key}, \"t\": \"${f.value.javaClass.simpleName}\", \"v\": $v}"
                })
                append("]}")
                if (ri < rows.size - 1) append(",")
                append("\n")
            }
            append("]\n")
        }
        java.io.File(outPath).writeText(json)
        println("Tersimpan: $outPath (${rows.size} profile)")
    } catch (e: Exception) {
        println("ERROR: ${e.message}")
    } finally {
        runCatching { sess.close() }
    }
}
