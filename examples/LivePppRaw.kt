package tik.foundation

import tik.foundation.winbox.*

/** Dump raw field satu baris [27,103] untuk verifikasi key byte counter. */
fun main(args: Array<String>) {
    val (host, portStr, user, pass) = args
    val sess = WinboxSession(host = host, port = portStr.toInt())
    try {
        sess.connect()
        sess.login(user, pass)
        val rows = sess.getAllRows(WinboxPaths.PPP_ACTIVE)
        println("Total baris: ${rows.size}")
        val row = rows.firstOrNull() ?: return
        println("=== Field baris pertama ===")
        for (f in row.fields.sortedBy { it.key }) {
            val vstr = when (val v = f.value) {
                is M2Value.Str -> "\"${v.s.take(30)}\""
                is M2Value.U8 -> v.v.toString()
                is M2Value.U32 -> v.v.toString()
                is M2Value.U64 -> v.v.toString()
                is M2Value.Bool -> v.v.toString()
                is M2Value.Raw -> "<raw ${v.b.size}b>"
                else -> "<${v.javaClass.simpleName}>"
            }
            println("  0x${f.key.toString(16).uppercase().padStart(4, '0')} = $vstr")
        }
    } catch (e: Exception) {
        println("ERROR: ${e.message}")
    } finally {
        runCatching { sess.close() }
    }
}
