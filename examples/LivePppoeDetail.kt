package tik.foundation

import tik.foundation.winbox.*

/** Dump lengkap satu interface PPPoE untuk identifikasi uptime/address. */
fun main(args: Array<String>) {
    val (host, portStr, user, pass) = args
    val sess = WinboxSession(host = host, port = portStr.toInt())
    try {
        sess.connect()
        sess.login(user, pass)

        val rows = sess.getAllRows(WinboxPaths.INTERFACE, withStats = true)
        val pppoe = rows.firstOrNull { (it.str(0x10006) ?: "").startsWith("<pppoe-") }
            ?: run { println("Tidak ada PPPoE"); return }

        println("=== ${pppoe.str(0x10006)} — SEMUA FIELD ===")
        for (f in pppoe.fields.sortedBy { it.key }) {
            val vstr = when (val v = f.value) {
                is M2Value.Str -> "\"${v.s.take(40)}\""
                is M2Value.U8 -> "u8:${v.v}"
                is M2Value.U32 -> "u32:${v.v}"
                is M2Value.U64 -> "u64:${v.v}"
                is M2Value.Bool -> "bool:${v.v}"
                is M2Value.Raw -> "<raw ${v.b.size}b>"
                else -> "<${v.javaClass.simpleName}>"
            }
            println("  0x${f.key.toString(16).uppercase().padStart(5, '0')} = $vstr")
        }

        // Coba interpretasi 0xB0009/0xB000A sebagai IP
        val b9 = pppoe.u32(0xB0009)
        val bA = pppoe.u32(0xB000A)
        println("\n0xB0009 sebagai IP: ${b9?.let { ipU32ToString(it) }}")
        println("0xB000A sebagai IP: ${bA?.let { ipU32ToString(it) }}")
    } catch (e: Exception) {
        println("ERROR: ${e.message}")
    } finally {
        runCatching { sess.close() }
    }
}
