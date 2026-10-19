package tik.foundation

import tik.foundation.winbox.*

/** Bandingkan interface ref di IP address dengan rowId interface. */
fun main(args: Array<String>) {
    val (host, portStr, user, pass) = args
    val sess = WinboxSession(host = host, port = portStr.toInt())
    try {
        sess.connect()
        sess.login(user, pass)

        // Map rowId -> nama interface
        val ifRows = sess.getAllRows(WinboxPaths.INTERFACE)
        val idToName = mutableMapOf<Long, String>()
        for (row in ifRows) {
            val rid = when (val v = row.itemId()?.value) {
                is M2Value.U8 -> v.v.toLong()
                is M2Value.U32 -> v.v
                else -> null
            } ?: continue
            idToName[rid] = row.str(0x10006) ?: "?"
        }

        // IP addresses: tampilkan IP -> ref -> nama (via rowId)
        val ipRows = sess.getAllRows(WinboxPaths.IP_ADDRESS)
        println("=== IP Address -> ref -> nama interface ===")
        for (row in ipRows.take(15)) {
            val ip = row.u32(m2Key(1, M2Ns.USER))?.let { ipU32ToString(it) } ?: "?"
            val ref = row.uint(m2Key(2, M2Ns.USER))
            val name = ref?.let { idToName[it] } ?: "(tidak ketemu)"
            println("  $ip -> ref=$ref -> $name")
        }
    } catch (e: Exception) {
        println("ERROR: ${e.message}")
    } finally {
        runCatching { sess.close() }
    }
}
