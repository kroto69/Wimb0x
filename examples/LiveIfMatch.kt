package tik.foundation

import tik.foundation.winbox.*

/** Cari field interface yang nilainya = ref di tabel IP. */
fun main(args: Array<String>) {
    val (host, portStr, user, pass) = args
    val sess = WinboxSession(host = host, port = portStr.toInt())
    try {
        sess.connect()
        sess.login(user, pass)

        // Ambil satu IP dan ref-nya
        val ipRows = sess.getAllRows(WinboxPaths.IP_ADDRESS)
        val sample = ipRows.firstOrNull()
        val targetRef = sample?.uint(m2Key(2, M2Ns.USER))
        val sampleIp = sample?.u32(m2Key(1, M2Ns.USER))?.let { ipU32ToString(it) }
        println("Sample: $sampleIp -> ref=$targetRef")

        // Cari di semua interface, field mana yang = targetRef
        val ifRows = sess.getAllRows(WinboxPaths.INTERFACE)
        println("\nCari field = $targetRef di ${ifRows.size} interface...")
        for (row in ifRows) {
            for (f in row.fields) {
                val v = when (val fv = f.value) {
                    is M2Value.U8 -> fv.v.toLong()
                    is M2Value.U32 -> fv.v
                    is M2Value.U64 -> fv.v.toLong()
                    else -> null
                }
                if (v == targetRef) {
                    println("KETEMU di ${row.str(0x10006)}: key 0x${f.key.toString(16).uppercase()} = $v")
                }
            }
        }
        println("Selesai mencari.")
    } catch (e: Exception) {
        println("ERROR: ${e.message}")
    } finally {
        runCatching { sess.close() }
    }
}
