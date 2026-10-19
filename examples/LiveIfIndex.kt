package tik.foundation

import tik.foundation.winbox.*

/**
 * Tes 4 otomatis: index enum interface.
 * Add 192.0.2.99/24 ke ether cadangan, baca ulang, cek ref. Hapus setelahnya.
 */
fun main(args: Array<String>) {
    val (host, portStr, user, pass) = args
    val sess = WinboxSession(host = host, port = portStr.toInt())
    try {
        sess.connect()
        sess.login(user, pass)
        println("Login OK")

        // Interface yang sudah punya IP (ref numeric)
        val ipRows = sess.getAllRows(WinboxPaths.IP_ADDRESS)
        val usedRefs = ipRows.mapNotNull { it.uint(m2Key(2, M2Ns.USER))?.toInt() }.toSet()
        println("Ref sudah dipakai: $usedRefs")

        // Cari ether cadangan: nama ether*, rowId U8 kecil, belum dipakai
        val ifRows = sess.getAllRows(WinboxPaths.INTERFACE)
        var spareName: String? = null
        var spareId: Long? = null
        for (row in ifRows) {
            val name = row.str(0x10006) ?: continue
            if (!name.startsWith("ether")) continue
            val rid = when (val v = row.itemId()?.value) {
                is M2Value.U8 -> v.v.toLong()
                is M2Value.U32 -> v.v
                else -> null
            } ?: continue
            if (rid.toInt() !in usedRefs) {
                spareName = name; spareId = rid
                break
            }
        }
        if (spareName == null || spareId == null) {
            println("Tidak ada ether cadangan — SKIP")
            return
        }
        println("Pakai: $spareName (rowId=$spareId)")

        print("Add 192.0.2.99/24... ")
        val addResult = sess.addIpAddressResult(
            IpAddressInput(address = "192.0.2.99/24", interfaceIdx = spareId.toInt())
        )
        println(addResult)
        if (addResult !is WriteResult.Ok) return
        Thread.sleep(1000)

        val ipRows2 = sess.getAllRows(WinboxPaths.IP_ADDRESS)
        val testRow = ipRows2.firstOrNull {
            it.u32(m2Key(1, M2Ns.USER))?.let { v -> ipU32ToString(v) } == "192.0.2.99"
        }
        if (testRow == null) {
            println("IP uji tidak ketemu — GAGAL")
            return
        }
        val landed = testRow.uint(m2Key(2, M2Ns.USER))
        println("Mendarat di ref: $landed | target rowId: $spareId")
        if (landed == spareId) println("✅ COCOK — interface ref = rowId (itemId)")
        else println("❌ TIDAK COCOK — ref=$landed vs rowId=$spareId")

        testRow.itemId()?.let {
            print("Hapus IP uji... ")
            println(sess.removeIpAddressResult(it))
        }
    } catch (e: Exception) {
        println("ERROR: ${e.javaClass.simpleName}: ${e.message}")
    } finally {
        runCatching { sess.close() }
        println("Selesai. Kredensial tidak disimpan.")
    }
}
