package tik.foundation

import tik.foundation.winbox.*

/**
 * Korelasi enum interface (IpAddrFields.INTERFACE 0xA, u8 enm) dengan
 * key numerik di baris interface.
 *
 * READ-ONLY: tidak menulis ke router.
 *
 * Untuk tiap baris IP: ambil nilai 0xA.
 * Untuk tiap baris interface: cetak semua key u8/u32/u64 + nilai.
 * Tandai key interface yang nilainya == 0xA baris IP (nama interface
 * ditampilkan sebagai petunjuk, tanpa mengira-ngira).
 */
fun main(args: Array<String>) {
    val (host, portStr, user, pass) = args
    val sess = WinboxSession(host = host, port = portStr.toInt())
    try {
        sess.connect()
        sess.login(user, pass)

        val ifRows = sess.getAllRows(WinboxPaths.INTERFACE, withStats = false)
        val ipRows = sess.getAllRows(WinboxPaths.IP_ADDRESS, withStats = false)

        println("=== INTERFACE ROWS (${ifRows.size}) — key numerik ===")
        // Kumpulkan semua key numerik yang muncul di baris interface
        val numKeys = sortedSetOf<Int>()
        for (row in ifRows) {
            for (f in row.fields) {
                when (f.value) {
                    is M2Value.U8, is M2Value.U32, is M2Value.U64 -> numKeys.add(f.key)
                    else -> {}
                }
            }
        }
        println("key numerik di interface: ${numKeys.map { "0x${it.toString(16).uppercase()}" }}")
        for (row in ifRows) {
            val name = row.str(0x10006) ?: "?"
            val itemId = row.u32(0xFE0001) ?: -1L
            val kv = numKeys.mapNotNull { k ->
                val v: String? = when (val fv = row.first(k)?.value) {
                    is M2Value.U8 -> fv.v.toString()
                    is M2Value.U32 -> fv.v.toString()
                    is M2Value.U64 -> fv.v.toString()
                    else -> null
                }
                v?.let { "0x${k.toString(16).uppercase()}=$it" }
            }
            println("  [$name] itemId=$itemId :: ${kv.joinToString(" ")}")
        }

        println()
        println("=== IP ROWS (${ipRows.size}) — korelasi 0xA ===")
        // Agregasi: key -> jumlah baris IP yang cocok
        val matchCount = mutableMapOf<Int, Int>()
        val matchDetail = mutableMapOf<Int, MutableList<String>>()

        for (row in ipRows) {
            val addr = row.str(0x10006) ?: row.str(0x10005) ?: "?"
            val enumVal = row.uint(0xA)
            if (enumVal == null) {
                println("  [$addr] 0xA = <tidak ada>")
                continue
            }
            val hits = mutableListOf<String>()
            for (ifRow in ifRows) {
                val ifName = ifRow.str(0x10006) ?: "?"
                for (k in numKeys) {
                    val iv: Long? = when (val fv = ifRow.first(k)?.value) {
                        is M2Value.U8 -> fv.v.toLong()
                        is M2Value.U32 -> fv.v
                        is M2Value.U64 -> if (fv.v <= Long.MAX_VALUE.toULong()) fv.v.toLong() else null
                        else -> null
                    }
                    if (iv == enumVal) {
                        hits.add("0x${k.toString(16).uppercase()} @ $ifName")
                        matchCount[k] = (matchCount[k] ?: 0) + 1
                        matchDetail.getOrPut(k) { mutableListOf() }
                            .add("$addr -> $ifName")
                    }
                }
            }
            println("  [$addr] 0xA=$enumVal :: ${if (hits.isEmpty()) "<tidak ada key interface yang cocok>" else hits.joinToString(" | ")}")
        }

        println()
        println("=== AGREGASI KANDIDAT (key -> #baris IP cocok) ===")
        val sorted = matchCount.entries.sortedByDescending { it.value }
        for ((k, c) in sorted) {
            val mark = if (c >= 3) "  <-- KANDIDAT (>=3)" else ""
            println("  0x${k.toString(16).uppercase()} : $c cocok$mark")
        }
        for ((k, c) in sorted) {
            if (c >= 3) {
                println()
                println("  Detail 0x${k.toString(16).uppercase()}:")
                matchDetail[k]?.forEach { println("    $it") }
            }
        }
    } catch (e: Exception) {
        println("ERROR: ${e.message}")
    } finally {
        runCatching { sess.close() }
    }
}
