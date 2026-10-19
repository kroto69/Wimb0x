package tik.foundation

import tik.foundation.winbox.*

/** Dump [27,103] 2x selisih 5 detik, lapor key yang berubah. */
fun main(args: Array<String>) {
    val (host, portStr, user, pass) = args
    val sess = WinboxSession(host = host, port = portStr.toInt())
    try {
        sess.connect()
        sess.login(user, pass)

        fun snapshot(): Map<String, Map<Int, Long>> {
            val rows = sess.getAllRows(WinboxPaths.PPP_ACTIVE)
            return rows.mapNotNull { row ->
                val name = row.str(0x1) ?: return@mapNotNull null
                val nums = mutableMapOf<Int, Long>()
                for (f in row.fields) {
                    val v = when (val fv = f.value) {
                        is M2Value.U8 -> fv.v.toLong()
                        is M2Value.U32 -> fv.v
                        is M2Value.U64 -> fv.v.toLong()
                        else -> null
                    }
                    if (v != null) nums[f.key] = v
                }
                name to nums
            }.toMap()
        }

        val s1 = snapshot()
        println("Snapshot 1: ${s1.size} sesi. Tunggu 5 detik...")
        Thread.sleep(5000)
        val s2 = snapshot()

        println("\n=== Key yang BERUBAH ===")
        var found = false
        for ((name, nums1) in s1) {
            val nums2 = s2[name] ?: continue
            for ((key, v1) in nums1) {
                val v2 = nums2[key] ?: continue
                if (v2 != v1) {
                    found = true
                    println("$name: 0x${key.toString(16).uppercase()} $v1 -> $v2 (delta +${v2 - v1})")
                }
            }
        }
        if (!found) println("(tidak ada yang berubah — semua sesi idle)")
    } catch (e: Exception) {
        println("ERROR: ${e.message}")
    } finally {
        runCatching { sess.close() }
    }
}
