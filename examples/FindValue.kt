package tik.foundation

import tik.foundation.winbox.*

/**
 * TAHAP A: dump [27,102] -> JSON + cari sentinel.
 * Sentinel: 7000000/9000000, "7M"/"9M", DNS u32, only-one.
 * READ-ONLY.
 */
fun main(args: Array<String>) {
    val (host, portStr, user, pass) = args
    val sess = WinboxSession(host = host, port = portStr.toInt())
    try {
        sess.connect()
        sess.login(user, pass)
        val rows = sess.getAllRows(WinboxPaths.PPP_PROFILE, withStats = false)

        // 1. Simpan JSON (password tidak ada di tabel ini; mask string panjang misterius)
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
        java.io.File("/tmp/ppp_profile_v6.json").writeText(json)
        println("JSON tersimpan: /tmp/ppp_profile_v6.json (${rows.size} profile)")

        // 2. Cari sentinel di zz-map
        val zz = rows.firstOrNull { (it.str(0x1) ?: "") == "zz-map" }
            ?: run { println("zz-map tidak ada"); return }
        val other = rows.firstOrNull { (it.str(0x1) ?: "") == "default" }

        println("\n=== SENTINEL di zz-map ===")
        for (f in zz.fields.sortedBy { it.key }) {
            val fv = f.value
            val hit = mutableListOf<String>()
            // 7000000/9000000 sebagai angka
            val numVal: Long? = when (fv) {
                is M2Value.U8 -> fv.v.toLong()
                is M2Value.U32 -> fv.v
                is M2Value.U64 -> if (fv.v <= Long.MAX_VALUE.toULong()) fv.v.toLong() else null
                else -> null
            }
            if (numVal == 7000000L) hit.add("==7000000")
            if (numVal == 9000000L) hit.add("==9000000")
            if (numVal == 151587082L) hit.add("==10.9.9.9")
            if (numVal == 134744074L) hit.add("==10.8.8.8")
            // string mengandung sentinel
            if (fv is M2Value.Str) {
                val s = fv.s
                if ("7M" in s || "9M" in s) hit.add("str rate")
                if ("7000000" in s || "9000000" in s) hit.add("str angka rate")
            }
            // u32array mengandung DNS
            if (fv is M2Value.U32Array) {
                if (151587082L in fv.vs) hit.add("arr 10.9.9.9")
                if (134744074L in fv.vs) hit.add("arr 10.8.8.8")
            }
            if (hit.isNotEmpty()) {
                println("  0x${f.key.toString(16).uppercase()} [${fv.javaClass.simpleName}] :: ${hit.joinToString(", ")}")
            }
        }

        // 3. Bandingkan kandidat only-one vs default
        println("\n=== BANDING zz-map vs default (kandidat only-one) ===")
        for (k in listOf(0x19, 0x1E, 0x79, 0x7A, 0x2, 0x3, 0x7, 0xA)) {
            val zv = zz.first(k)?.value?.let { v2s(it) } ?: "-"
            val dv = other?.first(k)?.value?.let { v2s(it) } ?: "-"
            val mark = if (zv != dv) "  <-- BEDA" else ""
            println("  0x${k.toString(16).uppercase()}: zz-map=$zv vs default=$dv$mark")
        }
    } catch (e: Exception) {
        println("ERROR: ${e.message}")
    } finally {
        runCatching { sess.close() }
    }
}

private fun v2s(v: M2Value): String = when (v) {
    is M2Value.Str -> "\"${v.s.take(30)}\""
    is M2Value.U8 -> "u8:${v.v}"
    is M2Value.U32 -> "u32:${v.v}"
    is M2Value.U64 -> "u64:${v.v}"
    is M2Value.Bool -> "bool:${v.v}"
    is M2Value.U32Array -> "arr:[${v.vs.joinToString(",")}]"
    else -> v.javaClass.simpleName
}
