package examples

import java.io.File

/**
 * Bandingkan dua file JSON hasil DumpTable.kt — 🟡.
 *
 * Usage: DiffDumpKt <before.json> <after.json>
 *
 * Cetak key yang berubah/muncul/hilang per baris (cocokkan via rowId).
 * Tujuan: user ubah SATU nilai di WinBox resmi → dump → diff → key ketemu.
 */
fun main(args: Array<String>) {
    if (args.size < 2) {
        println("Usage: DiffDumpKt <before.json> <after.json>")
        return
    }
    val before = parseDump(File(args[0]).readText())
    val after = parseDump(File(args[1]).readText())

    println("=== Diff: ${args[0]} → ${args[1]} ===")
    println("Baris: ${before.size} → ${after.size}")

    val beforeById = before.associateBy { it.rowId }
    val afterById = after.associateBy { it.rowId }

    // Baris hilang
    (beforeById.keys - afterById.keys).forEach { id ->
        println("\n[BARIS HILANG] rowId=$id")
    }
    // Baris baru
    (afterById.keys - beforeById.keys).forEach { id ->
        println("\n[BARIS BARU] rowId=$id")
        afterById[id]?.fields?.forEach { (k, v) ->
            println("  + $k = $v")
        }
    }
    // Baris berubah
    (beforeById.keys intersect afterById.keys).forEach { id ->
        val b = beforeById[id]!!
        val a = afterById[id]!!
        val bMap = b.fields.toMap()
        val aMap = a.fields.toMap()
        val changed = mutableListOf<String>()
        // Berubah
        (bMap.keys intersect aMap.keys).forEach { k ->
            if (bMap[k] != aMap[k]) {
                changed.add("  ~ $k: ${bMap[k]} → ${aMap[k]}")
            }
        }
        // Muncul
        (aMap.keys - bMap.keys).forEach { k ->
            changed.add("  + $k = ${aMap[k]} (baru muncul)")
        }
        // Hilang
        (bMap.keys - aMap.keys).forEach { k ->
            changed.add("  - $k (hilang, dulu=${bMap[k]})")
        }
        if (changed.isNotEmpty()) {
            println("\n[BERUBAH] rowId=$id (index ${b.index})")
            changed.forEach { println(it) }
        }
    }
    println("\n=== Selesai ===")
}

private data class DumpRow(
    val index: Int,
    val rowId: String,
    val fields: List<Pair<String, String>>, // (keyHex, valueStr)
)

/** Parse JSON sederhana (tanpa library). */
private fun parseDump(json: String): List<DumpRow> {
    val rows = mutableListOf<DumpRow>()
    // Ekstrak tiap row: {"index": N, "rowId": "...", "fields": [...]}
    val rowPattern = Regex(
        """\{\s*"index":\s*(\d+),\s*"rowId":\s*"([^"]+)",\s*"fields":\s*\[(.*?)\]\s*\}""",
        RegexOption.DOT_MATCHES_ALL,
    )
    val fieldPattern = Regex(
        """\{"key":\s*"([^"]+)",\s*"type":\s*"[^"]+",\s*"value":\s*(.+?)\}(?=,|\s*\])""",
    )
    rowPattern.findAll(json).forEach { m ->
        val idx = m.groupValues[1].toInt()
        val rowId = m.groupValues[2]
        val fieldsStr = m.groupValues[3]
        val fields = fieldPattern.findAll(fieldsStr).map { fm ->
            fm.groupValues[1] to fm.groupValues[2].trim()
        }.toList()
        rows.add(DumpRow(idx, rowId, fields))
    }
    return rows
}
