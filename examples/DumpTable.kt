package examples

import tik.foundation.winbox.*
import java.io.File

/**
 * Dump semua field tiap baris tabel sebagai JSON — 🟡.
 *
 * Usage: DumpTableKt <host> <user> <pass> <path: "27,102"> [--stats] [output.json]
 *
 * Mask nilai untuk key password (0x2 pada [27,101]) dan field bernama password.
 * Read-only: tidak menulis ke router.
 */
fun main(args: Array<String>) {
    if (args.size < 4) {
        println("Usage: DumpTableKt <host> <user> <pass> <path: \"27,102\"> [--stats] [output.json]")
        return
    }
    val host = args[0]
    val user = args[1]
    val pass = args[2]
    val path = args[3].split(",").map { it.trim().toInt() }
    val withStats = "--stats" in args
    val outFile = args.firstOrNull { it.endsWith(".json") }
        ?: "dump_${path.joinToString("_")}.json"

    val session = WinboxSession(host, 8291)
    try {
        session.connect()
        session.login(user, pass)
        val rows = session.getAllRows(path, withStats = withStats)

        val sb = StringBuilder()
        sb.append("{\n")
        sb.append("  \"path\": [${path.joinToString(", ")}],\n")
        sb.append("  \"withStats\": $withStats,\n")
        sb.append("  \"rowCount\": ${rows.size},\n")
        sb.append("  \"rows\": [\n")
        rows.forEachIndexed { idx, row ->
            sb.append("    {\n")
            sb.append("      \"index\": $idx,\n")
            // rowId untuk cocokkan baris di DiffDump
            val rowId = row.itemId()?.let { idToString(it) } ?: "null"
            sb.append("      \"rowId\": \"$rowId\",\n")
            sb.append("      \"fields\": [\n")
            row.fields.forEachIndexed { fIdx, f ->
                val keyHex = "0x${f.key.toString(16).uppercase()}"
                val typeName = f.value.javaClass.simpleName
                val valueStr = fieldValueToString(f, path)
                sb.append("        {\"key\": \"$keyHex\", \"type\": \"$typeName\", \"value\": $valueStr}")
                if (fIdx < row.fields.size - 1) sb.append(",")
                sb.append("\n")
            }
            sb.append("      ]\n")
            sb.append("    }")
            if (idx < rows.size - 1) sb.append(",")
            sb.append("\n")
        }
        sb.append("  ]\n")
        sb.append("}\n")

        File(outFile).writeText(sb.toString())
        println("Dump ${rows.size} baris → $outFile")
    } finally {
        runCatching { session.close() }
    }
}

private fun idToString(id: M2Field): String = when (val v = id.value) {
    is M2Value.U8 -> "u8:${v.v}"
    is M2Value.U32 -> "u32:${v.v}"
    else -> "?"
}

/** Konversi nilai field ke JSON string; mask password. */
private fun fieldValueToString(f: M2Field, path: List<Int>): String {
    // Mask password: key 0x2 pada [27,101], atau key bernama password
    val isPassword = (path == listOf(27, 101) && f.key == 0x2)
    if (isPassword) return "\"***MASKED***\""

    return when (val v = f.value) {
        is M2Value.Str -> "\"${v.s.replace("\"", "\\\"")}\""
        is M2Value.U8 -> v.v.toString()
        is M2Value.U32 -> v.v.toString()
        is M2Value.U64 -> v.v.toString()
        is M2Value.Bool -> v.v.toString()
        is M2Value.Raw -> "\"<raw ${v.b.size} bytes: ${v.b.take(16).joinToString("") { "%02x".format(it) }}…>\""
        is M2Value.MsgArray -> "\"<msgarray ${v.vs.size} items>\""
        is M2Value.U32Array -> "[${v.vs.joinToString(", ")}]"
        is M2Value.U64Array -> "[${v.vs.joinToString(", ")}]"
        else -> "\"<${v.javaClass.simpleName}>\""
    }
}
