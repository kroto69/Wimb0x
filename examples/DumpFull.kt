package examples

import tik.foundation.winbox.*
import java.io.File

/**
 * Dump semua field tiap baris tabel sebagai JSON — read-only.
 * Varian DumpTable yang terima host:port.
 *
 * Usage: DumpFullKt <host:port> <user> <pass> <path: "27,102"> <output.json>
 *
 * Mask nilai untuk key password (0x2 pada [27,101]).
 * [24,2] diambil via getSingleton bila getAllRows kosong.
 */
fun main(args: Array<String>) {
    if (args.size < 5) {
        println("Usage: DumpFullKt <host:port> <user> <pass> <path> <output.json>")
        return
    }
    val (host, port) = args[0].split(":").let { it[0] to it[1].toInt() }
    val user = args[1]
    val pass = args[2]
    val path = args[3].split(",").map { it.trim().toInt() }
    val outFile = args[4]

    val session = WinboxSession(host, port)
    try {
        session.connect()
        session.login(user, pass)
        var rows = runCatching { session.getAllRows(path) }.getOrElse { emptyList() }
        // [24,2] system resource = singleton
        if (rows.isEmpty() && path == listOf(24, 2)) {
            val single = runCatching { session.getSingleton(path) }.getOrNull()
            if (single != null) rows = listOf(single)
        }

        val sb = StringBuilder()
        sb.append("{\n")
        sb.append("  \"path\": [${path.joinToString(", ")}],\n")
        sb.append("  \"rowCount\": ${rows.size},\n")
        sb.append("  \"rows\": [\n")
        rows.forEachIndexed { idx, row ->
            sb.append("    {\n")
            sb.append("      \"index\": $idx,\n")
            val rowId = row.itemId()?.let { idToStringFull(it) } ?: "null"
            sb.append("      \"rowId\": \"$rowId\",\n")
            sb.append("      \"fields\": [\n")
            row.fields.forEachIndexed { fIdx, f ->
                val keyHex = "0x${f.key.toString(16).uppercase()}"
                val typeName = f.value.javaClass.simpleName
                val valueStr = fieldValueToStringFull(f, path)
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

        File(outFile).parentFile?.mkdirs()
        File(outFile).writeText(sb.toString())
        println("Dump [${path.joinToString(",")}] ${rows.size} baris → $outFile")
    } finally {
        runCatching { session.close() }
    }
}

private fun idToStringFull(id: M2Field): String = when (val v = id.value) {
    is M2Value.U8 -> "u8:${v.v}"
    is M2Value.U32 -> "u32:${v.v}"
    else -> "?"
}

private fun fieldValueToStringFull(f: M2Field, path: List<Int>): String {
    val isPassword = (path == listOf(27, 101) && f.key == 0x2)
    if (isPassword) return "\"***MASKED***\""

    return when (val v = f.value) {
        is M2Value.Str -> "\"${v.s.replace("\\", "\\\\").replace("\"", "\\\"")}\""
        is M2Value.U8 -> v.v.toString()
        is M2Value.U32 -> v.v.toString()
        is M2Value.U64 -> v.v.toString()
        is M2Value.Bool -> v.v.toString()
        is M2Value.Raw -> "\"<raw ${v.b.size} bytes: ${v.b.take(16).joinToString("") { "%02x".format(it) }}…>\""
        is M2Value.MsgArray -> "\"<msgarray ${v.vs.size} items>\""
        is M2Value.U32Array -> "[${v.vs.joinToString(", ")}]"
        is M2Value.U64Array -> "[${v.vs.joinToString(", ")}]"
        is M2Value.U16Array -> "[${v.vs.joinToString(", ")}]"
        is M2Value.StrArray -> "[${v.vs.joinToString(", ") { "\"$it\"" }}]"
        is M2Value.Addr6 -> "\"<addr6>\""
        else -> "\"<${v.javaClass.simpleName}>\""
    }
}
