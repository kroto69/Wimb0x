import tik.foundation.winbox.*

// Coba GET_ONE / GET_SINGLETON ke item SFP — cari data tab SFP.
fun main(args: Array<String>) {
    val (host, port) = args[0].split(":").let { it[0] to it[1].toInt() }
    val sess = WinboxSession(host, port, connectTimeoutMs = 8000)
    sess.connect()
    sess.login(args[1], args[2])
    try {
        val rows = sess.getAllRows(listOf(20, 0))
        val sfp = rows.firstOrNull { it.str(0x10006)?.contains("sfp", true) == true }
        val itemId = sfp?.u8(0xFE0001) ?: return
        println("SFP itemId: $itemId")

        // Coba GET_ONE (0xFE0002) dengan target itemId
        for ((name, cmd) in listOf("GET_ONE" to 0xFE0002L, "GET_SINGLETON" to 0xFE000DL)) {
            try {
                val req = M2Message(listOf(
                    sysTo(20, 0), sysFrom(0, 0),
                    sysRequest(true), sysReqId(1001),
                    sysCmd(cmd),
                    M2Field(0xFE0001, M2Value.U8(itemId)),
                ))
                val resp = sess.requestRaw(req)
                println("$name: ${resp.fields.size} fields")
                var sfpFound = false
                for (f in resp.fields.sortedBy { it.key }) {
                    val keyHex = "0x${f.key.toString(16).uppercase()}"
                    // tampilkan semua, cari yang SFP-ish
                    val v = when (val x = f.value) {
                        is M2Value.Str -> "\"${x.s.take(40)}\""
                        is M2Value.U8 -> "${x.v}"
                        is M2Value.U32 -> "${x.v}"
                        is M2Value.Bool -> "${x.v}"
                        is M2Value.Raw -> "Raw(${x.b.size}B)"
                        else -> "..."
                    }
                    println("  $keyHex=$v")
                    if (keyHex.startsWith("0x4") && f.key in 0x400..0x4FF) sfpFound = true
                }
                if (sfpFound) println("  ^^ ada field 0x400-0x4FF")
            } catch (e: Exception) {
                println("$name: ERROR ${e.message?.take(60)}")
            }
        }
    } finally {
        sess.close()
    }
}
