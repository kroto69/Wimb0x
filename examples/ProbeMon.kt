import tik.foundation.winbox.*

// Coba request monitor ke [20,0] dengan target item SFP.
fun main(args: Array<String>) {
    val (host, port) = args[0].split(":").let { it[0] to it[1].toInt() }
    val sess = WinboxSession(host, port, connectTimeoutMs = 8000)
    sess.connect()
    sess.login(args[1], args[2])
    try {
        // Cari itemId SFP
        val rows = sess.getAllRows(listOf(20, 0))
        val sfp = rows.firstOrNull { it.str(0x10006)?.contains("sfp", true) == true }
        val itemId = sfp?.u8(0xFE0001) ?: sfp?.u32(0xFE0001)?.toInt()
        println("SFP itemId: $itemId")
        if (itemId == null) return

        // Coba CMD 0x0A (monitor?) dengan target itemId
        // Lihat M2.kt untuk CMD yang tersedia
        println("Mencoba berbagai CMD...")
        for (cmd in listOf(0x0AL, 0x0BL, 0x0CL, 0xFE0012L)) {
            try {
                val req = M2Message(listOf(
                    sysTo(20, 0), sysFrom(0, 0),
                    sysRequest(true), sysReqId(999),
                    sysCmd(cmd),
                    M2Field(0xFE0001, M2Value.U8(itemId)),
                ))
                val resp = sess.requestRaw(req)
                println("CMD 0x${cmd.toString(16)}: OK, ${resp.fields.size} fields")
                for (f in resp.fields.take(10)) {
                    println("  0x${f.key.toString(16)} = ${f.value}")
                }
            } catch (e: Exception) {
                println("CMD 0x${cmd.toString(16)}: ${e.message?.take(50)}")
            }
        }
    } finally {
        sess.close()
    }
}
