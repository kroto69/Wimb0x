package tik.foundation

import tik.foundation.winbox.*

/** Live test system info ke dua router juragan. */
fun main() {
    val targets = listOf(
        Triple("103.102.14.90", 8988, "v6"),
        Triple("103.13.204.64", 8987, "v7"),
    )
    val creds = mapOf(
        "v6" to ("mUs3" to "mUs3@"),
        "v7" to ("Gajahmodo" to "majapahit"),
    )

    for ((host, port, label) in targets) {
        println("=== Router $label: $host:$port ===")
        val (user, pass) = creds[label]!!
        val sess = WinboxSession(host = host, port = port)
        try {
            sess.connect()
            sess.login(user, pass)
            println("Login OK, mode: ${sess.sessionMode}")

            val info = sess.getSystemInfo()
            println("Identity   : ${info.identity}")
            println("ROS version: ${info.version}")
            println("Board      : ${info.board}")
            println("Arch       : ${info.arch}")
            println("Uptime     : ${info.uptimeSec?.let { "${it / 3600}j ${(it % 3600) / 60}m" }}")
            println("Free mem   : ${info.freeMemKb?.let { "${it / 1024} MB" }}")
            println("CPU load   : ${info.cpuLoad}%")

            // RouterVersion parse
            val rv = sess.routerVersion()
            println("Parsed     : $rv (v6=${rv?.isV6}, v7=${rv?.isV7})")
        } catch (e: Exception) {
            println("ERROR: ${e.javaClass.simpleName}: ${e.message}")
        } finally {
            runCatching { sess.close() }
        }
        println()
    }
    println("Selesai. Kredensial tidak disimpan.")
}
