package examples

import tik.foundation.winbox.*

/**
 * Live test terminal WinBox: buka sesi, eksekusi perintah, tutup.
 * Usage: TerminalTestKt <host:port> <user> <pass> [command]
 * Default command: "/system identity print"
 */
fun main(args: Array<String>) {
    if (args.size < 3) {
        println("Usage: TerminalTestKt <host:port> <user> <pass> [command]")
        return
    }
    val (host, port) = args[0].split(":").let { it[0] to it[1].toInt() }
    val command = args.getOrNull(3) ?: "/system identity print"

    val session = WinboxSession(host, port)
    try {
        session.connect()
        session.login(args[1], args[2])
        println("login OK (${session.sessionMode})")

        // 1. Buka terminal
        val sid = session.openTerminal()
        println("openTerminal OK: sid=$sid")

        // 2. Login interaktif
        val loginOk = session.terminalLogin(sid, args[1], args[2])
        println("terminalLogin: ${if (loginOk) "OK" else "FAIL"}")
        if (!loginOk) {
            println("VERIFIKASI: FAIL — login terminal gagal")
            session.closeTerminal(sid)
            return
        }

        // 3. Eksekusi perintah
        println("--- exec: $command ---")
        val output = session.terminalExec(sid, command)
        println("OUTPUT:\n$output")
        println("--- end output ---")

        // Verifikasi: output mengandung hasil yang diharapkan
        val ok = when {
            command.contains("identity") -> output.contains("name:")
            else -> output.isNotEmpty()
        }
        println("VERIFIKASI: ${if (ok) "PASS" else "FAIL"}")

        // 4. Tutup terminal
        session.closeTerminal(sid)
        println("closeTerminal OK")
    } catch (e: Exception) {
        println("ERROR: ${e.message}")
        e.printStackTrace()
    } finally {
        session.close()
    }
}
