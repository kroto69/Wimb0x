import tik.foundation.winbox.*

// Monitor SFP via terminal: /interface ethernet monitor
fun main(args: Array<String>) {
    val (host, port) = args[0].split(":").let { it[0] to it[1].toInt() }
    val sess = WinboxSession(host, port, connectTimeoutMs = 8000)
    sess.connect()
    sess.login(args[1], args[2])
    try {
        val sid = sess.openTerminal()
        if (!sess.terminalLogin(sid, args[1], args[2])) {
            println("terminal login gagal")
            return
        }
        val out = sess.terminalExec(sid, "/interface ethernet monitor sfp-sfpplus1", 15000)
        println("=== OUTPUT ===")
        println(out)
        println("=== CLEAN ===")
        println(sess.cleanTerminalOutput(out, "/interface ethernet monitor sfp-sfpplus1"))
        sess.closeTerminal(sid)
    } finally {
        sess.close()
    }
}
