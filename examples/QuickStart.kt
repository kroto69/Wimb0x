import tik.foundation.discovery.MndpDiscovery
import tik.foundation.winbox.*

/**
 * Contoh pemakaian winbox-kotlin.
 * Jalankan: kotlinc examples/QuickStart.kt -cp <classes> && java ...
 * Kredensial HARUS via env, jangan di-hardcode:
 *   WINBOX_HOST, WINBOX_PORT (default 8291), WINBOX_USER, WINBOX_PASS
 */
fun main() {
    val host = System.getenv("WINBOX_HOST") ?: error("set WINBOX_HOST")
    val port = System.getenv("WINBOX_PORT")?.toInt() ?: 8291
    val user = System.getenv("WINBOX_USER") ?: error("set WINBOX_USER")
    val pass = System.getenv("WINBOX_PASS") ?: error("set WINBOX_PASS")

    // 1) Discovery (LAN): cari router MikroTik di sekitar
    MndpDiscovery().use { d ->
        d.start()
        Thread.sleep(3000)
        d.neighbors().forEach { println("found: ${it.identity} @ ${it.address} (${it.mac})") }
    }

    // 2) Session + login
    WinboxSession(host, port).use { s ->
        s.connect()
        s.login(user, pass)
        println("login ok, mode=${s.sessionMode}")

        // 3) Baca: log, tetangga, hotspot aktif
        println("--- log (3 terbaru) ---")
        s.getLogs().take(3).forEach { println("[${it.buffer}] ${it.message}") }
        println("--- neighbors ---")
        s.getRouterNeighbors().forEach { println("${it.identity} @ ${it.ip}") }
        println("--- hotspot active ---")
        s.getHotspotActive().forEach { println("${it.user} @ ${it.address}") }

        // 4) Ping speed
        val sid = s.pingStart("127.0.0.1") ?: error("ping gagal start")
        Thread.sleep(2500)
        val sample = s.pingPoll(sid)
        println("ping: current=${sample?.currentBps} avg=${sample?.averageBps}")
        s.pingStop(sid)

        // 5) Tulis: tambah → ubah → hapus PPP secret
        val name = "sdk-demo"
        s.addRow(WinboxPaths.PPP_SECRET, listOf(
            M2Field(m2Key(1, M2Ns.USER), M2Value.Str(name)),
            M2Field(m2Key(2, M2Ns.USER), M2Value.Str("demo123")),
        ))
        Thread.sleep(500)
        val id = s.getAllRows(WinboxPaths.PPP_SECRET)
            .firstOrNull { it.str(m2Key(1, M2Ns.USER)) == name }?.itemId()
            ?: error("baris tidak ketemu")
        s.setRow(WinboxPaths.PPP_SECRET, id,
            listOf(M2Field(m2Key(2, M2Ns.USER), M2Value.Str("demo456"))))
        s.removeRow(WinboxPaths.PPP_SECRET, id)
        println("CRUD ok")
    }
}
