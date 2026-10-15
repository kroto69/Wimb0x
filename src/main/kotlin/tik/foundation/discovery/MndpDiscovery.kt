package tik.foundation.discovery

import java.io.Closeable
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import kotlin.concurrent.thread

/**
 * Discovery MNDP: kirim solicitation broadcast + dengarkan respons di thread sendiri.
 *
 * Contoh pakai:
 * ```
 * MndpDiscovery(onNeighbor = { println("ketemu: ${it.displayName} @ ${it.address}") }).use { d ->
 *     d.start()
 *     d.solicit()
 *     Thread.sleep(5000)
 *     println(d.neighbors())
 * }
 * ```
 */
class MndpDiscovery(
    private val port: Int = Mndp.PORT,
    private val onNeighbor: (Neighbor) -> Unit = {},
) : Closeable {

    private val socket = DatagramSocket(null).apply {
        reuseAddress = true
        // WAJIB qualified: di dalam apply, `port` polos akan resolve ke
        // DatagramSocket.getPort() (= -1, belum connect), bukan port discovery!
        bind(InetSocketAddress(this@MndpDiscovery.port))
        soTimeout = 1000
    }

    @Volatile
    private var running = false
    private var worker: Thread? = null
    private val seen = LinkedHashMap<String, Neighbor>() // key = MAC

    /** Kirim satu solicitation ke broadcast. Panggil berkala (tiap ~2.5 dtk bila sepi). */
    fun solicit() {
        val pkt = Mndp.solicitPacket()
        socket.send(DatagramPacket(pkt, pkt.size, InetAddress.getByName(Mndp.BROADCAST), port))
    }

    /** Mulai thread pendengar. Idempoten. */
    fun start() {
        if (running) return
        running = true
        worker = thread(name = "mndp-listen", isDaemon = true) {
            val buf = ByteArray(2048)
            while (running) {
                try {
                    val dp = DatagramPacket(buf, buf.size)
                    socket.receive(dp)
                    val host = dp.address?.hostAddress
                    val n = if (host != null) parseNeighbor(host, dp.data, dp.length) else null
                    if (n != null) {
                        synchronized(seen) {
                            seen[n.mac] = n.copy(lastSeenMs = System.currentTimeMillis())
                        }
                        onNeighbor(n)
                    }
                } catch (_: SocketTimeoutException) {
                    // tick normal — tetap dengarkan
                } catch (_: Exception) {
                    // socket ditutup / error fatal: jeda sebentar biar tidak hot-loop
                    try {
                        Thread.sleep(200)
                    } catch (_: InterruptedException) {
                    }
                }
            }
        }
    }

    /** Daftar tetangga terakhir yang terlihat (dedupe per MAC). */
    fun neighbors(): List<Neighbor> = synchronized(seen) { seen.values.toList() }

    fun stop() {
        running = false
        worker?.interrupt()
    }

    override fun close() {
        stop()
        try {
            socket.close()
        } catch (_: Exception) {
        }
    }
}
