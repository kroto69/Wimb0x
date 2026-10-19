package tik.foundation.winbox

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * Sesi khusus untuk subscribe push-based (`CMD_SUBSCRIBE` = 0xFE0012).
 *
 * Cara kerja (terverifikasi live 2026-10-15):
 * - Kirim SUBSCRIBE ke handler path → router jawab ACK saja (tanpa baris data).
 * - Ambil state awal sendiri via `getAllRows` di sesi biasa.
 * - Setiap ada perubahan, router *push* baris-baris yang berubah sebagai pesan
 *   unsolicited (tanpa `SYS_REQID`, perintah `0xFE000B`), dikorelasikan via
 *   `SYS_FROM` = path handler.
 *
 * Satu koneksi TCP melayani banyak subscription sekaligus; background thread
 * membaca dan mendispatch ke listener per path. Sesi ini TERPISAH dari sesi
 * baca/tulis biasa — tulis (add/set/remove) tetap lewat [WinboxSession].
 *
 * Hanya jalur terenkripsi (EC-SRP5). Tutup dengan [close].
 */
class WinboxSubscriber(
    private val host: String,
    private val port: Int = 8291,
    private val connectTimeoutMs: Int = 8000,
) : AutoCloseable {

    private val session = WinboxSession(host, port, connectTimeoutMs)
    private val listeners = ConcurrentHashMap<List<Int>, CopyOnWriteArrayList<(List<M2Message>) -> Unit>>()
    private val pending = ConcurrentHashMap<Int, LinkedBlockingQueue<M2Message>>()

    @Volatile
    private var running = false
    private var reader: Thread? = null

    val sessionMode: String get() = session.sessionMode

    fun connect() = session.connect()

    fun login(username: String, password: String) {
        session.login(username, password)
        if (!session.sessionMode.startsWith("EC-SRP5")) {
            throw WinboxException("subscribe hanya didukung di jalur terenkripsi (EC-SRP5)")
        }
        startReader()
    }

    private fun startReader() {
        running = true
        reader = thread(isDaemon = true, name = "winbox-subscriber") {
            while (running) {
                val m = try {
                    session.readMessage(1000)
                } catch (_: Exception) {
                    null
                } ?: continue
                val reqId = m.u8(K_SYS_REQID)
                if (reqId != null) {
                    // respons untuk request sinkron (ACK subscribe/unsubscribe)
                    pending[reqId]?.offer(m)
                } else {
                    // push update — korelasi via SYS_FROM (path handler)
                    val path = (m.fields.firstOrNull { it.key == K_SYS_FROM }?.value as? M2Value.U32Array)
                        ?.vs?.map { it.toInt() }
                    val rows = (m.fields.firstOrNull { it.key == 0xFE0002 }?.value as? M2Value.MsgArray)?.vs
                        ?: emptyList()
                    if (path != null) {
                        listeners[path]?.forEach { cb ->
                            try {
                                cb(rows)
                            } catch (_: Exception) {
                            }
                        }
                    }
                }
            }
        }
    }

    private fun syncRequest(msg: M2Message, timeoutMs: Long = 8000): M2Message {
        val q = LinkedBlockingQueue<M2Message>()
        val id = session.sendOneWay(msg)
        pending[id] = q
        try {
            return q.poll(timeoutMs, TimeUnit.MILLISECONDS)
                ?: throw WinboxException("timeout menunggu ACK (reqId=$id)")
        } finally {
            pending.remove(id)
        }
    }

    private fun subMessage(path: List<Int>, cmd: Long, withStats: Boolean = false): M2Message {
        val flags = if (withStats) GETALL_FLAGS or GETALL_STATS_BIT else GETALL_FLAGS
        return M2Message(
            listOf(
                sysTo(*path.toIntArray()),
                sysFrom(0, 1),
                sysRequest(true),
                sysCmd(cmd),
                M2Field(0xFE000C, M2Value.U32(flags)),
            ),
        )
    }

    /**
     * Subscribe ke handler path. [onUpdate] dipanggil di background thread
     * dengan baris-baris yang berubah setiap ada push dari router.
     * Ambil state awal via `getAllRows` di sesi biasa sebelum/sesudah ini.
     */
    fun subscribe(path: List<Int>, onUpdate: (List<M2Message>) -> Unit, withStats: Boolean = false) {
        syncRequest(subMessage(path, CMD_SUBSCRIBE.toLong(), withStats))
        listeners.computeIfAbsent(path) { CopyOnWriteArrayList() }.add(onUpdate)
    }

    /** Berhenti menerima push untuk path ini. */
    fun unsubscribe(path: List<Int>) {
        listeners.remove(path)
        try {
            syncRequest(subMessage(path, CMD_UNSUBSCRIBE.toLong()))
        } catch (_: Exception) {
        }
    }

    override fun close() {
        running = false
        try {
            reader?.join(2000)
        } catch (_: Exception) {
        }
        session.close()
    }
}

/** ID unik baris dari field 0xFE0001 (u8 atau u32). */
fun M2Message.liveId(): String = when (val v = fields.firstOrNull { it.key == 0xFE0001 }?.value) {
    is M2Value.U8 -> "u8:${v.v}"
    is M2Value.U32 -> "u32:${v.v}"
    else -> "noid@${System.identityHashCode(this)}"
}

/**
 * True bila baris push ini adalah penanda hapus: hanya berisi 0xFE0013 +
 * 0xFE0001 (item id), tanpa field data. Ditemukan live 2026-10-15.
 */
fun M2Message.isDeleteMarker(): Boolean =
    fields.any { it.key == 0xFE0013 }

/**
 * Cermin lokal dari satu tabel WinBox yang dijaga tetap segar via push.
 * Thread-safe. ID korelasi selalu dari [liveId].
 */
class LiveTable<T>(private val parse: (M2Message) -> T?) {
    private data class Entry<T>(val id: String, val value: T)
    private val entries = mutableListOf<Entry<T>>()

    @Synchronized
    fun setInitial(messages: List<M2Message>) {
        entries.clear()
        messages.forEach { m ->
            val t = parse(m) ?: return@forEach
            entries.add(Entry(m.liveId(), t))
        }
    }

    /**
     * Terapkan satu batch push. Mengembalikan true bila ada perubahan
     * (tambah/ubah/hapus).
     */
    @Synchronized
    fun applyUpdate(messages: List<M2Message>): Boolean {
        var changed = false
        for (m in messages) {
            val id = m.liveId()
            if (m.isDeleteMarker()) {
                if (entries.removeIf { it.id == id }) changed = true
            } else {
                val t = parse(m) ?: continue
                val idx = entries.indexOfFirst { it.id == id }
                if (idx >= 0) entries[idx] = Entry(id, t) else entries.add(Entry(id, t))
                changed = true
            }
        }
        return changed
    }

    @Synchronized
    fun snapshot(): List<T> = entries.map { it.value }
}

/**
 * Satu paket "satset": subscribe + ambil state awal + [LiveTable] yang
 * otomatis ter-update via push. [onChange] dipanggil tiap ada perubahan
 * dengan snapshot terbaru.
 *
 * Urutan anti-race: subscribe dulu (push di-buffer), lalu getAllRows,
 * replay buffer, baru live.
 */
fun <T> WinboxSubscriber.liveTable(
    session: WinboxSession,
    path: List<Int>,
    parse: (M2Message) -> T?,
    onChange: (List<T>) -> Unit = {},
    withStats: Boolean = false,
): LiveTable<T> {
    val table = LiveTable(parse)
    val lock = Any()
    val buffered = mutableListOf<M2Message>()
    var live = false

    subscribe(path, { rows ->
        val doLive = synchronized(lock) {
            if (!live) {
                buffered.addAll(rows); false
            } else true
        }
        if (doLive && table.applyUpdate(rows)) onChange(table.snapshot())
    }, withStats)
    table.setInitial(session.getAllRows(path, withStats))
    synchronized(lock) {
        live = true
        table.applyUpdate(buffered)
        buffered.clear()
    }
    onChange(table.snapshot())
    return table
}
