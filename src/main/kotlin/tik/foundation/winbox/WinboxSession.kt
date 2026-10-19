package tik.foundation.winbox

import tik.foundation.winbox.WinboxCrypto.decryptFrame
import tik.foundation.winbox.WinboxCrypto.deriveKeys
import tik.foundation.winbox.WinboxCrypto.encryptFrame
import tik.foundation.winbox.WinboxCrypto.md5
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * Sesi WinBox native (M2) di atas TCP 8291.
 *
 * - Login: EC-SRP5 (RouterOS ≥ 6.43); bila router diam ≥ 3 dtk → reconnect +
 *   fallback ke MD5 challenge-response (plaintext, sesuai referensi publik).
 * - Setelah login, semua frame terenkripsi AES-128-CBC (jalur baru).
 * - Korelasi request/response via SYS_REQID (1..255, wrap; 0 dicadangkan).
 *
 * CATATAN: handshake & kripto terverifikasi melawan implementasi referensi
 * (vektor tetap di SmokeTest), tetapi interop penuh BELUM diuji ke router fisik.
 */
class WinboxSession(
    private val host: String,
    private val port: Int = 8291,
    private val connectTimeoutMs: Int = 5000,
    private val readTimeoutMs: Int = 15000,
) : Closeable {

    private var socket: Socket? = null
    private var input: DataInputStream? = null
    private var output: DataOutputStream? = null
    private var keys: WinboxCrypto.StreamKeys? = null
    private var legacyMode = false
    private var legacySid: Long = -1
    private var reqId = 0
    private val srcId = 1

    fun connect() {
        closeQuietly()
        val s = Socket()
        s.tcpNoDelay = true
        s.connect(InetSocketAddress(host, port), connectTimeoutMs)
        s.soTimeout = readTimeoutMs
        socket = s
        input = DataInputStream(s.getInputStream())
        output = DataOutputStream(s.getOutputStream())
    }

    val isConnected: Boolean get() = socket?.isConnected == true

    // ---------- handshake (tidak di-chunk) ----------

    private fun sendHandshake(payload: ByteArray) {
        requireNotNull(output) { "belum connect()" }
            .write(WinboxFrame.encodeHandshake(payload, WinboxFrame.TAG_ENCRYPTED))
    }

    /** Baca satu frame handshake → payload, atau null bila timeout. */
    private fun recvHandshake(timeoutMs: Int): ByteArray? {
        val s = requireNotNull(socket) { "belum connect()" }
        val inp = requireNotNull(input) { "belum connect()" }
        val old = s.soTimeout
        s.soTimeout = timeoutMs
        try {
            val len = inp.read()
            if (len < 0) return null
            val tag = inp.read()
            if (tag != WinboxFrame.TAG_ENCRYPTED) {
                throw WinboxException("tag handshake tak terduga: 0x${tag.toString(16)}")
            }
            val buf = ByteArray(len)
            readFully(inp, buf)
            return buf
        } catch (_: SocketTimeoutException) {
            return null
        } catch (_: EOFException) {
            return null
        } finally {
            s.soTimeout = old
        }
    }

    // ---------- login ----------

    /**
     * Login penuh. Melempar [WinboxException] bila kredensial salah / protokol gagal.
     */
    fun login(username: String, password: String) {
        try {
            loginEcSrp5(username, password)
        } catch (e: WinboxUnsupportedException) {
            // Router tua: sambung ulang dari nol, jalur legacy
            connect()
            loginLegacy(username, password)
            legacyMode = true
        }
    }

    private fun loginEcSrp5(username: String, password: String) {
        val init = EcSrp5.init()
        sendHandshake(EcSrp5.handshakePayload(username, init))
        val resp = recvHandshake(3000)
            ?: throw WinboxUnsupportedException("router diam — EC-SRP5 tak didukung?")
        if (resp.size != 49) {
            val txt = resp.toString(Charsets.UTF_8)
            throw WinboxException("login ditolak server: $txt")
        }
        val xWB = resp.copyOfRange(0, 32)
        val parityB = resp[32].toInt() and 0xFF
        val salt = resp.copyOfRange(33, 49)
        val sec = EcSrp5.processChallenge(init, xWB, parityB, salt, username, password)
        sendHandshake(sec.clientCc) // [32][0x06] + 32B
        val conf = recvHandshake(readTimeoutMs)
            ?: throw WinboxException("tak ada konfirmasi dari server")
        if (conf.size < 32 || !EcSrp5.verifyServer(conf.copyOf(32), sec)) {
            val txt = conf.toString(Charsets.UTF_8)
            throw WinboxException("username atau password salah ($txt)")
        }
        keys = deriveKeys(sec.secret)
        // CATATAN: Dulu ada request [13,4] "capabilities" di sini meniru client asli,
        // tapi hasilnya dibuang dan di sebagian router responsnya memakai frame tag
        // tak terduga (0/240/241) yang merusak posisi stream — login gagal.
        // Dihapus 2026-10-18: kunci sesi sudah valid dari handshake, [13,4] tidak esensial.
    }

    /**
     * Login legacy MD5 (RouterOS < 6.43) — M2 plaintext, sesuai referensi publik.
     * Best-effort: belum terverifikasi ke router fisik.
     */
    private fun loginLegacy(username: String, password: String) {
        val out = requireNotNull(output) { "belum connect()" }
        val inp = requireNotNull(input) { "belum connect()" }

        fun raw(req: M2Message): M2Message {
            val id = nextReqId()
            val withId = req.withField(sysReqId(id))
            val payload = byteArrayOf(
                ((withId.encode().size shr 8) and 0xFF).toByte(),
                (withId.encode().size and 0xFF).toByte(),
            ) + withId.encode()
            out.write(WinboxFrame.encodeData(payload, WinboxFrame.TAG_RAW))
            while (true) {
                val (tag, assembled) = WinboxFrame.decodeFrame(inp)
                if (tag != WinboxFrame.TAG_RAW) continue
                val resp = M2Message.decode(WinboxFrame.decodeRawBody(assembled))
                if (resp.u8(K_SYS_REQID) == id) return resp
            }
        }

        // 1. Minta session id
        val r1 = raw(
            M2Message(
                listOf(
                    sysTo(2, 2), sysFrom(0, srcId), sysCmd32(CMD_GET.toLong()),
                    sysRequest(true), userStr(1, "list"),
                ),
            ),
        )
        val sid = r1.u8(K_SESSION_ID)?.toLong()
            ?: r1.u32(K_SESSION_ID)
            ?: throw WinboxException("legacy: tak dapat session id")
        legacySid = sid
        val sidField = sessionIdField(sid)

        // 2. Challenge setup (respons boleh tak datang — drain singkat)
        try {
            val id = nextReqId()
            val m = M2Message(listOf(sysTo(2, 2), sysCmd32(CMD_OPEN.toLong()), sidField, sysReqId(id)))
            val payload = byteArrayOf(((m.encode().size shr 8) and 0xFF).toByte(), (m.encode().size and 0xFF).toByte()) + m.encode()
            out.write(WinboxFrame.encodeData(payload, WinboxFrame.TAG_RAW))
            socket?.soTimeout = 300
            try {
                WinboxFrame.decodeFrame(inp)
            } catch (_: Exception) {
            } finally {
                socket?.soTimeout = readTimeoutMs
            }
        } catch (_: Exception) {
        }

        // 3. Minta salt
        val r3 = raw(
            M2Message(
                listOf(
                    sysTo(13, 4), sysCmd32(CMD_GET.toLong()),
                    sysRequest(true), sidField,
                ),
            ),
        )
        val salt = r3.raw(m2Key(9, M2Ns.USER))
            ?: throw WinboxException("legacy: tak dapat salt")

        // 4. Login: 0x00 ‖ MD5(0x00 ‖ password ‖ salt)
        val hash = byteArrayOf(0) + md5(byteArrayOf(0) + password.toByteArray(Charsets.UTF_8) + salt)
        val r4 = raw(
            M2Message(
                listOf(
                    sysTo(13, 4), sysCmd32(1), sidField,
                    userStr(1, username), userRaw(9, salt), userRaw(10, hash),
                ),
            ),
        )
        val status = r4.u8(K_SYS_STATUS) ?: r4.u32(K_SYS_STATUS)?.toInt() ?: -1
        if (status != 0) {
            throw WinboxException("legacy login gagal (status=$status)")
        }
    }

    // ---------- request/response ----------

    private fun nextReqId(): Int {
        reqId = if (reqId >= 255) 1 else reqId + 1
        return reqId
    }

    private fun sendEncrypted(m2: ByteArray) {
        val k = requireNotNull(keys) { "belum login (jalur baru)" }
        val payload = encryptFrame(m2, k.sendAes, k.sendHmac)
        requireNotNull(output) { "belum connect()" }
            .write(WinboxFrame.encodeData(payload, WinboxFrame.TAG_ENCRYPTED))
    }

    /**
     * Kirim satu pesan M2 tanpa menunggu respons. Mengembalikan SYS_REQID
     * yang dipakai. Untuk dispatcher/subscribe — hanya jalur terenkripsi.
     */
    internal fun sendOneWay(msg: M2Message): Int {
        if (legacyMode) throw WinboxException("sendOneWay hanya untuk jalur terenkripsi")
        val id = nextReqId()
        sendEncrypted(msg.withField(sysReqId(id)).encode())
        return id
    }

    private fun recvEncryptedM2(): M2Message {
        val inp = requireNotNull(input) { "belum connect()" }
        val k = requireNotNull(keys) { "belum login (jalur baru)" }
        val (tag, payload) = WinboxFrame.decodeFrame(inp)
        if (tag != WinboxFrame.TAG_ENCRYPTED) {
            val hex = payload.take(16).joinToString(" ") { "%02X".format(it) }
            throw WinboxException("tag frame tak terduga: $tag (payload[0..16]=$hex)")
        }
        return M2Message.decode(decryptFrame(payload, k.recvAes))
    }

    /**
     * Kirim satu request M2, tunggu respons dengan SYS_REQID yang cocok.
     * Frame tak diminta (mis. logout push) dilewati.
     */
    fun requestRaw(msg: M2Message): M2Message {
        if (legacyMode) throw WinboxException("requestRaw hanya untuk jalur terenkripsi")
        val id = nextReqId()
        sendEncrypted(msg.withField(sysReqId(id)).encode())
        while (true) {
            val resp = recvEncryptedM2()
            if (resp.u8(K_SYS_REQID) == id) return resp
        }
    }

    /** Mode sesi: "EC-SRP5/AES", "legacy/MD5", atau "none". */
    val sessionMode: String
        get() = if (keys != null) "EC-SRP5/AES" else if (legacyMode) "legacy/MD5" else "none"

    /**
     * CRUD generik ke handler path (mis. [24,2] system resource).
     * Path handler per fitur perlu verifikasi ke router fisik.
     */
    fun crud(handlerPath: List<Int>, cmd: Long, extra: List<M2Field> = emptyList(), withStats: Boolean = false): M2Message {
        val fields = mutableListOf(
            sysTo(*handlerPath.toIntArray()),
            sysFrom(0, srcId),
            sysRequest(true),
            sysCmd(cmd),
        )
        if (cmd == CMD_GET_ALL.toLong()) {
            // flag wajib — tanpa ini handler tak mengembalikan baris;
            // withStats menyertakan counter runtime (window autorefresh)
            val flags = if (withStats) GETALL_FLAGS or GETALL_STATS_BIT else GETALL_FLAGS
            fields += M2Field(0xFE000C, M2Value.U32(flags))
        }
        fields += extra
        return requestRaw(M2Message(fields))
    }

    /**
     * Kirim satu request M2 mentah (mode legacy), tunggu respons dengan
     * SYS_REQID yang cocok. Null bila timeout.
     */
    fun requestLegacy(msg: M2Message, timeoutMs: Int = 5000): M2Message? {
        val out = requireNotNull(output) { "belum connect()" }
        val inp = requireNotNull(input) { "belum connect()" }
        val s = requireNotNull(socket) { "belum connect()" }
        val id = nextReqId()
        val full = msg.withField(sysReqId(id)).withField(sessionIdField(legacySid))
        val m2 = full.encode()
        val payload = byteArrayOf(((m2.size shr 8) and 0xFF).toByte(), (m2.size and 0xFF).toByte()) + m2
        out.write(WinboxFrame.encodeData(payload, WinboxFrame.TAG_RAW))
        out.flush()
        val old = s.soTimeout
        s.soTimeout = timeoutMs
        try {
            while (true) {
                val (tag, assembled) = WinboxFrame.decodeFrame(inp)
                if (tag != WinboxFrame.TAG_RAW) continue
                val resp = M2Message.decode(WinboxFrame.decodeRawBody(assembled))
                if (resp.u8(K_SYS_REQID) == id) return resp
            }
        } catch (_: SocketTimeoutException) {
            return null
        } finally {
            s.soTimeout = old
        }
    }

    /**
     * Getall legacy ke handler path (mis. [20,0]). Null bila timeout.
     * Flag ufe000c wajib — tanpa itu handler tak mengembalikan baris.
     */
    fun getAllLegacy(
        handlerPath: List<Int>,
        timeoutMs: Int = 5000,
        withStats: Boolean = false,
        extra: List<M2Field> = emptyList(),
    ): M2Message? {
        if (!legacyMode) throw WinboxException("getAllLegacy hanya untuk mode legacy")
        val flags = if (withStats) GETALL_FLAGS or GETALL_STATS_BIT else GETALL_FLAGS
        return requestLegacy(
            M2Message(
                listOf(
                    sysTo(*handlerPath.toIntArray()),
                    sysFrom(0, srcId),
                    sysRequest(true),
                    sysCmd(CMD_GET_ALL.toLong()),
                    M2Field(0xFE000C, M2Value.U32(flags)),
                ) + extra,
            ),
            timeoutMs,
        )
    }

    /**
     * Buka file via mproxy [2,2] (cmd=7 OpenStatic) → handle, atau null.
     * Berfungsi di mode terenkripsi maupun legacy.
     */
    fun mproxyOpen(filename: String): Int? {
        val req = M2Message(
            listOf(
                sysTo(2, 2), sysFrom(0, srcId), sysRequest(true),
                sysCmd(7), userStr(1, filename),
            ),
        )
        val resp = if (keys != null) requestRaw(req) else requestLegacy(req) ?: return null
        return resp.u8(K_SESSION_ID) ?: resp.u32(K_SESSION_ID)?.toInt()
    }

    /**
     * Baca satu chunk file via mproxy [2,2] (cmd=4). Mengembalikan respons mentah
     * agar pemanggil bisa inspeksi field chunk-nya.
     */
    fun mproxyReadRaw(handle: Int, maxChunk: Int = 32768): M2Message? {
        val req = M2Message(
            listOf(
                sysTo(2, 2), sysFrom(0, srcId), sysRequest(true),
                sysCmd(4), sessionIdField(handle.toLong()),
                M2Field(m2Key(2, M2Ns.USER), M2Value.U32(maxChunk.toLong())),
            ),
        )
        return if (keys != null) requestRaw(req) else requestLegacy(req)
    }

    /**
     * Baca satu pesan M2 terenkripsi tanpa filter reqID (untuk pesan
     * unsolicited seperti output terminal). Null bila timeout.
     */
    fun readMessage(timeoutMs: Int = 3000): M2Message? {
        val inp = requireNotNull(input) { "belum connect()" }
        val s = requireNotNull(socket) { "belum connect()" }
        val k = requireNotNull(keys) { "butuh mode terenkripsi" }
        val old = s.soTimeout
        s.soTimeout = timeoutMs
        try {
            val (tag, assembled) = WinboxFrame.decodeFrame(inp)
            if (tag != WinboxFrame.TAG_ENCRYPTED) return null
            return M2Message.decode(decryptFrame(assembled, k.recvAes))
        } catch (_: SocketTimeoutException) {
            return null
        } catch (_: EOFException) {
            return null
        } finally {
            s.soTimeout = old
        }
    }

    /**
     * Buka sesi terminal baru via handler [76] (mepty).
     * Mengirim CMD_MEPTY_LOGIN (0x0A0065); router mengembalikan session ID di 0xFE0001.
     * @return session ID untuk dipakai di [terminalSend]/[terminalExec]/[closeTerminal].
     */
    fun openTerminal(): Long {
        val resp = requestRaw(
            M2Message(
                listOf(
                    sysTo(76),
                    sysFrom(0, srcId),
                    sysRequest(true),
                    sysCmd(CMD_MEPTY_LOGIN.toLong()),
                )
            )
        )
        return resp.u8(K_SESSION_ID)?.toLong()
            ?: resp.u32(K_SESSION_ID)
            ?: throw WinboxException("openTerminal: respons tidak mengandung session ID (0xFE0001)")
    }

    /**
     * Login interaktif di sesi terminal. Router mengirim prompt "Login:" lalu
     * "Password:"; kita balas dengan kredensial. Harus dipanggil setelah
     * [openTerminal] sebelum [terminalExec].
     * @return true bila mendapat prompt shell ("] >").
     */
    fun terminalLogin(sid: Long, user: String, pass: String, timeoutMs: Int = 20000): Boolean {
        var stage = 0 // 0=tunggu Login:, 1=tunggu Password:, 2=tunggu prompt
        val deadline = System.currentTimeMillis() + timeoutMs

        // Kirim sinyal ready dulu untuk memicu pesan awal
        try { terminalSend(sid, 0, null) } catch (_: Exception) {}

        while (System.currentTimeMillis() < deadline) {
            val msg = try { readMessage(500) } catch (_: Exception) { null } ?: continue
            val raw = msg.fields.firstOrNull { it.key == 0x2 }?.value as? M2Value.Raw
                ?: continue
            val text = raw.b.toString(Charsets.UTF_8)

            when (stage) {
                0 -> if (text.contains("Login:")) {
                    termSendData(sid, "$user\n".toByteArray())
                    stage = 1
                }
                1 -> if (text.contains("Password:")) {
                    termSendData(sid, "$pass\n".toByteArray())
                    stage = 2
                }
                2 -> {
                    // Sukses bila banner RouterOS muncul atau prompt langsung.
                    // "Login failed" di awal adalah noise dari percobaan kosong pertama.
                    if (text.contains("MikroTik") || text.contains("RouterOS") || text.contains("] >")) return true
                }
            }
        }
        return false
    }

    /** Kirim data terminal. key3=0 (router tidak strict soal counter untuk sesi login). */
    private fun termSendData(sid: Long, data: ByteArray) {
        terminalSend(sid, 0, data)
    }

    /**
     * Tutup sesi terminal. Mengirim CMD_MEPTY_DATA dengan data kosong
     * sebagai sinyal tutup (best-effort; router juga timeout otomatis).
     */
    fun closeTerminal(sid: Long) {
        try {
            // Kirim EOF (Ctrl+D, 0x04)
            termSendData(sid, byteArrayOf(0x04))
        } catch (_: Exception) {
        }
    }

    /**
     * Kirim data terminal (meptyData). Mengembalikan pesan mentah bila perlu.
     * key_2 = input (atau null untuk sinyal ready/ACK), key_3 = counter.
     */
    fun terminalSend(sid: Long, key3: Long, data: ByteArray? = null): M2Message {
        val fields = mutableListOf(
            sysTo(76),
            sysFrom(0, srcId),
            sysRequest(true),
            M2Field(m2Key(3, M2Ns.USER), M2Value.U32(key3)),
            sessionIdField(sid),
            sysCmd(CMD_MEPTY_DATA.toLong()),
        )
        if (data != null) fields += userRaw(2, data)
        return requestRaw(M2Message(fields))
    }

    /**
     * Eksekusi perintah terminal sederhana: kirim input, kumpulkan output
     * selama [timeoutMs], kirim ACK flow-control. Mengembalikan teks output.
     */
    /**
     * Eksekusi perintah terminal. Kirim perintah, kumpulkan output sampai
     * prompt kembali. Membersihkan echo & ANSI escape.
     * @return output bersih perintah (tanpa echo/prompt).
     */
    fun terminalExec(sid: Long, command: String, timeoutMs: Int = 20000): String {
        val cmd = command.trimEnd()

        // 1. Tunggu prompt shell (tanda terminal siap terima perintah)
        val promptDeadline = System.currentTimeMillis() + 10000
        var promptSeen = false
        while (System.currentTimeMillis() < promptDeadline && !promptSeen) {
            val msg = try { readMessage(500) } catch (_: Exception) { null } ?: continue
            val msgSid = msg.u8(K_SESSION_ID)?.toLong() ?: msg.u32(K_SESSION_ID)
            if (msgSid != null && msgSid != sid) continue
            val raw = msg.fields.firstOrNull { it.key == 0x2 }?.value as? M2Value.Raw ?: continue
            if (raw.b.toString(Charsets.UTF_8).contains("] >")) promptSeen = true
        }

        // 2. Kirim perintah
        termSendData(sid, (cmd + "\r\n").toByteArray(Charsets.UTF_8))

        // 3. Kumpulkan output sampai prompt kembali
        val sb = StringBuilder()
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val msg = try { readMessage(500) } catch (_: Exception) { null } ?: continue
            val msgSid = msg.u8(K_SESSION_ID)?.toLong() ?: msg.u32(K_SESSION_ID)
            if (msgSid != null && msgSid != sid) continue
            val data = msg.fields.firstOrNull { it.key == 0x2 }?.value as? M2Value.Raw
                ?: continue
            if (data.b.isEmpty()) continue
            sb.append(data.b.toString(Charsets.UTF_8))
            val cleaned = cleanTerminalOutput(sb.toString(), cmd)
            if (cleaned.isNotEmpty() && sb.toString().trimEnd().endsWith("] >")) break
        }

        return cleanTerminalOutput(sb.toString(), cmd)
    }

    /**
     * Bersihkan output terminal: buang ANSI escape, echo perintah, dan prompt.
     * Handle v7 yang kirim output per karakter (satu karakter per baris).
     * Pure function — bisa dites offline.
     */
    fun cleanTerminalOutput(raw: String, command: String): String {
        val t = raw
            .replace(Regex("\u001b\\[[0-9;?]*[A-Za-z]"), "") // ANSI CSI
            .replace(Regex("\u001b\\([AB0]"), "") // ANSI charset
            .replace("\r", "")
        val lines = t.lines().map { it.trim() }.filter { it.isNotEmpty() }

        // Gabungkan baris satu-karakter (v7 per-char output) ke baris sebelumnya
        val merged = mutableListOf<String>()
        for (line in lines) {
            if (line.length == 1 && merged.isNotEmpty() && !merged.last().contains("] >")) {
                // Karakter lanjutan dari baris sebelumnya (mis. "R" + "." + "W" -> "R.W")
                merged[merged.size - 1] = merged.last() + line
            } else {
                merged.add(line)
            }
        }

        val cmdWords = command.trim().split(" ").filter { it.isNotEmpty() }
        val out = merged.filterNot { line ->
            // Prompt murni atau baris echo
            line.contains("] >")
        }
        return out.joinToString("\n").trim()
    }

    private fun closeQuietly() {
        try {
            socket?.close()
        } catch (_: Exception) {
        }
        socket = null
        keys = null
        legacyMode = false
    }

    override fun close() = closeQuietly()
}

class WinboxUnsupportedException(msg: String) : Exception(msg)
