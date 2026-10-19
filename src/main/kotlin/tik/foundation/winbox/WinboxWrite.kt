package tik.foundation.winbox

/**
 * Hasil operasi tulis (add/set/remove) — 🟡 belum live-test.
 *
 * Baca error dari response: 0xFF0008 (kode, 0 = ok), 0xFF0009 (string).
 */
sealed class WriteResult {
    /** Berhasil. [newId] = itemId baris baru (untuk add), [raw] = response mentah. */
    data class Ok(val newId: M2Field?, val raw: M2Message) : WriteResult()

    /** Gagal. [code] dari 0xFF0008, [message] dari 0xFF0009 atau exception. */
    data class Err(val code: Int?, val message: String) : WriteResult()

    /** Timeout / tidak ada response. */
    data object Timeout : WriteResult()

    val isOk: Boolean get() = this is Ok
}

/**
 * Parse response tulis → WriteResult — 🟡 belum live-test.
 * Jangan menelan pesan exception — ubah jadi Err.
 */
fun M2Message.toWriteResult(): WriteResult {
    val code = u8(0xFF0008) ?: u32(0xFF0008)?.toInt()
    val msg = str(0xFF0009)
    return if (code == null || code == 0) {
        WriteResult.Ok(newId = itemId(), raw = this)
    } else {
        WriteResult.Err(code = code, message = msg ?: "error code $code")
    }
}

/** Wrap pemanggilan tulis dengan runCatching → WriteResult (jangan telan pesan). */
inline fun writeCatching(block: () -> M2Message?): WriteResult {
    return try {
        val resp = block()
        resp?.toWriteResult() ?: WriteResult.Timeout
    } catch (e: Exception) {
        WriteResult.Err(code = null, message = e.message ?: e.javaClass.simpleName)
    }
}

/**
 * Escape argumen untuk perintah terminal RouterOS — 🟡 belum live-test.
 *
 * Karakter berbahaya: `"`, `\`, `$`, `[`, `]`, `;`.
 * Tanpa ini, nama PPP bisa menyuntik perintah terminal.
 */
fun escapeTerminalArg(s: String): String {
    val sb = StringBuilder(s.length + 8)
    for (c in s) {
        when (c) {
            '"', '\\', '$', '[', ']', ';' -> sb.append('\\')
            else -> {}
        }
        sb.append(c)
    }
    return sb.toString()
}

// ================= *Result variants — 🟡 belum live-test =================
// Varian yang return WriteResult (bukan Boolean) untuk setiap add/set/remove.
// Fungsi lama tetap ada (backward compatible).

fun WinboxSession.addPppSecretResult(input: PppSecretInput): WriteResult =
    writeCatching { addRow(WinboxPaths.PPP_SECRET, input.toFields().filterNotNull()) }

fun WinboxSession.setPppSecretResult(id: M2Field, input: PppSecretInput): WriteResult =
    writeCatching { setRow(WinboxPaths.PPP_SECRET, id, input.toFields().filterNotNull()) }

fun WinboxSession.removePppSecretResult(id: M2Field): WriteResult =
    writeCatching { removeRow(WinboxPaths.PPP_SECRET, id) }

// ================= verifiedSet — 🟡 belum live-test =================

/**
 * SET lalu verifikasi dengan baca ulang — 🟡 belum live-test.
 *
 * Setelah SET, baca ulang tabel via getAllRows, cari baris dengan itemId
 * sama, bandingkan key/nilai yang dikirim. Retry 3x jeda 300ms (roadmap
 * mencatat verify kadang gagal karena timing).
 *
 * Alasan: router mengabaikan write salah target/lebar tipe tanpa error.
 * Return Err("write diabaikan router") bila tidak cocok setelah retry.
 */
fun WinboxSession.verifiedSet(
    path: List<Int>,
    id: M2Field,
    fields: List<M2Field>,
    maxRetries: Int = 3,
    retryDelayMs: Long = 300,
): WriteResult {
    require(id.key == 0xFE0001) { "verifiedSet butuh id 0xFE0001" }

    // Kirim SET
    val setResult = writeCatching { setRow(path, id, fields) }
    if (setResult !is WriteResult.Ok) return setResult

    // Ambil nilai itemId untuk pencocokan (U8 atau U32)
    val idValue: Long? = when (val v = id.value) {
        is M2Value.U8 -> v.v.toLong()
        is M2Value.U32 -> v.v
        else -> null
    } ?: return WriteResult.Err(null, "itemId tidak valid")

    // Retry baca ulang + bandingkan
    repeat(maxRetries) { attempt ->
        if (attempt > 0) Thread.sleep(retryDelayMs)
        try {
            val rows = getAllRows(path)
            val row = rows.firstOrNull { r ->
                val rid = r.itemId()?.value
                when (rid) {
                    is M2Value.U8 -> rid.v.toLong() == idValue
                    is M2Value.U32 -> rid.v == idValue
                    else -> false
                }
            }
            if (row != null) {
                // Bandingkan setiap field yang dikirim
                val mismatch = fields.filterNotNull().firstOrNull { sent ->
                    val actual = row.fields.firstOrNull { it.key == sent.key }?.value
                    actual != sent.value
                }
                if (mismatch == null) {
                    return WriteResult.Ok(newId = id, raw = setResult.raw)
                }
            }
        } catch (_: Exception) {
            // lanjut retry
        }
    }
    return WriteResult.Err(null, "write diabaikan router")
}
