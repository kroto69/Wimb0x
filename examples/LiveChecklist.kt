package examples

import tik.foundation.winbox.*
import java.io.File
import java.time.Instant

/**
 * Live-test checklist runner — satu perintah untuk semua cek live juragan.
 *
 * READ-ONLY: tidak menulis ke router. Kick destruktif TIDAK dijalankan
 * (bagian kick hanya mencetak langkah manual).
 *
 * Usage: LiveChecklistKt <host> <user> <pass> [output.json]
 *
 * Urutan juragan 2026-10-16:
 *  1. test lokal (sudah 12/12 manual) — bukan di sini
 *  2. checklist live-test di router (v6/v7) — CEK A..F di bawah
 *  3. DumpTable/DiffDump untuk yang masih UNMAPPED — script ini mencetak
 *     semua key mentah yang dibutuhkan, tinggal dikirim ke chat.
 */
fun main(args: Array<String>) {
    if (args.size < 3) {
        println("Usage: LiveChecklistKt <host> <user> <pass> [output.json]")
        return
    }
    val host = args[0]; val user = args[1]; val pass = args[2]
    val outFile = args.getOrNull(3) ?: "live-checklist-${Instant.now().epochSecond}.json"

    val session = WinboxSession(host, 8291)
    val j = StringBuilder().append("{\n")
    fun jkv(k: String, v: String) { j.append("  \"$k\": $v,\n") }

    try {
        session.connect()
        session.login(user, pass)

        // ---------- A. versi ROS ----------
        val ver = runCatching { session.routerVersion() }.getOrNull()
        val major = ver?.major
        println("=== A. RouterOS ===")
        println("    versi: ${ver?.raw ?: "?"} (major=${major ?: "?"})")
        jkv("ros_version", "\"${ver?.raw ?: "?"}\"")
        val isV7 = (major ?: 7) >= 7

        // ---------- B. queue rate direction ----------
        println("\n=== B. Queue [20,9] rate keys (arah butuh DiffDump manual) ===")
        val qRows = runCatching { session.getAllRows(WinboxPaths.QUEUE_SIMPLE, withStats = true) }.getOrElse { emptyList() }
        val (kUp, kDown) = if (isV7) 0x13C to 0xD8 else 0x3C to 0x47
        println("    ekspektasi juragan: ${if (isV7) "v7" else "v6"} → 0x${kUp.toString(16).uppercase()}=UP, 0x${kDown.toString(16).uppercase()}=DOWN (BELUM terverifikasi)")
        qRows.take(10).forEach { r ->
            val name = r.str(0x2) ?: "?"
            val up = r.first(kUp); val down = r.first(kDown)
            println("    [$name] up=${fv(up)} down=${fv(down)}")
        }
        if (qRows.size > 10) println("    ... ${qRows.size - 10} baris lagi (lihat JSON)")
        jkv("queue_rows", qRows.size.toString())
        jkv("queue_key_up", "\"0x${kUp.toString(16).uppercase()}\"")
        jkv("queue_key_down", "\"0x${kDown.toString(16).uppercase()}\"")
        println("    LANGKAH MANUAL: ubah max-limit SATU queue di WinBox resmi →")
        println("    DumpTableKt <h> <u> <p> \"20,9\" --stats sebelum.json → sesudah.json →")
        println("    DiffDumpKt sebelum.json sesudah.json → key yang berubah = max-limit")

        // ---------- C. interface: index vs itemId + key detail ----------
        println("\n=== C. Interface [20,0]: index vs itemId + key detail (UNMAPPED) ===")
        val iRows = runCatching { session.getAllRows(WinboxPaths.INTERFACE) }.getOrElse { emptyList() }
        iRows.forEachIndexed { idx, r ->
            val name = r.str(0x2) ?: "?"
            val id = r.itemId()?.let { idStr(it) } ?: "null"
            val mac = r.first(0x26D)?.let { fvs(it) } ?: "-"
            val mtu = r.first(0x10064)?.let { fvs(it) } ?: "-"
            val speed = r.first(0x3F2)?.let { fvs(it) } ?: "-"
            println("    idx=$idx itemId=$id name=$name MAC=$mac MTU=$mtu speed=$speed")
        }
        println("    key dari .jg (BELUM live-verified): MAC=0x26D MTU=0x10064 speed=0x3F2")
        println("    txrate=0x100D4 rxrate=0x100D3 txbytes=0x100FD rxbytes=0x100FC")
        jkv("interface_rows", iRows.size.toString())

        // ---------- D. PPP secret: lebar PROFILE ----------
        println("\n=== D. PPP secret [27,101]: lebar field PROFILE 0x5 (u8 vs u32?) ===")
        val sRows = runCatching { session.getAllRows(WinboxPaths.PPP_SECRET) }.getOrElse { emptyList() }
        val profTypes = sRows.mapNotNull { it.first(0x5)?.value?.javaClass?.simpleName }.toSet()
        sRows.take(8).forEach { r ->
            val name = r.str(0x1) ?: "?"
            val pf = r.first(0x5)
            println("    [$name] profile=0x5 → ${fv(pf)}")
        }
        println("    tipe teramati di semua secret: ${profTypes.joinToString()} — catat di FIELD-MAP")
        jkv("ppp_secret_rows", sRows.size.toString())
        jkv("profile_field_types", "\"${profTypes.joinToString()}\"")

        // ---------- E. PPP profile: mapping id→nama ----------
        println("\n=== E. PPP profile [27,102]: mapping itemId→nama ===")
        val pRows = runCatching { session.getAllRows(WinboxPaths.PPP_PROFILE) }.getOrElse { emptyList() }
        pRows.forEach { r ->
            val id = r.itemId()?.let { idStr(it) } ?: "null"
            val name = r.str(0xFE0009) ?: "?"
            println("    itemId=$id name=$name")
        }
        jkv("ppp_profile_rows", pRows.size.toString())

        // ---------- F. PPP active: arah traffic 0x9/0xA ----------
        println("\n=== F. PPP active [27,103]: delta bytes 0x9/0xA (2 dtk) ===")
        println("    PENTING: jalankan script ini SAAT ada pelanggan yang sedang download.")
        println("    Arah yang bertumbuh pesat saat download = DOWNSTREAM menurut router.")
        val a1 = runCatching { session.getAllRows(WinboxPaths.PPP_ACTIVE, withStats = true) }.getOrElse { emptyList() }
        Thread.sleep(2000)
        val a2 = runCatching { session.getAllRows(WinboxPaths.PPP_ACTIVE, withStats = true) }.getOrElse { emptyList() }
        val m2 = a2.associateBy { it.itemId()?.let { f -> idStr(f) } }
        a1.forEach { r ->
            val id = r.itemId()?.let { f -> idStr(f) } ?: "null"
            val name = r.str(0xFE0009) ?: "?"
            val cid = r.str(0x3) ?: "-"
            val b9a = r.u64(0x9)?.toLong() ?: -1L
            val bAa = r.u64(0xA)?.toLong() ?: -1L
            val r2 = m2[id]
            val d9 = if (r2 != null) (r2.u64(0x9)?.toLong() ?: b9a) - b9a else -1L
            val dA = if (r2 != null) (r2.u64(0xA)?.toLong() ?: bAa) - bAa else -1L
            println("    [$name/$cid] d(0x9)=$d9 B/2dtk  d(0xA)=$dA B/2dtk")
        }
        if (a1.isEmpty()) println("    (tidak ada sesi aktif — cek saat ada pelanggan online)")
        jkv("ppp_active_rows", a1.size.toString())

        // ---------- G. kick: manual only ----------
        println("\n=== G. Kick [27,103]: TIDAK dijalankan otomatis (destruktif) ===")
        println("    code-level ✅ (terverifikasi 2026-10-16):")
        println("      - escapeTerminalArg() escape \" \\ \$ [ ] ; + test")
        println("      - tombol kick verifikasi via baca ulang [27,103] setelah removeRow")
        println("    LANGKAH MANUAL: kick SATU akun tes dari app → baca ulang [27,103] →")
        println("    pastikan barisnya benar-benar hilang (bukan sekadar reply OK)")

        j.append("  \"generated\": \"${Instant.now()}\"\n}")
        File(outFile).writeText(j.toString())
        println("\nJSON tersimpan → $outFile  (kirim file ini ke chat untuk dibaca key-nya)")
    } finally {
        runCatching { session.close() }
    }
}

/** "0xD8:u32=12345" atau "-" bila null */
private fun fv(f: M2Field?): String =
    f?.let { "0x${it.key.toString(16).uppercase()}:${it.value.javaClass.simpleName}=${fvs(it)}" } ?: "-"

private fun fvs(f: M2Field): String = when (val v = f.value) {
    is M2Value.Str -> v.s
    is M2Value.U8 -> v.v.toString()
    is M2Value.U32 -> v.v.toString()
    is M2Value.U64 -> v.v.toString()
    is M2Value.Bool -> v.v.toString()
    else -> "<${v.javaClass.simpleName}>"
}

private fun idStr(f: M2Field): String = when (val v = f.value) {
    is M2Value.U8 -> "u8:${v.v}"
    is M2Value.U32 -> "u32:${v.v}"
    else -> "?"
}
