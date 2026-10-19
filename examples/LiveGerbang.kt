package tik.foundation

import tik.foundation.winbox.*

/**
 * Live test untuk 4 gerbang 🟡 — dijalankan ke router uji juragan.
 *
 * Usage: kotlin LiveGerbangKt <host> <port> <user> <password>
 *
 * Tes:
 * 1. Arah PPP active (read-only): dump 27,103 2x selisih 5 detik
 * 2. Arah queue: buat queue uji 7M/9M, dump 20,9, cari key 7000000/9000000
 * 3. Lebar PROFILE: add secret zz-test-wimb0x, baca ulang, hapus
 * 4. Index interface: panduan manual (tidak otomatis)
 *
 * Kredensial hanya dipakai saat tes, tidak disimpan.
 */
fun main(args: Array<String>) {
    if (args.size < 4) {
        println("Usage: LiveGerbangKt <host> <port> <user> <password>")
        return
    }
    val (host, portStr, user, password) = args
    val port = portStr.toIntOrNull() ?: 8291

    println("=== LIVE TEST GERBANG ===")
    println("Target: $host:$port")

    val sess = WinboxSession(host = host, port = port)
    try {
        print("Connect... ")
        sess.connect()
        println("OK")
        print("Login ($user)... ")
        sess.login(user, password)
        println("OK")
        println("Mode: ${sess.sessionMode}")
        println("RouterOS: ${sess.routerVersion()}")

        // ============ TES 1: Arah PPP active (read-only) ============
        println("\n--- TES 1: Arah PPP active [27,103] ---")
        val active1 = sess.getPppActive()
        println("Sesi aktif: ${active1.size}")
        if (active1.isNotEmpty()) {
            val s = active1[0]
            val a1 = s.bytesA; val b1 = s.bytesB
            println("Sesi '${s.name}': A=$a1 B=$b1")
            println("Tunggu 5 detik...")
            Thread.sleep(5000)
            val active2 = sess.getPppActive().firstOrNull { it.name == s.name }
            if (active2 != null) {
                val dA = active2.bytesA - a1
                val dB = active2.bytesB - b1
                println("Delta 5 detik: 0x9=+$dA 0xA=+$dB")
                println("KESIMPULAN: key yang naik = arah traffic aktif saat itu.")
            }
        } else {
            println("Tidak ada sesi aktif — SKIP (butuh sesi yang ada traffic).")
        }

        // ============ TES 2: Arah queue ============
        println("\n--- TES 2: Arah queue [20,9] ---")
        print("Buat queue uji 'zz-test-wimb0x' (up 7M / down 9M)... ")
        val qResult = sess.addQueueResult(
            QueueInput(name = "zz-test-wimb0x", upMaxBps = 7_000_000, downMaxBps = 9_000_000)
        )
        println(qResult)
        if (qResult is WriteResult.Ok) {
            Thread.sleep(1000)
            val queues = sess.getAllRows(WinboxPaths.QUEUE_SIMPLE)
            // Nama queue di key 0x2 (str)
            val testQ = queues.firstOrNull { it.str(0x2) == "zz-test-wimb0x" }
            if (testQ != null) {
                println("Queue ditemukan. Key dengan nilai 7000000 / 9000000:")
                for (f in testQ.fields) {
                    val v = when (val fv = f.value) {
                        is M2Value.U32 -> fv.v
                        is M2Value.U64 -> fv.v.toLong()
                        is M2Value.U8 -> fv.v.toLong()
                        else -> null
                    }
                    if (v == 7_000_000L || v == 9_000_000L) {
                        val arah = if (v == 7_000_000L) "UPLOAD" else "DOWNLOAD"
                        println("  0x${f.key.toString(16).uppercase()} = $v  <-- $arah")
                    }
                }
            } else {
                println("Queue tidak ketemu setelah add — cek manual.")
            }
            // Hapus queue uji
            val qId = testQ?.itemId()
            if (qId != null) {
                print("Hapus queue uji... ")
                println(sess.removeQueueResult(qId))
            }
        }

        // ============ TES 3: Lebar PROFILE ============
        println("\n--- TES 3: Lebar PROFILE [27,101] ---")
        val profiles = sess.getPppProfiles()
        println("Profile: ${profiles.map { it.name }}")
        if (profiles.isNotEmpty()) {
            print("Add secret 'zz-test-wimb0x' (profileId u32)... ")
            val sResult = sess.addPppSecretResult(
                PppSecretInput(name = "zz-test-wimb0x", password = "test123", profileId = 0)
            )
            println(sResult)
            if (sResult is WriteResult.Ok) {
                Thread.sleep(1000)
                val testS = sess.getPppSecrets().firstOrNull { it.name == "zz-test-wimb0x" }
                if (testS != null) {
                    println("Terbaca: profileRef=${testS.profileRef}")
                    println("KESIMPULAN: jika profileRef=0 -> u32 BENAR.")
                    print("Hapus secret uji... ")
                    println(sess.removePppSecretResult(testS.rowId))
                }
            }
        }

        // ============ TES 4: panduan manual ============
        println("\n--- TES 4: Index interface (manual) ---")
        val ifaces = sess.getInterfaces()
        println("Interface tersedia:")
        ifaces.forEach { println("  ${it.name} (rowId=${it.rowId.value})") }
        println("PANDUAN: di WinBox resmi, add 192.0.2.99/24 ke interface cadangan,")
        println("lalu lihat interface mana yang terpasang. Cocok dengan rowId di atas?")

        println("\n=== SELESAI ===")
    } catch (e: Exception) {
        println("\nERROR: ${e.javaClass.simpleName}: ${e.message}")
    } finally {
        runCatching { sess.close() }
        println("Koneksi ditutup. Kredensial tidak disimpan.")
    }
}
