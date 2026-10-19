package examples

import tik.foundation.winbox.*

/**
 * Probe read-only kandidat path tabel route di ROS v7.
 *
 * Latar: dump 2026-10-17 — [44,1] IP Route = 47 baris di v6, 0 baris di v7
 * (RB4011iGS+ ROS 7.24.4), tanpa error. [44,2], [44,3], [45,1] juga 0.
 * Tool ini mencoba kandidat path dari loader resmi (.jg) dalam SATU sesi,
 * read-only — untuk memastikan apakah path v7 berbeda atau user tak berizin.
 *
 * Kontrol positif [20,0] (Interface List) dibaca PERTAMA — tiap router pasti
 * punya interface, jadi hasilnya memutuskan dua hipotesis:
 *  - kontrol > 0 baris, semua kandidat route = 0 → path v7 memang beda
 *  - kontrol = 0 baris → masalah izin/login, bukan path (jangan kejar path)
 *
 * Usage: ProbeRoutePathsKt <host:port> <user> <pass>
 */
fun main(args: Array<String>) {
    if (args.size < 3) {
        println("Usage: ProbeRoutePathsKt <host:port> <user> <pass>")
        return
    }
    val (host, port) = args[0].split(":").let { it[0] to it[1].toInt() }
    val user = args[1]
    val pass = args[2]

    // label dari loader resmi roteros.jg (MikroTik Pro APK)
    val candidates = listOf(
        listOf(20, 0) to "Interface List (KONTROL positif — tiap router pasti ada)",
        listOf(44, 1) to "Route List (.jg resmi)",
        listOf(44, 2) to "Route Nexthop (.jg resmi)",
        listOf(44, 10) to "Policy Routing Rule (.jg resmi)",
        listOf(44, 11) to "Routing Mark values (.jg resmi)",
        listOf(44, 15) to "VRF (.jg resmi)",
        listOf(44, 0) to "44,0 (eksplorasi)",
        listOf(44, 3) to "44,3 (pernah 0 di dump)",
    )

    val session = WinboxSession(host, port)
    try {
        session.connect()
        session.login(user, pass)
        println("=== Probe route paths @ $host (read-only) ===")
        for ((path, label) in candidates) {
            val rows = runCatching { session.getAllRows(path) }
                .onFailure { println("[${path.joinToString(",")}] ERROR: ${it.message}") }
                .getOrElse { emptyList() }
            val keys = rows.firstOrNull()?.fields
                ?.map { "0x${it.key.toString(16).uppercase()}" }
                ?.take(8)?.joinToString(",") ?: "-"
            println("[${path.joinToString(",")}] $label -> ${rows.size} baris | keys: $keys")
        }
        println("=== selesai ===")
    } finally {
        runCatching { session.close() }
    }
}
