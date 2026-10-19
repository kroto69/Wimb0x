package examples

import tik.foundation.winbox.*

/**
 * Live test tulis IP address — verifikasi encoding interface 0xA.
 * Read-only kecuali add+remove satu alamat TEST 192.0.2.10/24 (rentang dokumentasi).
 * Usage: IpAddrWriteTestKt <host:port> <user> <pass>
 */
fun main(args: Array<String>) {
    if (args.size < 3) {
        println("Usage: IpAddrWriteTestKt <host:port> <user> <pass>")
        return
    }
    val (host, port) = args[0].split(":").let { it[0] to it[1].toInt() }
    val session = WinboxSession(host, port)
    try {
        session.connect()
        session.login(args[1], args[2])
        println("login OK")

        // Cari interface ether1 untuk target tes
        val ifaces = session.getInterfaceOptions()
        val target = ifaces.firstOrNull { it.name == "ether1" }
            ?: ifaces.firstOrNull()
            ?: error("tidak ada interface")
        println("target: ${target.name} (itemId=${target.index})")

        // 1. ADD 192.0.2.10/24
        val addRes = session.addIpAddressResult(
            IpAddressInput(address = "192.0.2.10/24", interfaceIdx = target.index, comment = "zz-wimb0x-test")
        )
        println("ADD: ok=${addRes.ok} err=${addRes.error}")

        // 2. Baca ulang — verifikasi mendarat di interface yang benar
        Thread.sleep(500)
        val rows = session.getIpAddresses()
        val found = rows.firstOrNull { it.address.startsWith("192.0.2.10/") }
        if (found != null) {
            println("READ-BACK: address=${found.address} iface=${found.interfaceName} (ref=${found.interfaceRef})")
            println("VERIFIKASI: ${if (found.interfaceName == target.name) "PASS — mendarat di ${target.name}" else "FAIL — mendarat di ${found.interfaceName}, target ${target.name}"}")
        } else {
            println("READ-BACK: FAIL — alamat tidak ditemukan")
        }

        // 3. REMOVE — bersihkan
        if (found != null) {
            val delRes = session.removeIpAddressResult(found.rowId)
            println("REMOVE: ok=${delRes.ok} err=${delRes.error}")
            Thread.sleep(500)
            val gone = session.getIpAddresses().none { it.address.startsWith("192.0.2.10/") }
            println("CLEANUP: ${if (gone) "PASS — terhapus" else "FAIL — masih ada"}")
        }
    } finally {
        session.disconnect()
    }
}
