package tik.foundation

import tik.foundation.winbox.FwRuleInput
import tik.foundation.winbox.HsBindingInput
import tik.foundation.winbox.HsServerInput
import tik.foundation.winbox.HsUserInput
import tik.foundation.winbox.InterfaceFields
import tik.foundation.winbox.IpAddrFields
import tik.foundation.winbox.IpAddressInput
import tik.foundation.winbox.IpRouteFields
import tik.foundation.winbox.IpRouteInput
import tik.foundation.winbox.IpServiceFields
import tik.foundation.winbox.M2Field
import tik.foundation.winbox.M2Value
import tik.foundation.winbox.NetwatchFields
import tik.foundation.winbox.NetwatchInput
import tik.foundation.winbox.PppProfileFields
import tik.foundation.winbox.PppProfileInput
import tik.foundation.winbox.PppSecretFields
import tik.foundation.winbox.PppSecretInput
import tik.foundation.winbox.QueueFields
import tik.foundation.winbox.QueueInput
import tik.foundation.winbox.WinboxPaths
import tik.foundation.winbox.ipToU32
import tik.foundation.winbox.parseRateToBps
import tik.foundation.winbox.toFields
import tik.foundation.winbox.toFilterFields

private var failures = 0

private fun check(name: String, cond: Boolean) {
    if (cond) println("PASS: $name")
    else { println("FAIL: $name"); failures++ }
}

private fun Array<M2Field?>.str(key: Int): String? =
    firstOrNull { it?.key == key }?.value?.let { (it as? M2Value.Str)?.s }

private fun Array<M2Field?>.bool(key: Int): Boolean? =
    firstOrNull { it?.key == key }?.value?.let { (it as? M2Value.Bool)?.v }

private fun Array<M2Field?>.u8(key: Int): Int? =
    firstOrNull { it?.key == key }?.value?.let { (it as? M2Value.U8)?.v }

private fun Array<M2Field?>.u32(key: Int): Long? =
    firstOrNull { it?.key == key }?.value?.let { (it as? M2Value.U32)?.v }

fun main() {
    // ---- parseRateToBps ----
    check("rate 20M", parseRateToBps("20M") == 20_000_000L)
    check("rate 512K", parseRateToBps("512K") == 512_000L)
    check("rate 1G", parseRateToBps("1G") == 1_000_000_000L)
    check("rate plain", parseRateToBps("1500") == 1500L)

    // ---- PPP Secret ----
    val ps = PppSecretInput(name = "budi", password = "rahasia", service = 3,
        profileId = 5L, callerId = "AA:BB:CC:DD:EE:FF", comment = "test", disabled = false).toFields()
    check("ppp-secret name", ps.str(PppSecretFields.NAME) == "budi")
    check("ppp-secret password", ps.str(PppSecretFields.PASSWORD) == "rahasia")
    check("ppp-secret service u8", ps.u8(PppSecretFields.SERVICE) == 3)
    check("ppp-secret profile u32", ps.u32(PppSecretFields.PROFILE) == 5L)
    check("ppp-secret disabled bool", ps.bool(PppSecretFields.DISABLED) == false)
    check("ppp-secret null-skipped", PppSecretInput(name = "x").toFields().filterNotNull().size == 1)

    // ---- PPP Profile (NAME=0x1 fix) ----
    val pp = PppProfileInput(name = "paket-10m", comment = "c").toFields()
    check("ppp-profile name key 0x1", pp.str(0x1) == "paket-10m")
    check("ppp-profile const", PppProfileFields.NAME == 0x1)

    // ---- IP Address ----
    val ia = IpAddressInput(address = "192.168.88.1/24", interfaceIdx = 2, disabled = true).toFields()
    check("ipaddr address str", ia.str(IpAddrFields.ADDRESS) == "192.168.88.1/24")
    check("ipaddr iface u8", ia.u8(IpAddrFields.INTERFACE) == 2)

    // ---- IP Route ----
    val ir = IpRouteInput(dst = "0.0.0.0/0", gateway = "192.168.88.1", distance = 1L).toFields()
    check("route dst", ir.str(IpRouteFields.DST) == "0.0.0.0/0")
    check("route gw u32", ir.u32(IpRouteFields.GATEWAY) == ipToU32("192.168.88.1"))
    check("route distance", ir.u32(IpRouteFields.DISTANCE) == 1L)

    // ---- Firewall ----
    val fw = FwRuleInput(chain = "forward", action = 0, srcAddress = "192.168.88.0/24",
        protocol = "tcp", dstPort = "80,443", comment = "web", disabled = false).toFilterFields()
    check("fw chain", fw.str(0x27) == "forward")
    check("fw action u8", fw.u8(0x28) == 0)
    check("fw src-addr", fw.str(0x1A2) == "192.168.88.0/24")

    // ---- Queue ----
    val q = QueueInput(name = "warnet-01", target = "192.168.90.21/32",
        upMaxBps = 20_000_000L, downMaxBps = 20_000_000L, priority = 8).toFields()
    check("queue name", q.str(QueueFields.NAME) == "warnet-01")
    check("queue target", q.str(QueueFields.TARGET) == "192.168.90.21/32")
    check("queue up-max", q.u32(QueueFields.UP_MAX) == 20_000_000L)
    check("queue prio", q.u8(QueueFields.UP_PRIORITY) == 8)

    // ---- Hotspot User/Server/Binding ----
    val hu = HsUserInput(name = "tamu", password = "tamu123", profileId = 1L).toFields()
    check("hsuser name", hu.str(0x1) == "tamu")
    check("hsuser pass", hu.str(0x2) == "tamu123")
    val hs = HsServerInput(name = "hs1", interfaceIdx = 3).toFields()
    check("hsserver name", hs.str(0x10) == "hs1")
    val hb = HsBindingInput(mac = "AA:BB:CC:DD:EE:FF", address = "192.168.10.5", type = 1).toFields()
    check("hsbinding mac", hb.str(0x1) == "AA:BB:CC:DD:EE:FF")

    // ---- Netwatch ----
    val nw = NetwatchInput(host = "8.8.8.8", name = "google-dns",
        intervalSec = 60L, timeoutMs = 1000L).toFields()
    check("netwatch host u32", nw.u32(NetwatchFields.HOST) == ipToU32("8.8.8.8"))
    check("netwatch interval", nw.u32(NetwatchFields.INTERVAL) == 60L)

    // ---- Paths ----
    check("path ppp-secret", WinboxPaths.PPP_SECRET == listOf(27, 101))
    check("path ppp-profile", WinboxPaths.PPP_PROFILE == listOf(27, 102))
    check("path iface", WinboxPaths.INTERFACE == listOf(20, 0))
    check("path ipaddr", WinboxPaths.IP_ADDRESS == listOf(20, 1))

    // ---- InterfaceFields dari dump v7 ----
    check("iface name key", InterfaceFields.NAME == 0x10006)
    check("iface comment/disabled session-ns",
        InterfaceFields.COMMENT == 0xFE0009 && InterfaceFields.DISABLED == 0xFE000A)
    check("ipsvc port key", IpServiceFields.PORT == 0x2)

    println(if (failures == 0) "ALL CRUD TESTS PASSED" else "$failures FAILURES")
    if (failures > 0) kotlin.system.exitProcess(1)
}
