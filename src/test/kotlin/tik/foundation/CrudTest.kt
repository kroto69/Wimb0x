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
import tik.foundation.winbox.parseNetwork
import tik.foundation.winbox.prefixToNetmaskU32
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
    check("ipaddr address u32", ia.u32(IpAddrFields.ADDRESS) == ipToU32("192.168.88.1"))
    check("ipaddr netmask u32", ia.u32(IpAddrFields.NETMASK) == 16777215L)
    check("ipaddr iface u8", ia.u8(IpAddrFields.INTERFACE) == 2)
    check("parseNetwork", parseNetwork("10.0.0.1/8") == ("10.0.0.1" to 8))
    check("netmask /32", prefixToNetmaskU32(32) == 4294967295L)
    check("netmask /0", prefixToNetmaskU32(0) == 0L)

    // ---- IP Route ----
    val ir = IpRouteInput(dst = "0.0.0.0/0", gateway = "192.168.88.1", distance = 1L).toFields()
    check("route dst", ir.str(IpRouteFields.DST) == "0.0.0.0/0")
    val irGw = ir.firstOrNull { it?.key == IpRouteFields.GATEWAY }?.value as? M2Value.MsgArray
    check("route gw msgarr", irGw != null && irGw.vs.size == 1)
    check("route distance", ir.u32(IpRouteFields.DISTANCE) == 1L)

    // ---- Firewall ----
    val fw = FwRuleInput(chain = "forward", action = 0, srcAddress = "192.168.88.0/24",
        protocol = "tcp", dstPort = "80,443", comment = "web", disabled = false).toFilterFields()
    check("fw chain", fw.str(0x27) == "forward")
    check("fw action u8", fw.u8(0x28) == 0)
    check("fw src-addr", fw.str(0x1A2) == "192.168.88.0/24")

    // ---- Queue ----
    val q = QueueInput(name = "warnet-01", target = "192.168.90.21/32",
        dstAddress = "192.168.90.21/32", parent = 0,
        upMaxBps = 20_000_000L, downMaxBps = 20_000_000L, priority = 8).toFields()
    check("queue name", q.str(QueueFields.NAME) == "warnet-01")
    val qTarget = q.firstOrNull { it?.key == QueueFields.TARGET }?.value as? M2Value.MsgArray
    check("queue target msgarr", qTarget != null && qTarget.vs.size == 1)
    val qTgtIp = qTarget?.vs?.firstOrNull()?.fields?.firstOrNull { it.key == 0x1 }?.value as? M2Value.U32
    check("queue target ip", qTgtIp?.v == ipToU32("192.168.90.21"))
    check("queue dst", q.str(QueueFields.DST) == "192.168.90.21/32")
    check("queue parent", q.u8(QueueFields.PARENT) == 0)
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
    check("hsbinding addr u32", hb.u32(0x7) == ipToU32("192.168.10.5"))

    // ---- Netwatch ----
    val nw = NetwatchInput(host = "8.8.8.8", name = "google-dns",
        intervalSec = 60L, timeoutMs = 1000L).toFields()
    check("netwatch host u32", nw.u32(NetwatchFields.HOST) == ipToU32("8.8.8.8"))
    check("netwatch interval u8", nw.u8(NetwatchFields.INTERVAL) == 60)

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
