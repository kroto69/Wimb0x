package tik.foundation

import tik.foundation.winbox.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Test TAHAP 1-2 — 🟡 (offline, tanpa router).
 */
class Tahap12Test {

    // ---------- RouterVersion ----------

    @Test fun `parse v7 dengan channel`() {
        val v = RouterVersion.parse("7.24.4 (stable)")
        assertEquals(7, v?.major)
        assertEquals(24, v?.minor)
        assertEquals(4, v?.patch)
        assertTrue(v?.isV7 == true)
    }

    @Test fun `parse v6 polos`() {
        val v = RouterVersion.parse("6.49.19")
        assertEquals(6, v?.major)
        assertTrue(v?.isV6 == true)
    }

    @Test fun `parse gagal return null`() {
        assertNull(RouterVersion.parse(null))
        assertNull(RouterVersion.parse(""))
        assertNull(RouterVersion.parse("bukan-versi"))
    }

    // ---------- netmaskU32ToPrefix ----------

    @Test fun `netmask 16777215 jadi 24`() {
        assertEquals(24, netmaskU32ToPrefix(16777215))
    }

    @Test fun `netmask ffffff00 jadi 24`() {
        assertEquals(24, netmaskU32ToPrefix(0xFFFFFF00))
    }

    @Test fun `netmask ffff0000 jadi 16`() {
        assertEquals(16, netmaskU32ToPrefix(0xFFFF0000))
    }

    // ---------- FieldKey ----------

    private fun msg(vararg fields: M2Field) = M2Message(fields.toList())

    @Test fun `FieldKey coba v7 dulu`() {
        val row = msg(
            M2Field(0x1, M2Value.Str("v7name")),
            M2Field(0xFE0009, M2Value.Str("v6name")),
        )
        assertEquals("v7name", row.str(VersionedKeys.PPP_NAME))
    }

    @Test fun `FieldKey fallback v6`() {
        val row = msg(
            M2Field(0xFE0009, M2Value.Str("v6name")),
        )
        assertEquals("v6name", row.str(VersionedKeys.PPP_NAME))
    }

    @Test fun `FieldKey null bila tidak ada`() {
        val row = msg()
        assertNull(row.str(VersionedKeys.PPP_NAME))
    }

    // ---------- parsePppActiveRow v7 vs v6 ----------

    @Test fun `parse PPP active v7-style (name di 0x1)`() {
        val row = msg(
            M2Field(0xFE0001, M2Value.U8(5)),
            M2Field(0x1, M2Value.Str("user1")),
            M2Field(0x3, M2Value.Str("AA:BB:CC:DD:EE:FF")),
            M2Field(0x9, M2Value.U64(1000u)),
            M2Field(0xA, M2Value.U64(2000u)),
        )
        val p = parsePppActiveRow(row)!!
        assertEquals("user1", p.name)
        assertEquals(1000L, p.bytesA)
        assertEquals(2000L, p.bytesB)
        // Arah tidak disimpulkan
        assertNull(PppActive.BYTES_A_IS_DOWN)
    }

    @Test fun `parse PPP active v6-style (name di 0xFE0009)`() {
        val row = msg(
            M2Field(0xFE0009, M2Value.Str("v6user")),
            M2Field(0xFE0001, M2Value.U8(6)),
        )
        val p = parsePppActiveRow(row)!!
        assertEquals("v6user", p.name)
    }

    // ---------- parseQueueRow v7 vs v6 ----------

    @Test fun `parse queue v7-style (u64 rate)`() {
        val row = msg(
            M2Field(0xFE0001, M2Value.U8(1)),
            M2Field(0x2, M2Value.Str("q1")),
            M2Field(0xD8, M2Value.U64(1000000u)),
            M2Field(0x13C, M2Value.U64(2000000u)),
        )
        val q = parseQueueRow(row)!!
        assertEquals("q1", q.name)
        assertEquals(1000000L, q.maxUpBps)
        assertEquals(2000000L, q.maxDownBps)
    }

    @Test fun `parse queue v6-style (u32 rate)`() {
        val row = msg(
            M2Field(0xFE0001, M2Value.U8(1)),
            M2Field(0x2, M2Value.Str("q1")),
            M2Field(0x3C, M2Value.U32(500000)),
            M2Field(0x47, M2Value.U32(1000000)),
        )
        val q = parseQueueRow(row)!!
        assertEquals(500000L, q.maxUpBps)
        assertEquals(1000000L, q.maxDownBps)
    }

    // ---------- WriteResult ----------

    @Test fun `toWriteResult Ok bila kode 0`() {
        val resp = msg(
            M2Field(0xFF0008, M2Value.U8(0)),
            M2Field(0xFE0001, M2Value.U8(42)),
        )
        val r = resp.toWriteResult()
        assertTrue(r is WriteResult.Ok)
    }

    @Test fun `toWriteResult Err bila kode non-nol`() {
        val resp = msg(
            M2Field(0xFF0008, M2Value.U8(6)),
            M2Field(0xFF0009, M2Value.Str("invalid user")),
        )
        val r = resp.toWriteResult()
        assertTrue(r is WriteResult.Err)
        assertEquals(6, (r as WriteResult.Err).code)
        assertEquals("invalid user", r.message)
    }

    @Test fun `writeCatching tangkap exception jadi Err`() {
        val r = writeCatching { throw RuntimeException("boom") }
        assertTrue(r is WriteResult.Err)
        assertEquals("boom", (r as WriteResult.Err).message)
    }

    @Test fun `writeCatching null jadi Timeout`() {
        val r = writeCatching { null }
        assertTrue(r is WriteResult.Timeout)
    }

    // ---------- ServiceRow toleran tipe ----------

    @Test fun `parse service toleran str`() {
        val row = msg(
            M2Field(0xFE0001, M2Value.U8(1)),
            M2Field(0x1, M2Value.Str("www")),
            M2Field(0x2, M2Value.U32(80)),
        )
        val s = parseServiceRow(row)!!
        assertEquals("www", s.name)
        assertEquals(80, s.port)
    }

    @Test fun `parse service toleran uint`() {
        val row = msg(
            M2Field(0xFE0001, M2Value.U8(1)),
            M2Field(0x1, M2Value.U8(5)),
            M2Field(0x2, M2Value.U8(80)),
        )
        val s = parseServiceRow(row)!!
        assertEquals("5", s.name) // uint → string
        assertEquals(80, s.port)
    }

    // ---------- helpers ----------

    @Test fun `ipU32ToString`() {
        // 192.168.88.1 octet-LSB = 0x0158A8C0
        assertEquals("192.168.88.1", ipU32ToString(0x0158A8C0))
    }

    @Test fun `macToString`() {
        val mac = byteArrayOf(0xDC.toByte(), 0x2C, 0x6E, 0x66, 0x44, 0x61)
        assertEquals("DC:2C:6E:66:44:61", macToString(mac))
    }
}
