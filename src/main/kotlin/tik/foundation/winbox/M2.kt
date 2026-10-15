package tik.foundation.winbox

import java.io.ByteArrayOutputStream
import java.io.EOFException

/**
 * Codec pesan M2 WinBox: `M2` + deretan field TLV.
 * Tiap field: `[key_lo][key_hi][namespace][type][value...]`.
 * Full key = (namespace shl 16) | (keyHi shl 8) | keyLo.
 *
 * Diverifikasi byte-per-byte terhadap contoh di referensi publik (PROTOCOL.md §6).
 */
object M2Ns {
    const val USER = 0x00
    const val SESSION = 0xFE
    const val SYSTEM = 0xFF
}

object M2Type {
    const val BOOL_FALSE = 0x00
    const val BOOL_TRUE = 0x01
    const val U32 = 0x08
    const val U8 = 0x09
    const val U64 = 0x10
    const val ADDR6 = 0x18
    const val STR_LONG = 0x20
    const val STR_SHORT = 0x21
    const val MSG_LONG = 0x28
    const val MSG_SHORT = 0x29
    const val MSG_LONG32 = 0x2A
    const val RAW_LONG = 0x30
    const val RAW_SHORT = 0x31
    const val U32_ARRAY = 0x88
    const val U64_ARRAY = 0x90
    const val ADDR6_ARRAY = 0x98
    const val STR_ARRAY = 0xA0
    const val MSG_ARRAY = 0xA8
    const val RAW_ARRAY = 0xB0
    const val U16_ARRAY = 0x80 // array u16 (mis. daftar port)
}

/** full key dari komponen. */
fun m2Key(keyLo: Int, ns: Int, keyHi: Int = 0): Int =
    (ns shl 16) or (keyHi shl 8) or keyLo

// ---- System keys (0xFF....) ----
const val K_SYS_TO = 0xFF0001
const val K_SYS_FROM = 0xFF0002
const val K_SYS_REQUEST = 0xFF0005
const val K_SYS_REQID = 0xFF0006
const val K_SYS_CMD = 0xFF0007
const val K_SYS_STATUS = 0xFF0008
const val K_SYS_ERROR = 0xFF0009

// ---- Session keys (0xFE....) ----
const val K_SESSION_ID = 0xFE0001

// ---- Perintah SYS_CMD ----
const val CMD_GET = 7 // capabilities / get data (jalur lama & terminal)
const val CMD_OPEN = 5 // open handler/session (jalur lama)
const val CMD_GET_ONE = 0xFE0002
const val CMD_SET = 0xFE0003
const val CMD_GET_ALL = 0xFE0004
const val CMD_ADD = 0xFE0005
const val CMD_REMOVE = 0xFE0006
const val CMD_MOVE = 0xFE0007
const val CMD_SETUP = 0xFE0008
const val CMD_GET_SINGLETON = 0xFE000D
const val CMD_SET_SINGLETON = 0xFE000E
const val CMD_SUBSCRIBE = 0xFE0012
const val CMD_UNSUBSCRIBE = 0xFE0013
const val CMD_LOGOUT = 0xFE0014
const val CMD_RESET = 0xFE0016
const val CMD_MEPTY_LOGIN = 0x0A0065
const val CMD_MEPTY_DATA = 0x0A0067

class M2Exception(msg: String) : Exception(msg)

sealed interface M2Value {
    data class Bool(val v: Boolean) : M2Value
    data class U8(val v: Int) : M2Value
    data class U32(val v: Long) : M2Value
    data class U64(val v: ULong) : M2Value
    data class Addr6(val b: ByteArray) : M2Value // tepat 16 byte
    data class Str(val s: String) : M2Value
    data class Raw(val b: ByteArray) : M2Value
    data class Embedded(val msg: M2Message) : M2Value
    data class U32Array(val vs: List<Long>) : M2Value
    data class U64Array(val vs: List<ULong>) : M2Value
    data class Addr6Array(val vs: List<ByteArray>) : M2Value // tiap 16 byte
    data class U16Array(val vs: List<Int>) : M2Value // mis. daftar port
    data class StrArray(val vs: List<String>) : M2Value
    data class RawArray(val vs: List<ByteArray>) : M2Value
    data class MsgArray(val vs: List<M2Message>) : M2Value
}

data class M2Field(val key: Int, val value: M2Value)

data class M2Message(val fields: List<M2Field>) {
    fun first(key: Int): M2Field? = fields.firstOrNull { it.key == key }
    fun bool(key: Int): Boolean? = (first(key)?.value as? M2Value.Bool)?.v
    fun u8(key: Int): Int? = (first(key)?.value as? M2Value.U8)?.v
    fun u32(key: Int): Long? = (first(key)?.value as? M2Value.U32)?.v
    fun u64(key: Int): ULong? = (first(key)?.value as? M2Value.U64)?.v
    fun str(key: Int): String? = (first(key)?.value as? M2Value.Str)?.s
    fun raw(key: Int): ByteArray? = (first(key)?.value as? M2Value.Raw)?.b
    fun u32Array(key: Int): List<Long>? = (first(key)?.value as? M2Value.U32Array)?.vs

    fun withField(f: M2Field): M2Message = M2Message(fields + f)

    fun encode(): ByteArray {
        val out = ByteArrayOutputStream()
        out.write('M'.code)
        out.write('2'.code)
        for (f in fields) {
            out.write(f.key and 0xFF)
            out.write((f.key shr 8) and 0xFF)
            out.write((f.key shr 16) and 0xFF)
            encodeValue(out, f.value)
        }
        return out.toByteArray()
    }

    companion object {
        fun decode(bytes: ByteArray): M2Message {
            if (bytes.size < 2 || bytes[0] != 'M'.code.toByte() || bytes[1] != '2'.code.toByte()) {
                throw M2Exception("bukan pesan M2")
            }
            val fields = mutableListOf<M2Field>()
            var pos = 2
            while (pos < bytes.size) {
                if (pos + 4 > bytes.size) throw M2Exception("header field terpotong")
                val keyLo = bytes[pos].toInt() and 0xFF
                val keyHi = bytes[pos + 1].toInt() and 0xFF
                val ns = bytes[pos + 2].toInt() and 0xFF
                val type = bytes[pos + 3].toInt() and 0xFF
                pos += 4
                val (v, next) = decodeValue(bytes, pos, type)
                fields += M2Field(m2Key(keyLo, ns, keyHi), v)
                pos = next
            }
            return M2Message(fields)
        }

        private fun decodeValue(b: ByteArray, pos: Int, type: Int): Pair<M2Value, Int> {
            fun need(n: Int) {
                if (pos + n > b.size) throw M2Exception("value terpotong (type $type)")
            }
            fun u16(): Int {
                need(2)
                return (b[pos].toInt() and 0xFF) or ((b[pos + 1].toInt() and 0xFF) shl 8)
            }
            fun u32(): Long {
                need(4)
                var v = 0L
                for (i in 0..3) v = v or ((b[pos + i].toLong() and 0xFF) shl (8 * i))
                return v
            }
            fun bytes(n: Int): ByteArray {
                need(n)
                return b.copyOfRange(pos, pos + n)
            }
            return when (type) {
                M2Type.BOOL_FALSE -> M2Value.Bool(false) to pos
                M2Type.BOOL_TRUE -> M2Value.Bool(true) to pos
                M2Type.U8 -> { need(1); M2Value.U8(b[pos].toInt() and 0xFF) to pos + 1 }
                M2Type.U32 -> M2Value.U32(u32()) to pos + 4
                M2Type.U64 -> {
                    need(8)
                    var v = 0UL
                    for (i in 0..7) v = v or ((b[pos + i].toULong() and 0xFFu) shl (8 * i))
                    M2Value.U64(v) to pos + 8
                }
                M2Type.ADDR6 -> M2Value.Addr6(bytes(16)) to pos + 16
                M2Type.STR_SHORT -> {
                    need(1)
                    val n = b[pos].toInt() and 0xFF
                    need(1 + n)
                    M2Value.Str(b.copyOfRange(pos + 1, pos + 1 + n).toString(Charsets.UTF_8)) to pos + 1 + n
                }
                M2Type.STR_LONG -> {
                    val n = u16()
                    M2Value.Str(b.copyOfRange(pos + 2, pos + 2 + n).toString(Charsets.UTF_8)) to pos + 2 + n
                }
                M2Type.RAW_SHORT -> {
                    need(1)
                    val n = b[pos].toInt() and 0xFF
                    need(1 + n)
                    M2Value.Raw(b.copyOfRange(pos + 1, pos + 1 + n)) to pos + 1 + n
                }
                M2Type.RAW_LONG -> {
                    val n = u16()
                    M2Value.Raw(b.copyOfRange(pos + 2, pos + 2 + n)) to pos + 2 + n
                }
                M2Type.MSG_SHORT, M2Type.MSG_LONG, M2Type.MSG_LONG32 -> {
                    val n = when (type) {
                        M2Type.MSG_SHORT -> { need(1); b[pos].toInt() and 0xFF }
                        M2Type.MSG_LONG -> u16()
                        else -> {
                            need(4)
                            var v = 0L
                            for (i in 0..3) v = v or ((b[pos + i].toLong() and 0xFF) shl (8 * i))
                            v.toInt()
                        }
                    }
                    val hdr = if (type == M2Type.MSG_SHORT) 1 else if (type == M2Type.MSG_LONG) 2 else 4
                    M2Value.Embedded(decode(b.copyOfRange(pos + hdr, pos + hdr + n))) to pos + hdr + n
                }
                M2Type.U16_ARRAY -> {
                    val c = u16()
                    need(2 + c * 2)
                    val vs = (0 until c).map { i ->
                        val p = pos + 2 + i * 2
                        (b[p].toInt() and 0xFF) or ((b[p + 1].toInt() and 0xFF) shl 8)
                    }
                    M2Value.U16Array(vs) to pos + 2 + c * 2
                }
                M2Type.U32_ARRAY -> {
                    val c = u16()
                    val vs = (0 until c).map { u32At(b, pos + 2 + it * 4) }
                    M2Value.U32Array(vs) to pos + 2 + c * 4
                }
                M2Type.U64_ARRAY -> {
                    val c = u16()
                    val vs = (0 until c).map { u64At(b, pos + 2 + it * 8) }
                    M2Value.U64Array(vs) to pos + 2 + c * 8
                }
                M2Type.ADDR6_ARRAY -> {
                    val c = u16()
                    val vs = (0 until c).map { b.copyOfRange(pos + 2 + it * 16, pos + 2 + it * 16 + 16) }
                    M2Value.Addr6Array(vs) to pos + 2 + c * 16
                }
                M2Type.STR_ARRAY, M2Type.RAW_ARRAY, M2Type.MSG_ARRAY -> {
                    val c = u16()
                    var p = pos + 2
                    val strs = mutableListOf<String>()
                    val raws = mutableListOf<ByteArray>()
                    val msgs = mutableListOf<M2Message>()
                    repeat(c) {
                        if (p + 2 > b.size) throw M2Exception("array terpotong")
                        val n = (b[p].toInt() and 0xFF) or ((b[p + 1].toInt() and 0xFF) shl 8)
                        val d = b.copyOfRange(p + 2, p + 2 + n)
                        when (type) {
                            M2Type.STR_ARRAY -> strs += d.toString(Charsets.UTF_8)
                            M2Type.RAW_ARRAY -> raws += d
                            else -> msgs += decode(d)
                        }
                        p += 2 + n
                    }
                    val v: M2Value = when (type) {
                        M2Type.STR_ARRAY -> M2Value.StrArray(strs)
                        M2Type.RAW_ARRAY -> M2Value.RawArray(raws)
                        else -> M2Value.MsgArray(msgs)
                    }
                    v to p
                }
                else -> {
                    val after = minOf(b.size, pos + 40)
                    val afterHex = b.copyOfRange(pos, after).joinToString("") { "%02x".format(it) }
                    throw M2Exception("tipe tak dikenal: 0x${type.toString(16)} after=[$afterHex]")
                }
            }
        }

        private fun u32At(b: ByteArray, p: Int): Long {
            var v = 0L
            for (i in 0..3) v = v or ((b[p + i].toLong() and 0xFF) shl (8 * i))
            return v
        }

        private fun u64At(b: ByteArray, p: Int): ULong {
            var v = 0UL
            for (i in 0..7) v = v or ((b[p + i].toULong() and 0xFFu) shl (8 * i))
            return v
        }
    }
}

private fun writeU16LE(out: ByteArrayOutputStream, v: Int) {
    out.write(v and 0xFF)
    out.write((v shr 8) and 0xFF)
}

private fun writeU32LE(out: ByteArrayOutputStream, v: Long) {
    for (i in 0..3) out.write(((v shr (8 * i)) and 0xFF).toInt())
}

private fun writeU64LE(out: ByteArrayOutputStream, v: ULong) {
    for (i in 0..7) out.write(((v shr (8 * i)) and 0xFFu).toInt())
}

private fun encodeValue(out: ByteArrayOutputStream, v: M2Value) {
    when (v) {
        is M2Value.Bool -> out.write(if (v.v) M2Type.BOOL_TRUE else M2Type.BOOL_FALSE)
        is M2Value.U8 -> {
            out.write(M2Type.U8)
            out.write(v.v and 0xFF)
        }
        is M2Value.U32 -> {
            out.write(M2Type.U32)
            writeU32LE(out, v.v)
        }
        is M2Value.U64 -> {
            out.write(M2Type.U64)
            writeU64LE(out, v.v)
        }
        is M2Value.Addr6 -> {
            require(v.b.size == 16)
            out.write(M2Type.ADDR6)
            out.write(v.b)
        }
        is M2Value.Str -> {
            val b = v.s.toByteArray(Charsets.UTF_8)
            if (b.size <= 255) {
                out.write(M2Type.STR_SHORT)
                out.write(b.size)
            } else {
                out.write(M2Type.STR_LONG)
                writeU16LE(out, b.size)
            }
            out.write(b)
        }
        is M2Value.Raw -> {
            if (v.b.size <= 255) {
                out.write(M2Type.RAW_SHORT)
                out.write(v.b.size)
            } else {
                out.write(M2Type.RAW_LONG)
                writeU16LE(out, v.b.size)
            }
            out.write(v.b)
        }
        is M2Value.Embedded -> {
            val inner = v.msg.encode()
            if (inner.size <= 255) {
                out.write(M2Type.MSG_SHORT)
                out.write(inner.size)
            } else {
                out.write(M2Type.MSG_LONG)
                writeU16LE(out, inner.size)
            }
            out.write(inner)
        }
        is M2Value.U16Array -> {
            out.write(M2Type.U16_ARRAY)
            writeU16LE(out, v.vs.size)
            v.vs.forEach {
                out.write(it and 0xFF)
                out.write((it shr 8) and 0xFF)
            }
        }
        is M2Value.U32Array -> {
            out.write(M2Type.U32_ARRAY)
            writeU16LE(out, v.vs.size)
            v.vs.forEach { writeU32LE(out, it) }
        }
        is M2Value.U64Array -> {
            out.write(M2Type.U64_ARRAY)
            writeU16LE(out, v.vs.size)
            v.vs.forEach { writeU64LE(out, it) }
        }
        is M2Value.Addr6Array -> {
            out.write(M2Type.ADDR6_ARRAY)
            writeU16LE(out, v.vs.size)
            v.vs.forEach {
                require(it.size == 16)
                out.write(it)
            }
        }
        is M2Value.StrArray -> {
            out.write(M2Type.STR_ARRAY)
            writeU16LE(out, v.vs.size)
            v.vs.forEach {
                val b = it.toByteArray(Charsets.UTF_8)
                writeU16LE(out, b.size)
                out.write(b)
            }
        }
        is M2Value.RawArray -> {
            out.write(M2Type.RAW_ARRAY)
            writeU16LE(out, v.vs.size)
            v.vs.forEach {
                writeU16LE(out, it.size)
                out.write(it)
            }
        }
        is M2Value.MsgArray -> {
            out.write(M2Type.MSG_ARRAY)
            writeU16LE(out, v.vs.size)
            v.vs.forEach {
                val b = it.encode()
                writeU16LE(out, b.size)
                out.write(b)
            }
        }
    }
}

// ---- Builder helpers ----

fun sysTo(vararg path: Int): M2Field =
    M2Field(K_SYS_TO, M2Value.U32Array(path.map { it.toLong() }))

fun sysFrom(vararg path: Int): M2Field =
    M2Field(K_SYS_FROM, M2Value.U32Array(path.map { it.toLong() }))

fun sysRequest(v: Boolean = true): M2Field =
    M2Field(K_SYS_REQUEST, M2Value.Bool(v))

fun sysReqId(id: Int): M2Field =
    M2Field(K_SYS_REQID, M2Value.U8(id))

fun sysCmd(cmd: Long): M2Field =
    if (cmd <= 255) M2Field(K_SYS_CMD, M2Value.U8(cmd.toInt()))
    else M2Field(K_SYS_CMD, M2Value.U32(cmd))

/** SYS_CMD sebagai u32 — dipakai alur legacy (sesuai referensi). */
fun sysCmd32(cmd: Long): M2Field =
    M2Field(K_SYS_CMD, M2Value.U32(cmd))

fun sysStatus(v: Int): M2Field =
    M2Field(K_SYS_STATUS, M2Value.U8(v))

fun sessionIdField(sid: Long): M2Field =
    if (sid <= 255) M2Field(K_SESSION_ID, M2Value.U8(sid.toInt()))
    else M2Field(K_SESSION_ID, M2Value.U32(sid))

fun userStr(id: Int, s: String): M2Field =
    M2Field(m2Key(id, M2Ns.USER), M2Value.Str(s))

fun userRaw(id: Int, b: ByteArray): M2Field =
    M2Field(m2Key(id, M2Ns.USER), M2Value.Raw(b))

fun userU8(id: Int, v: Int): M2Field =
    M2Field(m2Key(id, M2Ns.USER), M2Value.U8(v))

fun userU32(id: Int, v: Long): M2Field =
    M2Field(m2Key(id, M2Ns.USER), M2Value.U32(v))
