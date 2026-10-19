import tik.foundation.winbox.*

// Test getSfpInfo native.
fun main(args: Array<String>) {
    val (host, port) = args[0].split(":").let { it[0] to it[1].toInt() }
    val sess = WinboxSession(host, port, connectTimeoutMs = 8000)
    sess.connect()
    sess.login(args[1], args[2])
    try {
        val info = sess.getSfpInfo("sfp-sfpplus1")
        if (info == null) {
            println("SFP info null")
            return
        }
        println("Vendor: ${info.vendorName} ${info.vendorPartNumber}")
        println("Serial: ${info.vendorSerial}")
        println("Wavelength: ${info.wavelength}")
        println("Link: ${info.linkLengthSm}")
        println("Temp: ${info.temperatureC}°C")
        println("Voltage: ${info.supplyVoltageV}V")
        println("Tx bias: ${info.txBiasCurrentMa}mA")
        println("Tx power: ${info.txPowerDbm}dBm")
        println("Rx power: ${info.rxPowerDbm}dBm")
        println("Rx loss: ${info.rxLoss}, Tx fault: ${info.txFault}")
    } finally {
        sess.close()
    }
}
