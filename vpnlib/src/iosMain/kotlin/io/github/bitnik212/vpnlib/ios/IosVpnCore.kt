package io.github.bitnik212.vpnlib.ios

import io.github.bitnik212.vpnlib.ios.cinterop.vpncoreAwgBumpSockets
import io.github.bitnik212.vpnlib.ios.cinterop.vpncoreAwgGetConfig
import io.github.bitnik212.vpnlib.ios.cinterop.vpncoreAwgTurnOff
import io.github.bitnik212.vpnlib.ios.cinterop.vpncoreAwgTurnOn
import io.github.bitnik212.vpnlib.ios.cinterop.vpncoreFree
import io.github.bitnik212.vpnlib.ios.cinterop.vpncoreLastError
import io.github.bitnik212.vpnlib.ios.cinterop.vpncoreSetLogger
import io.github.bitnik212.vpnlib.ios.cinterop.vpncoreSetMemoryLimit
import io.github.bitnik212.vpnlib.ios.cinterop.vpncoreVersion
import io.github.bitnik212.vpnlib.ios.cinterop.vpncoreXrayGetStats
import io.github.bitnik212.vpnlib.ios.cinterop.vpncoreXrayStart
import io.github.bitnik212.vpnlib.ios.cinterop.vpncoreXrayStop
import io.github.bitnik212.vpnlib.tunnel.VpnCore
import io.github.bitnik212.vpnlib.tunnel.VpnException
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.staticCFunction
import kotlinx.cinterop.toKString
import platform.Foundation.NSLog

/**
 * [VpnCore] backed by libvpncore.a (VpnCore.xcframework). Used inside the
 * Network Extension process.
 */
public object IosVpnCore : VpnCore {

    init {
        vpncoreSetLogger(staticCFunction(::logFromCore))
    }

    /**
     * Soft memory limit of the Go runtime. Packet tunnel extensions are
     * killed above ~50 MB, so keep this well below.
     */
    public fun setMemoryLimit(bytes: Long): Unit = vpncoreSetMemoryLimit(bytes)

    /** Re-binds WireGuard sockets after a network path change. */
    public fun wireGuardBumpSockets(handle: Int): Unit = vpncoreAwgBumpSockets(handle)

    override fun wireGuardStart(tunFd: Int, uapiConfig: String): Int =
        checkHandle(vpncoreAwgTurnOn(tunFd, uapiConfig), "WireGuard")

    override fun wireGuardStop(handle: Int): Unit = vpncoreAwgTurnOff(handle)

    override fun wireGuardGetConfig(handle: Int): String? = takeString(vpncoreAwgGetConfig(handle))

    override fun xrayStart(tunFd: Int, jsonConfig: String): Int =
        checkHandle(vpncoreXrayStart(tunFd, jsonConfig), "Xray")

    override fun xrayStop(handle: Int): Unit = vpncoreXrayStop(handle)

    override fun xrayGetStats(handle: Int): String? = takeString(vpncoreXrayGetStats(handle))

    override fun version(): String = takeString(vpncoreVersion()) ?: "unknown"

    private fun checkHandle(handle: Int, engine: String): Int {
        if (handle < 0) {
            throw VpnException("$engine failed to start: ${takeString(vpncoreLastError()) ?: "unknown error"}")
        }
        return handle
    }

    private fun takeString(pointer: CPointer<ByteVar>?): String? {
        if (pointer == null) return null
        val value = pointer.toKString()
        vpncoreFree(pointer)
        return value
    }
}

private fun logFromCore(level: Int, tag: CPointer<ByteVar>?, message: CPointer<ByteVar>?) {
    val levelName = when (level) {
        0 -> "D"
        1 -> "I"
        2 -> "W"
        else -> "E"
    }
    NSLog("%@", "[$levelName/${tag?.toKString()}] ${message?.toKString()}")
}
