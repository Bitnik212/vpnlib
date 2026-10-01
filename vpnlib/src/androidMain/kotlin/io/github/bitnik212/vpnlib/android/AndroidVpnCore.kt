package io.github.bitnik212.vpnlib.android

import io.github.bitnik212.vpnlib.android.internal.NativeCore
import io.github.bitnik212.vpnlib.tunnel.VpnCore
import io.github.bitnik212.vpnlib.tunnel.VpnException

/** [VpnCore] backed by libvpncore.so. */
public object AndroidVpnCore : VpnCore {

    /** Installs the socket protector used by both engines (normally the VpnService). */
    public fun setProtector(protector: SocketProtector?): Unit = NativeCore.setProtector(protector)

    /** DNS servers (IP literals) the engines use to resolve hostnames inside their configs. */
    public fun setDnsServers(servers: List<String>): Unit = NativeCore.setDnsServers(servers.joinToString(","))

    override fun wireGuardStart(tunFd: Int, uapiConfig: String): Int =
        checkHandle(NativeCore.awgTurnOn(tunFd, uapiConfig), "WireGuard")

    override fun wireGuardStop(handle: Int): Unit = NativeCore.awgTurnOff(handle)

    override fun wireGuardGetConfig(handle: Int): String? = NativeCore.awgGetConfig(handle)

    override fun xrayStart(tunFd: Int, jsonConfig: String): Int =
        checkHandle(NativeCore.xrayStart(tunFd, jsonConfig), "Xray")

    override fun xrayStop(handle: Int): Unit = NativeCore.xrayStop(handle)

    override fun xrayGetStats(handle: Int): String? = NativeCore.xrayGetStats(handle)

    override fun version(): String = NativeCore.version()

    private fun checkHandle(handle: Int, engine: String): Int {
        if (handle < 0) throw VpnException("$engine failed to start: ${NativeCore.lastError() ?: "unknown error"}")
        return handle
    }
}
