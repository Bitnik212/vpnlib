package io.github.bitnik212.vpnlib.tunnel

import io.github.bitnik212.vpnlib.config.VpnProtocol
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull

class TunnelSessionTest {
    private class FakeCore : VpnCore {
        val calls = mutableListOf<String>()
        override fun wireGuardStart(tunFd: Int, uapiConfig: String): Int = 7.also { calls += "wg-start:$tunFd" }
        override fun wireGuardStop(handle: Int) { calls += "wg-stop:$handle" }
        override fun wireGuardGetConfig(handle: Int): String = "public_key=${"02".repeat(32)}\nrx_bytes=10\ntx_bytes=20\n"
        override fun xrayStart(tunFd: Int, jsonConfig: String): Int = 3.also { calls += "xray-start:$tunFd" }
        override fun xrayStop(handle: Int) { calls += "xray-stop:$handle" }
        override fun xrayGetStats(handle: Int): String = "uplink=5\ndownlink=9\n"
        override fun version(): String = "fake"
    }

    private fun plan(engine: EngineConfig) = TunnelPlan(
        profileId = "p",
        sessionName = "p",
        protocol = VpnProtocol.XRAY,
        addresses = emptyList(),
        routes = emptyList(),
        excludedRoutes = emptyList(),
        dnsServers = emptyList(),
        searchDomains = emptyList(),
        mtu = 1500,
        includedApplications = emptyList(),
        excludedApplications = emptyList(),
        allowBypass = false,
        metered = false,
        remoteAddress = "1.2.3.4",
        engine = engine,
    )

    @Test
    fun drivesWireGuardEngine() {
        val core = FakeCore()
        val session = TunnelSession.start(core, plan(EngineConfig.WireGuard("x")), tunFd = 42)
        assertEquals(TunnelStatistics(10, 20, peers = session.statistics()!!.peers), session.statistics())
        session.stop()
        session.stop()
        assertFalse(session.isRunning)
        assertNull(session.statistics())
        assertEquals(listOf("wg-start:42", "wg-stop:7"), core.calls)
    }

    @Test
    fun drivesXrayEngine() {
        val core = FakeCore()
        val session = TunnelSession.start(core, plan(EngineConfig.Xray("{}")), tunFd = 5)
        assertEquals(TunnelStatistics(rxBytes = 9, txBytes = 5), session.statistics())
        session.stop()
        assertEquals(listOf("xray-start:5", "xray-stop:3"), core.calls)
    }
}
