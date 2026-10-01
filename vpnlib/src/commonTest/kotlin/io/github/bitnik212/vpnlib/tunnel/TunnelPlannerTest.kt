package io.github.bitnik212.vpnlib.tunnel

import io.github.bitnik212.vpnlib.config.AWG_CONF
import io.github.bitnik212.vpnlib.config.ConfigException
import io.github.bitnik212.vpnlib.config.TunnelOptions
import io.github.bitnik212.vpnlib.config.VLESS_REALITY
import io.github.bitnik212.vpnlib.config.VpnProfile
import io.github.bitnik212.vpnlib.config.VpnProtocol
import io.github.bitnik212.vpnlib.config.WG_CONF
import io.github.bitnik212.vpnlib.config.wireguard.WgQuickFormat
import io.github.bitnik212.vpnlib.config.XrayConfig
import io.github.bitnik212.vpnlib.net.IpAddress
import io.github.bitnik212.vpnlib.net.IpPrefix
import io.github.bitnik212.vpnlib.net.Routes
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

class TunnelPlannerTest {
    private val resolved = mutableListOf<String>()
    private val planner = TunnelPlanner { host ->
        resolved += host
        when (host) {
            "vpn.example.com" -> listOf("2001:db8::1", "198.51.100.1")
            else -> error("unknown host $host")
        }
    }

    @Test
    fun plansWireGuard() = runTest {
        val plan = planner.plan(VpnProfile("wg", "Home", WgQuickFormat.parse(WG_CONF)))
        assertEquals(VpnProtocol.WIREGUARD, plan.protocol)
        assertEquals(listOf("vpn.example.com"), resolved)
        assertEquals("198.51.100.1", plan.remoteAddress)
        assertEquals(listOf("0.0.0.0/0", "::/0"), plan.routes.map { it.toString() })
        assertEquals(1420, plan.mtu)
        assertEquals(listOf("corp.example"), plan.searchDomains)
        val uapi = assertIs<EngineConfig.WireGuard>(plan.engine).uapi
        assertTrue("endpoint=198.51.100.1:51820" in uapi.lines())
    }

    @Test
    fun appliesTunnelOptions() = runTest {
        val profile = VpnProfile(
            "awg",
            "Amnezia",
            WgQuickFormat.parse(AWG_CONF),
            TunnelOptions(
                allowLanAccess = true,
                excludedRoutes = listOf(IpPrefix.parse("203.0.113.0/24")),
                dnsServers = listOf("9.9.9.9"),
                mtu = 1380,
                excludedApplications = listOf("com.example.bank"),
            ),
        )
        val plan = planner.plan(profile)
        assertEquals(VpnProtocol.AMNEZIA_WG, plan.protocol)
        assertTrue(resolved.isEmpty(), "IP endpoints are not resolved")
        assertEquals(listOf("9.9.9.9"), plan.dnsServers)
        assertEquals(1380, plan.mtu)
        assertEquals(listOf("com.example.bank"), plan.excludedApplications)
        (Routes.LOCAL_NETWORKS.filter { it.isIpv4 } + IpPrefix.parse("203.0.113.0/24")).forEach { excluded ->
            assertTrue(plan.routes.none { it.overlaps(excluded) }, "$excluded must not be routed")
        }
        assertTrue(plan.routes.any { IpAddress.parse("8.8.8.8") in it })
    }

    @Test
    fun plansXray() = runTest {
        val plan = planner.plan(VpnProfile("x", "Xray", XrayConfig.fromShareLink(VLESS_REALITY)))
        assertEquals("198.51.100.1", plan.remoteAddress)
        assertEquals(listOf("0.0.0.0/0", "::/0"), plan.routes.map { it.toString() })
        assertEquals(XrayConfig.DEFAULT_TUN_ADDRESSES, plan.addresses)
        val json = assertIs<EngineConfig.Xray>(plan.engine).json
        assertTrue("\"198.51.100.1\"" in json)

        val ipv4Only = planner.plan(VpnProfile("x", "Xray", XrayConfig.fromShareLink(VLESS_REALITY).copy(ipv6 = false)))
        assertEquals(listOf("0.0.0.0/0"), ipv4Only.routes.map { it.toString() })
        assertTrue(ipv4Only.addresses.all { it.isIpv4 })
    }

    @Test
    fun failsOnInvalidConfigOrResolution() = runTest {
        assertFailsWith<ConfigException> { planner.plan(VpnProfile("x", "Xray", XrayConfig())) }
        val unknown = XrayConfig.fromShareLink(VLESS_REALITY.replace("vpn.example.com", "nope.example.com"))
        assertFailsWith<VpnException> { planner.plan(VpnProfile("x", "Xray", unknown)) }
    }
}
