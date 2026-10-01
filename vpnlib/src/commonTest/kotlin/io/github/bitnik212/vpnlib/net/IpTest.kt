package io.github.bitnik212.vpnlib.net

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class IpTest {
    @Test
    fun parsesAndFormatsIpv4() {
        assertEquals("10.0.0.1", IpAddress.parse("10.0.0.1").toString())
        assertNull(IpAddress.parseOrNull("256.0.0.1"))
        assertNull(IpAddress.parseOrNull("1.2.3"))
        assertNull(IpAddress.parseOrNull("example.com"))
    }

    @Test
    fun parsesAndFormatsIpv6Canonically() {
        assertEquals("2001:db8::1", IpAddress.parse("2001:0DB8:0:0:0:0:0:1").toString())
        assertEquals("::", IpAddress.parse("::").toString())
        assertEquals("::1", IpAddress.parse("::1").toString())
        assertEquals("fe80::1", IpAddress.parse("fe80::1%wlan0").toString())
        assertEquals("::ffff:c000:201", IpAddress.parse("::ffff:192.0.2.1").toString())
        assertEquals("2001:db8:0:1:1:1:1:1", IpAddress.parse("2001:db8:0:1:1:1:1:1").toString())
        assertNull(IpAddress.parseOrNull("1::2::3"))
        assertNull(IpAddress.parseOrNull("1:2:3:4:5:6:7:8:9"))
    }

    @Test
    fun prefixContainmentAndNetmask() {
        val net = IpPrefix.parse("10.1.2.3/8")
        assertEquals("10.0.0.0/8", net.network.toString())
        assertTrue(IpPrefix.parse("10.200.0.0/16") in net)
        assertFalse(IpPrefix.parse("11.0.0.0/16") in net)
        assertEquals("255.255.240.0", IpPrefix.parse("1.2.3.4/20").ipv4Netmask())
        assertEquals("0.0.0.0", IpPrefix.IPV4_DEFAULT.ipv4Netmask())
        assertEquals("1.2.3.4/32", IpPrefix.parse("1.2.3.4").toString())
        assertEquals("::1/128", IpPrefix.parse("::1").toString())
    }

    @Test
    fun endpointParsing() {
        assertEquals(Endpoint("vpn.example.com", 51820), Endpoint.parse("vpn.example.com:51820"))
        assertEquals(Endpoint("2001:db8::1", 443), Endpoint.parse("[2001:db8::1]:443"))
        assertEquals("[2001:db8::1]:443", Endpoint("2001:db8::1", 443).toString())
        assertNull(Endpoint.parseOrNull("2001:db8::1:443"))
        assertNull(Endpoint.parseOrNull("host:99999"))
    }

    @Test
    fun subtractsRoutes() {
        val routes = Routes.subtract(listOf(IpPrefix.IPV4_DEFAULT), listOf(IpPrefix.parse("10.0.0.0/8")))
        assertEquals(
            listOf(
                "0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4",
                "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1",
            ),
            routes.map { it.toString() },
        )
        assertEquals(emptyList(), Routes.subtract(listOf(IpPrefix.parse("10.1.0.0/16")), listOf(IpPrefix.parse("10.0.0.0/8"))))
    }

    @Test
    fun subtractingLocalNetworksKeepsEverythingElse() {
        val routes = Routes.subtract(listOf(IpPrefix.IPV4_DEFAULT, IpPrefix.IPV6_DEFAULT), Routes.LOCAL_NETWORKS)
        for (local in Routes.LOCAL_NETWORKS) {
            assertTrue(routes.none { it.overlaps(local) }, "$local must be excluded")
        }
        listOf("8.8.8.8", "1.1.1.1", "172.32.0.1", "2001:4860:4860::8888").forEach { ip ->
            assertTrue(routes.any { IpAddress.parse(ip) in it }, "$ip must stay routed")
        }
    }

    @Test
    fun normalizeDropsCoveredPrefixes() {
        val normalized = Routes.normalize(
            listOf("10.0.0.5/24", "10.0.0.0/8", "192.168.1.0/24", "10.0.0.0/8").map(IpPrefix::parse),
        )
        assertEquals(listOf("10.0.0.0/8", "192.168.1.0/24"), normalized.map { it.toString() })
    }
}
