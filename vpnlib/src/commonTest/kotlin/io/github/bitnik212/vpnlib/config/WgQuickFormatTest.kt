package io.github.bitnik212.vpnlib.config

import io.github.bitnik212.vpnlib.config.AmneziaWgConfig
import io.github.bitnik212.vpnlib.config.wireguard.WgKey
import io.github.bitnik212.vpnlib.config.wireguard.WgQuickFormat
import io.github.bitnik212.vpnlib.config.wireguard.WgUapi
import io.github.bitnik212.vpnlib.config.WireGuardConfig
import io.github.bitnik212.vpnlib.net.Endpoint
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

internal const val KEY1 = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
internal const val KEY2 = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
internal const val KEY3 = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="

internal val WG_CONF = """
    [Interface]
    PrivateKey = $KEY1
    Address = 10.8.0.2/32, fd00::2/128
    DNS = 1.1.1.1, 2606:4700:4700::1111, corp.example
    MTU = 1420
    PostUp = iptables -A FORWARD  # ignored wg-quick key

    [Peer]
    PublicKey = $KEY2
    PresharedKey = $KEY3
    AllowedIPs = 0.0.0.0/0, ::/0
    Endpoint = vpn.example.com:51820
    PersistentKeepalive = 25
""".trimIndent()

internal val AWG_CONF = """
    [Interface]
    PrivateKey = $KEY1
    Address = 10.8.1.2/32
    Jc = 4
    Jmin = 40
    Jmax = 70
    S1 = 15
    S2 = 68
    H1 = 1106457265
    H2 = 249455488
    H3 = 1209847463
    H4 = 1646644382
    I1 = <b 0xc6000000010843290a47ba8ba2ed000044d0e3efd9326adb60561baa3bc4b52471b2d459ddcc9a508dffddc97e4eb8><r 20>

    [Peer]
    PublicKey = $KEY2
    AllowedIPs = 0.0.0.0/0
    Endpoint = 203.0.113.7:4443
""".trimIndent()

class WgQuickFormatTest {
    @Test
    fun parsesWireGuard() {
        val config = assertIs<WireGuardConfig>(WgQuickFormat.parse(WG_CONF))
        config.validate()
        assertEquals(listOf("10.8.0.2/32", "fd00::2/128"), config.iface.addresses.map { it.toString() })
        assertEquals(listOf("1.1.1.1", "2606:4700:4700::1111"), config.iface.dnsServers)
        assertEquals(listOf("corp.example"), config.iface.dnsSearchDomains)
        assertEquals(1420, config.iface.mtu)
        val peer = config.peers.single()
        assertEquals(Endpoint("vpn.example.com", 51820), peer.endpoint)
        assertEquals(25, peer.persistentKeepalive)
        assertNull(config.amneziaParams)
    }

    @Test
    fun parsesAmneziaWg() {
        val config = assertIs<AmneziaWgConfig>(WgQuickFormat.parse(AWG_CONF))
        config.validate()
        assertEquals(4, config.amnezia.jc)
        assertEquals("1106457265", config.amnezia.h1)
        assertTrue(config.amnezia.i1!!.startsWith("<b 0xc6"))
    }

    @Test
    fun roundTripsThroughText() {
        listOf(WG_CONF, AWG_CONF).forEach { text ->
            val parsed = WgQuickFormat.parse(text)
            assertEquals(parsed, WgQuickFormat.parse(parsed.toWgQuick()))
        }
    }

    @Test
    fun rejectsUnknownKeysAndBadValues() {
        assertFailsWith<ConfigException> { WgQuickFormat.parse("[Interface]\nPrivateKey = $KEY1\nFoo = 1") }
        assertFailsWith<ConfigException> { WgQuickFormat.parse("[Peer]\nPublicKey = $KEY2") }
        assertFailsWith<ConfigException> {
            WgQuickFormat.parse("[Interface]\nPrivateKey = $KEY1\nAddress = 10.0.0.300/32")
        }
    }

    @Test
    fun validationReportsProblems() {
        val bad = WgQuickFormat.parse(AWG_CONF.replace("S2 = 68", "S2 = 71").replace("Jmin = 40", "Jmin = 90"))
        val error = assertFailsWith<ConfigException> { bad.validate() }
        assertTrue("S1 + 56" in error.message!!)
        assertTrue("Jmin" in error.message!!)
        assertFailsWith<ConfigException> { WgQuickFormat.parse(WG_CONF.replace(KEY2, "short")).validate() }
    }

    @Test
    fun buildsUapi() {
        val config = WgQuickFormat.parse(WG_CONF)
        val uapi = WgUapi.build(
            config,
            mapOf(Endpoint("vpn.example.com", 51820) to Endpoint("198.51.100.1", 51820)),
        )
        val expected = """
            private_key=${"01".repeat(32)}
            replace_peers=true
            public_key=${"02".repeat(32)}
            preshared_key=${"03".repeat(32)}
            endpoint=198.51.100.1:51820
            persistent_keepalive_interval=25
            replace_allowed_ips=true
            allowed_ip=0.0.0.0/0
            allowed_ip=::/0

        """.trimIndent()
        assertEquals(expected, uapi)
    }

    @Test
    fun buildsAmneziaUapiWithDeviceKeysBeforePeers() {
        val uapi = WgUapi.build(WgQuickFormat.parse(AWG_CONF))
        val lines = uapi.lines()
        assertTrue(lines.indexOf("jc=4") in 1 until lines.indexOf("replace_peers=true"))
        assertTrue("h4=1646644382" in lines)
        assertTrue(lines.any { it.startsWith("i1=<b 0xc6") })
        assertTrue("endpoint=203.0.113.7:4443" in lines)
    }

    @Test
    fun uapiRequiresResolvedEndpoints() {
        assertFailsWith<IllegalArgumentException> { WgUapi.build(WgQuickFormat.parse(WG_CONF)) }
    }

    @Test
    fun parsesUapiStatistics() {
        val stats = WgUapi.parseStatistics(
            """
            private_key=${"01".repeat(32)}
            listen_port=40000
            public_key=${"02".repeat(32)}
            endpoint=198.51.100.1:51820
            last_handshake_time_sec=1700000000
            last_handshake_time_nsec=0
            tx_bytes=1000
            rx_bytes=2000
            public_key=${"03".repeat(32)}
            tx_bytes=1
            rx_bytes=2
            last_handshake_time_sec=0
            errno=0
            """.trimIndent(),
        )
        assertEquals(2002, stats.rxBytes)
        assertEquals(1001, stats.txBytes)
        assertEquals(1700000000, stats.lastHandshakeEpochSeconds)
        assertEquals(listOf(KEY2, KEY3), stats.peers.map { it.publicKey })
        assertNull(stats.peers[1].lastHandshakeEpochSeconds)
        assertEquals(KEY2, WgKey.fromHex(WgKey.toHex(KEY2)))
    }
}
