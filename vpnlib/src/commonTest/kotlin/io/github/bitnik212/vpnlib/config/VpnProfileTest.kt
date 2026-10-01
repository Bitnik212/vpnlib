package io.github.bitnik212.vpnlib.config

import io.github.bitnik212.vpnlib.config.wireguard.WgQuickFormat
import io.github.bitnik212.vpnlib.config.XrayConfig
import io.github.bitnik212.vpnlib.net.IpPrefix
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class VpnProfileTest {
    @Test
    fun roundTripsAllProtocolsThroughJson() {
        val profiles = listOf(
            VpnProfile("wg", "WireGuard", WgQuickFormat.parse(WG_CONF)),
            VpnProfile(
                "awg",
                "Amnezia",
                WgQuickFormat.parse(AWG_CONF),
                TunnelOptions(excludedRoutes = listOf(IpPrefix.parse("192.0.2.0/24")), allowLanAccess = true),
            ),
            VpnProfile("xray", "Xray", XrayConfig.fromShareLink(VLESS_REALITY)),
            VpnProfile("raw", "Raw", XrayConfig.fromJson("""{"outbounds":[]}""")),
        )
        for (profile in profiles) {
            val json = profile.toJson()
            assertEquals(profile, VpnProfile.fromJson(json), json)
        }
        assertTrue("\"type\":\"amneziawg\"" in profiles[1].toJson())
    }
}
