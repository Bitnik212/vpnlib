package io.github.bitnik212.vpnlib.tunnel

import io.github.bitnik212.vpnlib.config.VpnProtocol
import io.github.bitnik212.vpnlib.net.IpPrefix

/**
 * Everything a platform needs to bring a tunnel up: interface settings for
 * VpnService.Builder / NEPacketTunnelNetworkSettings plus the engine config.
 * Produced by [TunnelPlanner].
 */
public data class TunnelPlan(
    val profileId: String,
    val sessionName: String,
    val protocol: VpnProtocol,
    /** Interface addresses (may include host bits). */
    val addresses: List<IpPrefix>,
    /** Routes into the tunnel, normalized, with exclusions already applied. */
    val routes: List<IpPrefix>,
    /** Requested exclusions, for platforms that support excluded routes natively. */
    val excludedRoutes: List<IpPrefix>,
    val dnsServers: List<String>,
    val searchDomains: List<String>,
    val mtu: Int,
    val includedApplications: List<String>,
    val excludedApplications: List<String>,
    val allowBypass: Boolean,
    val metered: Boolean,
    /** IP of the primary remote server (iOS `tunnelRemoteAddress`). */
    val remoteAddress: String,
    val engine: EngineConfig,
)

/** Input for the native engine. */
public sealed interface EngineConfig {
    public data class WireGuard(val uapi: String) : EngineConfig {
        override fun toString(): String = "WireGuard(uapi=<redacted>)"
    }

    public data class Xray(val json: String) : EngineConfig {
        override fun toString(): String = "Xray(json=<redacted>)"
    }
}
