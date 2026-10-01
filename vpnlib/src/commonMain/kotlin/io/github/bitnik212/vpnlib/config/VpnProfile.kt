package io.github.bitnik212.vpnlib.config

import io.github.bitnik212.vpnlib.net.IpPrefix
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * A named VPN connection: a protocol [config] plus platform tunnel [options].
 * Profiles are serialized with [toJson] to cross process boundaries (the
 * Android VPN service, the iOS Network Extension).
 */
@Serializable
public data class VpnProfile(
    val id: String,
    val name: String,
    val config: VpnConfig,
    val options: TunnelOptions = TunnelOptions(),
) {
    public fun toJson(): String = VpnLibJson.encodeToString(serializer(), this)

    public companion object {
        @Throws(Exception::class)
        public fun fromJson(json: String): VpnProfile = VpnLibJson.decodeFromString(serializer(), json)
    }
}

/**
 * Settings of the OS tunnel interface that are independent of the protocol.
 */
@Serializable
public data class TunnelOptions(
    /** Android: only these packages use the VPN (takes precedence over [excludedApplications]). */
    val includedApplications: List<String> = emptyList(),
    /** Android: these packages bypass the VPN. */
    val excludedApplications: List<String> = emptyList(),
    /** Destinations that are routed outside of the tunnel. */
    val excludedRoutes: List<IpPrefix> = emptyList(),
    /** Keep LAN, link-local and multicast traffic outside of the tunnel. */
    val allowLanAccess: Boolean = false,
    /** Overrides the DNS servers of the protocol config. */
    val dnsServers: List<String>? = null,
    /** Overrides the MTU of the protocol config. */
    val mtu: Int? = null,
    /** Android: lets apps opt out of the VPN via ConnectivityManager. */
    val allowBypass: Boolean = false,
    /** Android: marks the VPN network as metered. */
    val metered: Boolean = false,
)

/** JSON format used for profiles and statistics. */
public val VpnLibJson: Json = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
    classDiscriminator = "type"
}
