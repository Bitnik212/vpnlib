package io.github.bitnik212.vpnlib.config

import io.github.bitnik212.vpnlib.config.wireguard.AmneziaParams
import io.github.bitnik212.vpnlib.config.wireguard.WgKey
import io.github.bitnik212.vpnlib.config.wireguard.WgQuickFormat
import io.github.bitnik212.vpnlib.net.Endpoint
import io.github.bitnik212.vpnlib.net.IpAddress
import io.github.bitnik212.vpnlib.net.IpPrefix
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** `[Interface]` section of a WireGuard config. */
@Serializable
public data class WgInterface(
    val privateKey: String,
    val addresses: List<IpPrefix> = emptyList(),
    val dnsServers: List<String> = emptyList(),
    val dnsSearchDomains: List<String> = emptyList(),
    val listenPort: Int? = null,
    val mtu: Int? = null,
    /** wireguard-android extension: only these packages use the tunnel. */
    val includedApplications: List<String> = emptyList(),
    /** wireguard-android extension: these packages bypass the tunnel. */
    val excludedApplications: List<String> = emptyList(),
) {
    internal fun problems(): List<String> = buildList {
        if (!WgKey.isValid(privateKey)) add("PrivateKey is not a valid key")
        if (addresses.isEmpty()) add("Address is required")
        dnsServers.filterNot(IpAddress::isValid).forEach { add("DNS '$it' is not an IP address") }
        if (listenPort != null && listenPort !in 0..65535) add("ListenPort $listenPort is out of range")
        if (mtu != null && mtu !in MIN_MTU..MAX_MTU) add("MTU $mtu is out of range $MIN_MTU..$MAX_MTU")
        if (includedApplications.isNotEmpty() && excludedApplications.isNotEmpty()) {
            add("IncludedApplications and ExcludedApplications are mutually exclusive")
        }
    }

    public companion object {
        public const val MIN_MTU: Int = 576
        public const val MAX_MTU: Int = 65535
    }
}

/** `[Peer]` section of a WireGuard config. */
@Serializable
public data class WgPeer(
    val publicKey: String,
    val presharedKey: String? = null,
    val allowedIps: List<IpPrefix> = emptyList(),
    val endpoint: Endpoint? = null,
    val persistentKeepalive: Int? = null,
) {
    internal fun problems(index: Int): List<String> = buildList {
        if (!WgKey.isValid(publicKey)) add("peer #$index: PublicKey is not a valid key")
        if (presharedKey != null && !WgKey.isValid(presharedKey)) add("peer #$index: PresharedKey is not a valid key")
        if (persistentKeepalive != null && persistentKeepalive !in 0..65535) {
            add("peer #$index: PersistentKeepalive is out of range")
        }
    }
}

/**
 * Common shape of WireGuard based configs ([WireGuardConfig], [AmneziaWgConfig]).
 */
public sealed interface WgBasedConfig : VpnConfig {
    public val iface: WgInterface
    public val peers: List<WgPeer>

    /** AmneziaWG obfuscation parameters, null for plain WireGuard. */
    public val amneziaParams: AmneziaParams?

    /** Serializes to the wg-quick / AmneziaWG `.conf` format. */
    public fun toWgQuick(): String = WgQuickFormat.format(this)

    @Throws(ConfigException::class)
    override fun validate() {
        val problems = buildList {
            addAll(iface.problems())
            if (peers.isEmpty()) add("at least one [Peer] is required")
            peers.forEachIndexed { i, peer -> addAll(peer.problems(i + 1)) }
            amneziaParams?.let { addAll(it.problems()) }
        }
        throwIfProblems("${protocol.name} config", problems)
    }
}

/** Plain WireGuard. */
@Serializable
@SerialName("wireguard")
public data class WireGuardConfig(
    @SerialName("interface") override val iface: WgInterface,
    override val peers: List<WgPeer>,
) : WgBasedConfig {
    override val protocol: VpnProtocol get() = VpnProtocol.WIREGUARD
    override val amneziaParams: AmneziaParams? get() = null

    /** Converts to AmneziaWG with the given obfuscation parameters. */
    public fun withAmnezia(params: AmneziaParams): AmneziaWgConfig = AmneziaWgConfig(iface, peers, params)

    public companion object {
        /** Parses a wg-quick config; fails if it contains AmneziaWG parameters. */
        @Throws(ConfigException::class)
        public fun parse(text: String): WireGuardConfig = when (val config = WgQuickFormat.parse(text)) {
            is WireGuardConfig -> config
            is AmneziaWgConfig -> throw ConfigException(
                "Config contains AmneziaWG parameters, use AmneziaWgConfig.parse or WgQuickFormat.parse",
            )
        }
    }
}

/** AmneziaWG: WireGuard with DPI obfuscation (junk packets, padding, custom headers). */
@Serializable
@SerialName("amneziawg")
public data class AmneziaWgConfig(
    @SerialName("interface") override val iface: WgInterface,
    override val peers: List<WgPeer>,
    val amnezia: AmneziaParams,
) : WgBasedConfig {
    override val protocol: VpnProtocol get() = VpnProtocol.AMNEZIA_WG
    override val amneziaParams: AmneziaParams get() = amnezia

    public companion object {
        /** Parses an AmneziaWG (or plain wg-quick) config. */
        @Throws(ConfigException::class)
        public fun parse(text: String): AmneziaWgConfig = when (val config = WgQuickFormat.parse(text)) {
            is AmneziaWgConfig -> config
            is WireGuardConfig -> config.withAmnezia(AmneziaParams())
        }
    }
}
