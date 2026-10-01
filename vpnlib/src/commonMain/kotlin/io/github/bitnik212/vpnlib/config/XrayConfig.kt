package io.github.bitnik212.vpnlib.config

import io.github.bitnik212.vpnlib.config.xray.XrayJsonBuilder
import io.github.bitnik212.vpnlib.config.xray.XrayOutbound
import io.github.bitnik212.vpnlib.config.xray.XrayShareLink
import io.github.bitnik212.vpnlib.config.xray.problems
import io.github.bitnik212.vpnlib.net.IpAddress
import io.github.bitnik212.vpnlib.net.IpPrefix
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/**
 * Xray-core connection.
 *
 * Either a single structured [outbound] (typically parsed from a share link
 * with [fromShareLink]) from which a complete Xray config is generated, or a
 * full Xray JSON config in [rawJson] for advanced setups (routing rules,
 * balancers, chained proxies...). In both cases the library injects the
 * `tun` inbound that connects Xray to the OS tunnel.
 */
@Serializable
@SerialName("xray")
public data class XrayConfig(
    val outbound: XrayOutbound? = null,
    val rawJson: String? = null,
    /** DNS servers used by the tunnel and by Xray's resolver. */
    val dnsServers: List<String> = DEFAULT_DNS_SERVERS,
    /** Addresses of the tunnel interface. */
    val tunAddresses: List<IpPrefix> = DEFAULT_TUN_ADDRESSES,
    val mtu: Int = DEFAULT_MTU,
    /** Route IPv6 through the tunnel (otherwise only IPv4 is captured). */
    val ipv6: Boolean = true,
    /** Xray log level: debug, info, warning, error or none. */
    val logLevel: String = "warning",
    /** Sniff TLS / HTTP / QUIC to route by domain instead of the resolved IP. */
    val sniffing: Boolean = true,
    /**
     * Resolve a hostname server address before starting and connect to the IP,
     * keeping the hostname as TLS SNI / HTTP host. Avoids DNS lookups from
     * inside the VPN process, which can loop through the tunnel.
     */
    val resolveServerAddress: Boolean = true,
) : VpnConfig {

    override val protocol: VpnProtocol get() = VpnProtocol.XRAY

    @Throws(ConfigException::class)
    override fun validate() {
        val problems = buildList {
            if ((outbound == null) == (rawJson == null)) add("exactly one of outbound and rawJson must be set")
            outbound?.let { addAll(it.problems()) }
            rawJson?.let { json ->
                val parsed = runCatching { Json.parseToJsonElement(json) as? JsonObject }.getOrNull()
                if (parsed == null) add("rawJson is not a JSON object")
            }
            dnsServers.filterNot(IpAddress::isValid).forEach { add("DNS '$it' is not an IP address") }
            if (tunAddresses.none { it.isIpv4 }) add("an IPv4 tun address is required")
            if (mtu !in 576..65535) add("MTU $mtu is out of range")
        }
        throwIfProblems("Xray config", problems)
    }

    /** Generates the Xray JSON config. See [XrayJsonBuilder]. */
    public fun toXrayJson(resolvedServerAddress: String? = null): String =
        XrayJsonBuilder.build(this, resolvedServerAddress)

    public companion object {
        public const val DEFAULT_MTU: Int = 1500
        public val DEFAULT_DNS_SERVERS: List<String> = listOf("1.1.1.1", "8.8.8.8")
        public val DEFAULT_TUN_ADDRESSES: List<IpPrefix> =
            listOf(IpPrefix.parse("172.19.0.1/30"), IpPrefix.parse("fdfe:dcba:9876::1/126"))

        /** Parses a `vless://`, `vmess://`, `trojan://` or `ss://` link. */
        @Throws(ConfigException::class)
        public fun fromShareLink(link: String): XrayConfig = XrayConfig(outbound = XrayShareLink.parse(link))

        /** Wraps a complete Xray JSON config. */
        @Throws(ConfigException::class)
        public fun fromJson(json: String): XrayConfig {
            val parsed = runCatching { Json.parseToJsonElement(json) }.getOrNull()
            if (parsed !is JsonObject) throw ConfigException("Xray config is not a JSON object")
            return XrayConfig(rawJson = json)
        }
    }
}
