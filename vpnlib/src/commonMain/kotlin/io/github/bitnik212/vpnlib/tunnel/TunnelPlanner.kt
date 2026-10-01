package io.github.bitnik212.vpnlib.tunnel

import io.github.bitnik212.vpnlib.config.VpnProfile
import io.github.bitnik212.vpnlib.config.WgBasedConfig
import io.github.bitnik212.vpnlib.config.wireguard.WgUapi
import io.github.bitnik212.vpnlib.config.XrayConfig
import io.github.bitnik212.vpnlib.config.xray.XrayJsonBuilder
import io.github.bitnik212.vpnlib.net.Endpoint
import io.github.bitnik212.vpnlib.net.IpAddress
import io.github.bitnik212.vpnlib.net.IpPrefix
import io.github.bitnik212.vpnlib.net.Routes

/**
 * Turns a [VpnProfile] into a [TunnelPlan]: validates the config, resolves
 * server hostnames, computes routes and renders the engine config.
 */
public class TunnelPlanner(private val resolver: HostResolver) {

    public suspend fun plan(profile: VpnProfile): TunnelPlan {
        profile.config.validate()
        return when (val config = profile.config) {
            is WgBasedConfig -> planWireGuard(profile, config)
            is XrayConfig -> planXray(profile, config)
        }
    }

    private suspend fun planWireGuard(profile: VpnProfile, config: WgBasedConfig): TunnelPlan {
        val options = profile.options
        val resolved = mutableMapOf<Endpoint, Endpoint>()
        for (endpoint in config.peers.mapNotNull { it.endpoint }.filterNot { it.isResolved }.distinct()) {
            resolved[endpoint] = Endpoint(resolveHost(endpoint.host), endpoint.port)
        }
        val remote = config.peers.firstNotNullOfOrNull { peer ->
            peer.endpoint?.let { (resolved[it] ?: it).host }
        } ?: config.iface.addresses.first().address.toString()

        val excluded = excludedRoutes(profile)
        val allowedIps = config.peers.flatMap { it.allowedIps }
        return TunnelPlan(
            profileId = profile.id,
            sessionName = profile.name,
            protocol = config.protocol,
            addresses = config.iface.addresses,
            routes = Routes.subtract(allowedIps, excluded),
            excludedRoutes = excluded,
            dnsServers = options.dnsServers ?: config.iface.dnsServers,
            searchDomains = config.iface.dnsSearchDomains,
            mtu = options.mtu ?: config.iface.mtu ?: DEFAULT_WIREGUARD_MTU,
            includedApplications = (options.includedApplications + config.iface.includedApplications).distinct(),
            excludedApplications = (options.excludedApplications + config.iface.excludedApplications).distinct(),
            allowBypass = options.allowBypass,
            metered = options.metered,
            remoteAddress = remote,
            engine = EngineConfig.WireGuard(WgUapi.build(config, resolved)),
        )
    }

    private suspend fun planXray(profile: VpnProfile, config: XrayConfig): TunnelPlan {
        val options = profile.options
        val outbound = config.outbound
        val resolvedAddress = when {
            outbound == null -> null
            IpAddress.isValid(outbound.address) -> outbound.address
            config.resolveServerAddress -> resolveHost(outbound.address)
            else -> null
        }
        val tunAddresses = config.tunAddresses.filter { config.ipv6 || it.isIpv4 }
        val fullRoutes = buildList {
            add(IpPrefix.IPV4_DEFAULT)
            if (config.ipv6 && tunAddresses.any { it.isIpv6 }) add(IpPrefix.IPV6_DEFAULT)
        }
        val excluded = excludedRoutes(profile)
        val effective = config.copy(
            dnsServers = options.dnsServers ?: config.dnsServers,
            mtu = options.mtu ?: config.mtu,
        )
        return TunnelPlan(
            profileId = profile.id,
            sessionName = profile.name,
            protocol = config.protocol,
            addresses = tunAddresses,
            routes = Routes.subtract(fullRoutes, excluded),
            excludedRoutes = excluded,
            dnsServers = effective.dnsServers,
            searchDomains = emptyList(),
            mtu = effective.mtu,
            includedApplications = options.includedApplications,
            excludedApplications = options.excludedApplications,
            allowBypass = options.allowBypass,
            metered = options.metered,
            remoteAddress = resolvedAddress ?: outbound?.address ?: tunAddresses.first().address.toString(),
            engine = EngineConfig.Xray(XrayJsonBuilder.build(effective, resolvedAddress)),
        )
    }

    private fun excludedRoutes(profile: VpnProfile): List<IpPrefix> {
        val options = profile.options
        return Routes.normalize(options.excludedRoutes + if (options.allowLanAccess) Routes.LOCAL_NETWORKS else emptyList())
    }

    private suspend fun resolveHost(host: String): String {
        val addresses = try {
            resolver.resolve(host)
        } catch (e: Exception) {
            throw VpnException("Unable to resolve $host: ${e.message}", e)
        }
        val parsed = addresses.mapNotNull(IpAddress::parseOrNull)
        val best = parsed.firstOrNull { it.isIpv4 } ?: parsed.firstOrNull()
            ?: throw VpnException("Unable to resolve $host: no addresses")
        return best.toString()
    }

    public companion object {
        public const val DEFAULT_WIREGUARD_MTU: Int = 1280
    }
}
