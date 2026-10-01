package io.github.bitnik212.vpnlib.ios

import io.github.bitnik212.vpnlib.config.VpnLibJson
import io.github.bitnik212.vpnlib.config.VpnProfile
import io.github.bitnik212.vpnlib.net.IpPrefix
import io.github.bitnik212.vpnlib.tunnel.EngineConfig
import io.github.bitnik212.vpnlib.tunnel.TunnelPlan
import io.github.bitnik212.vpnlib.tunnel.TunnelPlanner
import io.github.bitnik212.vpnlib.tunnel.TunnelSession
import io.github.bitnik212.vpnlib.tunnel.TunnelStatistics
import io.github.bitnik212.vpnlib.tunnel.VpnException
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.toKString
import kotlinx.cinterop.value
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import platform.Foundation.NSData
import platform.Foundation.NSError
import platform.Foundation.NSLocalizedDescriptionKey
import platform.Foundation.NSNumber
import platform.Foundation.NSString
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.create
import platform.Foundation.dataUsingEncoding
import platform.NetworkExtension.NEDNSSettings
import platform.NetworkExtension.NEIPv4Route
import platform.NetworkExtension.NEIPv4Settings
import platform.NetworkExtension.NEIPv6Route
import platform.NetworkExtension.NEIPv6Settings
import platform.NetworkExtension.NEPacketTunnelNetworkSettings
import platform.NetworkExtension.NEPacketTunnelProvider
import platform.NetworkExtension.NETunnelProviderProtocol
import platform.posix.getsockopt
import platform.posix.socklen_tVar
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Runs a vpnlib tunnel inside an iOS Packet Tunnel Network Extension.
 *
 * Forward the provider callbacks from your `NEPacketTunnelProvider`
 * subclass (see `ios/PacketTunnelProvider.swift`):
 *
 * ```swift
 * private lazy var engine = PacketTunnelEngine(provider: self)
 * override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
 *     engine.startTunnel(options: options, completion: completionHandler)
 * }
 * ```
 */
public class PacketTunnelEngine(private val provider: NEPacketTunnelProvider) {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val lock = Mutex()
    private var session: TunnelSession? = null

    /** Go heap limit applied before starting an engine (extensions are capped at ~50 MB). */
    public var memoryLimitBytes: Long = 30L * 1024 * 1024

    /**
     * Starts the tunnel. The profile JSON is read from [options] (key
     * [IosVpnController.PROFILE_KEY]) or from the provider configuration.
     */
    public fun startTunnel(options: Map<Any?, *>?, completion: (NSError?) -> Unit) {
        scope.launch {
            val error = try {
                lock.withLock { start(loadProfile(options)) }
                null
            } catch (e: Throwable) {
                NSError.errorWithDomain(
                    ERROR_DOMAIN,
                    code = 1,
                    userInfo = mapOf<Any?, Any?>(NSLocalizedDescriptionKey to (e.message ?: e.toString())),
                )
            }
            completion(error)
        }
    }

    public fun stopTunnel(completion: () -> Unit) {
        scope.launch {
            lock.withLock {
                session?.stop()
                session = null
            }
            completion()
        }
    }

    /**
     * Handles `sendProviderMessage` from the app. Message [MESSAGE_STATISTICS]
     * replies with [TunnelStatistics] as JSON.
     */
    public fun handleAppMessage(message: NSData, completion: ((NSData?) -> Unit)?) {
        val text = NSString.create(data = message, encoding = NSUTF8StringEncoding)?.toString()
        val reply = when (text) {
            MESSAGE_STATISTICS -> session?.statistics()?.let {
                VpnLibJson.encodeToString(TunnelStatistics.serializer(), it)
            }
            else -> null
        }
        completion?.invoke(reply?.toNSData())
    }

    /** Call when the provider's default path changes (WireGuard re-binds its sockets). */
    public fun networkPathChanged() {
        val current = session ?: return
        if (current.plan.engine is EngineConfig.WireGuard) IosVpnCore.wireGuardBumpSockets(current.handle)
    }

    private suspend fun start(profile: VpnProfile) {
        session?.stop()
        session = null

        val plan = TunnelPlanner(IosHostResolver()).plan(profile)
        applyNetworkSettings(plan)
        val fd = findTunnelFileDescriptor() ?: throw VpnException("Unable to find the utun file descriptor")
        IosVpnCore.setMemoryLimit(memoryLimitBytes)
        session = TunnelSession.start(IosVpnCore, plan, fd)
    }

    private fun loadProfile(options: Map<Any?, *>?): VpnProfile {
        val fromOptions = options?.get(IosVpnController.PROFILE_KEY)?.toString()
        val protocol = provider.protocolConfiguration as? NETunnelProviderProtocol
        val fromConfiguration = protocol?.providerConfiguration?.get(IosVpnController.PROFILE_KEY)?.toString()
        val json = fromOptions ?: fromConfiguration ?: throw VpnException("No VPN profile in the tunnel configuration")
        return VpnProfile.fromJson(json)
    }

    private suspend fun applyNetworkSettings(plan: TunnelPlan) {
        val settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress = plan.remoteAddress)
        settings.MTU = NSNumber(int = plan.mtu)

        val v4 = plan.addresses.filter { it.isIpv4 }
        if (v4.isNotEmpty()) {
            settings.IPv4Settings = NEIPv4Settings(
                addresses = v4.map { it.address.toString() },
                subnetMasks = v4.map { it.ipv4Netmask() },
            ).apply {
                includedRoutes = plan.routes.filter { it.isIpv4 }.map(::ipv4Route)
            }
        }
        val v6 = plan.addresses.filter { it.isIpv6 }
        if (v6.isNotEmpty()) {
            settings.IPv6Settings = NEIPv6Settings(
                addresses = v6.map { it.address.toString() },
                networkPrefixLengths = v6.map { NSNumber(int = it.prefixLength) },
            ).apply {
                includedRoutes = plan.routes.filter { it.isIpv6 }.map(::ipv6Route)
            }
        }
        if (plan.dnsServers.isNotEmpty()) {
            settings.DNSSettings = NEDNSSettings(servers = plan.dnsServers).apply {
                // Send every query to the tunnel DNS servers.
                matchDomains = listOf("")
                if (plan.searchDomains.isNotEmpty()) searchDomains = plan.searchDomains
            }
        }

        suspendCancellableCoroutine { continuation ->
            provider.setTunnelNetworkSettings(settings) { error ->
                if (error == null) {
                    continuation.resume(Unit)
                } else {
                    continuation.resumeWithException(VpnException("setTunnelNetworkSettings: ${error.localizedDescription}"))
                }
            }
        }
    }

    private fun ipv4Route(prefix: IpPrefix): NEIPv4Route =
        NEIPv4Route(destinationAddress = prefix.address.toString(), subnetMask = prefix.ipv4Netmask())

    private fun ipv6Route(prefix: IpPrefix): NEIPv6Route =
        NEIPv6Route(destinationAddress = prefix.address.toString(), networkPrefixLength = NSNumber(int = prefix.prefixLength))

    public companion object {
        public const val ERROR_DOMAIN: String = "io.github.bitnik212.vpnlib"
        public const val MESSAGE_STATISTICS: String = "statistics"

        private const val SYSPROTO_CONTROL = 2
        private const val UTUN_OPT_IFNAME = 2
        private const val IFNAMSIZ = 16

        /**
         * NetworkExtension does not expose the utun descriptor; find it by
         * asking every open fd for its utun interface name.
         */
        internal fun findTunnelFileDescriptor(): Int? = memScoped {
            val name = allocArray<ByteVar>(IFNAMSIZ)
            val length = alloc<socklen_tVar>()
            for (fd in 0..1024) {
                length.value = IFNAMSIZ.convert()
                if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, name, length.ptr) == 0 &&
                    name.toKString().startsWith("utun")
                ) {
                    return@memScoped fd
                }
            }
            null
        }
    }
}

internal fun String.toNSData(): NSData? = NSString.create(string = this).dataUsingEncoding(NSUTF8StringEncoding)
