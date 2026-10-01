package io.github.bitnik212.vpnlib.ios

import io.github.bitnik212.vpnlib.config.VpnLibJson
import io.github.bitnik212.vpnlib.config.VpnProfile
import io.github.bitnik212.vpnlib.tunnel.TunnelState
import io.github.bitnik212.vpnlib.tunnel.TunnelStatistics
import io.github.bitnik212.vpnlib.tunnel.VpnController
import io.github.bitnik212.vpnlib.tunnel.VpnException
import kotlinx.cinterop.ObjCObjectVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import platform.Foundation.NSError
import platform.Foundation.NSNotificationCenter
import platform.Foundation.NSOperationQueue
import platform.Foundation.NSString
import platform.Foundation.NSUTF8StringEncoding
import platform.Foundation.create
import platform.Foundation.timeIntervalSince1970
import platform.NetworkExtension.NETunnelProviderManager
import platform.NetworkExtension.NETunnelProviderProtocol
import platform.NetworkExtension.NETunnelProviderSession
import platform.NetworkExtension.NEVPNStatus
import platform.NetworkExtension.NEVPNStatusConnected
import platform.NetworkExtension.NEVPNStatusConnecting
import platform.NetworkExtension.NEVPNStatusDidChangeNotification
import platform.NetworkExtension.NEVPNStatusDisconnecting
import platform.NetworkExtension.NEVPNStatusReasserting
import platform.darwin.NSObjectProtocol
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Controls the VPN from the iOS app through NETunnelProviderManager. The
 * tunnel itself runs in a Packet Tunnel extension with bundle id
 * [providerBundleIdentifier] that forwards to [PacketTunnelEngine].
 *
 * Call [load] at app start to pick up an existing configuration and status.
 */
public class IosVpnController(
    private val providerBundleIdentifier: String,
) : VpnController {

    private val mutableState = MutableStateFlow<TunnelState>(TunnelState.Disconnected)
    override val state: StateFlow<TunnelState> = mutableState.asStateFlow()

    private var manager: NETunnelProviderManager? = null
    private var statusObserver: NSObjectProtocol? = null
    private var profileId: String? = null

    /** Loads the saved tunnel configuration (if any) and starts tracking its status. */
    @Throws(Exception::class)
    public suspend fun load() {
        val existing = loadManager() ?: return
        manager = existing
        profileId = existing.savedProfile()?.id
        observe(existing)
    }

    @Throws(Exception::class)
    override suspend fun connect(profile: VpnProfile) {
        profile.config.validate()
        val manager = manager ?: loadManager() ?: NETunnelProviderManager()
        val protocol = NETunnelProviderProtocol().apply {
            providerBundleIdentifier = this@IosVpnController.providerBundleIdentifier
            serverAddress = profile.name
            providerConfiguration = mapOf<Any?, Any?>(PROFILE_KEY to profile.toJson())
        }
        manager.protocolConfiguration = protocol
        manager.localizedDescription = profile.name
        manager.enabled = true
        awaitCompletion { manager.saveToPreferencesWithCompletionHandler(it) }
        // A saved manager must be reloaded before it can be started.
        awaitCompletion { manager.loadFromPreferencesWithCompletionHandler(it) }

        this.manager = manager
        profileId = profile.id
        observe(manager)
        mutableState.value = TunnelState.Connecting(profile.id)

        val session = manager.connection as? NETunnelProviderSession
            ?: throw VpnException("Tunnel provider session is unavailable")
        memScoped {
            val error = alloc<ObjCObjectVar<NSError?>>()
            if (!session.startTunnelWithOptions(null, error.ptr)) {
                mutableState.value = TunnelState.Error(profile.id, error.value?.localizedDescription ?: "start failed")
                throw VpnException("Unable to start the tunnel: ${error.value?.localizedDescription}")
            }
        }
    }

    @Throws(Exception::class)
    override suspend fun disconnect() {
        manager?.connection?.stopVPNTunnel()
    }

    @Throws(Exception::class)
    override suspend fun statistics(): TunnelStatistics? {
        val session = manager?.connection as? NETunnelProviderSession ?: return null
        if (session.status != NEVPNStatusConnected) return null
        val message = PacketTunnelEngine.MESSAGE_STATISTICS.toNSData() ?: return null
        return suspendCancellableCoroutine { continuation ->
            val sent = memScoped {
                val error = alloc<ObjCObjectVar<NSError?>>()
                session.sendProviderMessage(message, error.ptr) { response ->
                    val json = response?.let { NSString.create(data = it, encoding = NSUTF8StringEncoding)?.toString() }
                    val stats = json?.let {
                        runCatching { VpnLibJson.decodeFromString(TunnelStatistics.serializer(), it) }.getOrNull()
                    }
                    continuation.resume(stats)
                }
            }
            if (!sent) continuation.resume(null)
        }
    }

    /** Removes the VPN configuration from the system settings. */
    @Throws(Exception::class)
    public suspend fun removeConfiguration() {
        val manager = manager ?: loadManager() ?: return
        awaitCompletion { manager.removeFromPreferencesWithCompletionHandler(it) }
        statusObserver?.let { NSNotificationCenter.defaultCenter.removeObserver(it) }
        statusObserver = null
        this.manager = null
        mutableState.value = TunnelState.Disconnected
    }

    private fun observe(manager: NETunnelProviderManager) {
        statusObserver?.let { NSNotificationCenter.defaultCenter.removeObserver(it) }
        statusObserver = NSNotificationCenter.defaultCenter.addObserverForName(
            name = NEVPNStatusDidChangeNotification,
            `object` = manager.connection,
            queue = NSOperationQueue.mainQueue,
        ) { _ -> updateState(manager) }
        updateState(manager)
    }

    private fun updateState(manager: NETunnelProviderManager) {
        val connection = manager.connection
        val id = profileId ?: manager.savedProfile()?.id ?: ""
        mutableState.value = mapStatus(connection.status, id) {
            connection.connectedDate?.timeIntervalSince1970?.let { (it * 1000).toLong() } ?: 0L
        }
    }

    private fun mapStatus(status: NEVPNStatus, id: String, connectedAt: () -> Long): TunnelState = when (status) {
        NEVPNStatusConnecting -> TunnelState.Connecting(id)
        NEVPNStatusConnected -> TunnelState.Connected(id, connectedAt())
        NEVPNStatusReasserting -> TunnelState.Reconnecting(id)
        NEVPNStatusDisconnecting -> TunnelState.Disconnecting(id)
        else -> TunnelState.Disconnected
    }

    private suspend fun loadManager(): NETunnelProviderManager? = suspendCancellableCoroutine { continuation ->
        NETunnelProviderManager.loadAllFromPreferencesWithCompletionHandler { managers, error ->
            if (error != null) {
                continuation.resumeWithException(VpnException("Unable to load VPN configurations: ${error.localizedDescription}"))
            } else {
                val match = managers.orEmpty().filterIsInstance<NETunnelProviderManager>().firstOrNull {
                    (it.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier ==
                        providerBundleIdentifier
                }
                continuation.resume(match)
            }
        }
    }

    private suspend fun awaitCompletion(call: ((NSError?) -> Unit) -> Unit) {
        suspendCancellableCoroutine { continuation ->
            call { error ->
                if (error == null) {
                    continuation.resume(Unit)
                } else {
                    continuation.resumeWithException(VpnException(error.localizedDescription))
                }
            }
        }
    }

    private fun NETunnelProviderManager.savedProfile(): VpnProfile? {
        val json = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?.get(PROFILE_KEY)
        return json?.toString()?.let { runCatching { VpnProfile.fromJson(it) }.getOrNull() }
    }

    public companion object {
        /** Key of the profile JSON in the provider configuration / start options. */
        public const val PROFILE_KEY: String = "vpnlib.profile"
    }
}
