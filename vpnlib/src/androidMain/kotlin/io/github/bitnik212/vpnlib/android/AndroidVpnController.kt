package io.github.bitnik212.vpnlib.android

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import io.github.bitnik212.vpnlib.android.internal.ProfileStore
import io.github.bitnik212.vpnlib.android.internal.VpnRuntime
import io.github.bitnik212.vpnlib.config.VpnProfile
import io.github.bitnik212.vpnlib.tunnel.TunnelState
import io.github.bitnik212.vpnlib.tunnel.TunnelStatistics
import io.github.bitnik212.vpnlib.tunnel.VpnController
import io.github.bitnik212.vpnlib.tunnel.VpnException
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Controls the VPN from the app process.
 *
 * ```
 * val vpn = AndroidVpnController(context)
 * vpn.prepare()?.let { activity.startActivityForResult(it, REQUEST_VPN) } // once, for consent
 * vpn.connect(VpnProfile("id", "Home", AmneziaWgConfig.parse(text)))
 * ```
 */
public class AndroidVpnController(
    context: Context,
    private val serviceClass: Class<out VpnLibService> = VpnLibService::class.java,
) : VpnController {

    private val context: Context = context.applicationContext

    override val state: StateFlow<TunnelState> = VpnRuntime.state.asStateFlow()

    /**
     * Intent asking the user for VPN consent, or null when already granted.
     * Launch it from an Activity before [connect].
     */
    public fun prepare(): Intent? = VpnService.prepare(context)

    @Throws(Exception::class)
    override suspend fun connect(profile: VpnProfile) {
        profile.config.validate()
        if (prepare() != null) {
            throw VpnException("VPN consent is required, launch the intent returned by prepare() first")
        }
        VpnRuntime.state.value = TunnelState.Connecting(profile.id)
        val intent = Intent(context, serviceClass)
            .setAction(VpnLibService.ACTION_CONNECT)
            .putExtra(VpnLibService.EXTRA_PROFILE, profile.toJson())
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent)
        } else {
            context.startService(intent)
        }
    }

    @Throws(Exception::class)
    override suspend fun disconnect() {
        val service = VpnRuntime.activeService
        if (service != null) {
            service.disconnect()
        } else {
            VpnRuntime.state.value = TunnelState.Disconnected
        }
    }

    @Throws(Exception::class)
    override suspend fun statistics(): TunnelStatistics? = VpnRuntime.activeService?.statistics()

    /** Version string of the native engines. */
    public fun coreVersion(): String = AndroidVpnCore.version()

    /** Forgets the profile kept for always-on VPN restarts. */
    public fun clearSavedProfile(): Unit = ProfileStore.clear(context)
}
