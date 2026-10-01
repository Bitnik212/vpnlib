package io.github.bitnik212.vpnlib.android.internal

import android.content.Context
import io.github.bitnik212.vpnlib.android.VpnLibService
import io.github.bitnik212.vpnlib.config.VpnProfile
import io.github.bitnik212.vpnlib.tunnel.TunnelState
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * Process wide link between [VpnLibService] and the controllers. The service
 * must run in the app's main process (the default).
 */
internal object VpnRuntime {
    val state = MutableStateFlow<TunnelState>(TunnelState.Disconnected)

    @Volatile
    var activeService: VpnLibService? = null
}

/** Last started profile, used to restart the tunnel for always-on VPN. */
internal object ProfileStore {
    private const val PREFS = "io.github.bitnik212.vpnlib"
    private const val KEY_PROFILE = "last_profile"

    fun save(context: Context, profile: VpnProfile) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString(KEY_PROFILE, profile.toJson())
            .apply()
    }

    fun load(context: Context): VpnProfile? {
        val json = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_PROFILE, null)
        return json?.let { runCatching { VpnProfile.fromJson(it) }.getOrNull() }
    }

    fun clear(context: Context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove(KEY_PROFILE).apply()
    }
}
