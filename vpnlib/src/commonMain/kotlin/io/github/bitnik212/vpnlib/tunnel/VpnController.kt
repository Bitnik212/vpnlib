package io.github.bitnik212.vpnlib.tunnel

import io.github.bitnik212.vpnlib.config.VpnProfile
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach

/**
 * App-side entry point for controlling the system VPN.
 *
 * Platform implementations: `AndroidVpnController` (VpnService) and
 * `IosVpnController` (NETunnelProviderManager).
 */
public interface VpnController {
    public val state: StateFlow<TunnelState>

    /**
     * Starts the VPN with [profile], replacing a running tunnel. Returns once
     * the request is handed to the OS; follow [state] for the outcome.
     */
    @Throws(Exception::class)
    public suspend fun connect(profile: VpnProfile)

    @Throws(Exception::class)
    public suspend fun disconnect()

    /** Counters of the running tunnel, or null when disconnected. */
    @Throws(Exception::class)
    public suspend fun statistics(): TunnelStatistics?
}

/** Handle for a callback registered with [watchState]. */
public fun interface Cancellable {
    public fun cancel()
}

/**
 * Callback flavored [VpnController.state] for Swift and Java callers. The
 * callback runs on the main thread, first with the current state.
 */
public fun VpnController.watchState(onChange: (TunnelState) -> Unit): Cancellable {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    state.onEach { onChange(it) }.launchIn(scope)
    return Cancellable { scope.cancel() }
}
