package io.github.bitnik212.vpnlib.tunnel

import io.github.bitnik212.vpnlib.config.wireguard.WgUapi

/**
 * A running engine bound to an OS tunnel file descriptor. Platform services
 * create one after the interface is established and stop it on teardown.
 */
public class TunnelSession private constructor(
    private val core: VpnCore,
    public val plan: TunnelPlan,
    /** Native engine handle. */
    public val handle: Int,
) {
    private var stopped = false

    public val isRunning: Boolean get() = !stopped

    /** Current counters, or null when the engine cannot report them. */
    public fun statistics(): TunnelStatistics? {
        if (stopped) return null
        return when (plan.engine) {
            is EngineConfig.WireGuard -> core.wireGuardGetConfig(handle)?.let(WgUapi::parseStatistics)
            is EngineConfig.Xray -> core.xrayGetStats(handle)?.let(::parseXrayStats)
        }
    }

    public fun stop() {
        if (stopped) return
        stopped = true
        when (plan.engine) {
            is EngineConfig.WireGuard -> core.wireGuardStop(handle)
            is EngineConfig.Xray -> core.xrayStop(handle)
        }
    }

    public companion object {
        /** Starts the engine described by [plan] on [tunFd]. */
        public fun start(core: VpnCore, plan: TunnelPlan, tunFd: Int): TunnelSession {
            val handle = when (val engine = plan.engine) {
                is EngineConfig.WireGuard -> core.wireGuardStart(tunFd, engine.uapi)
                is EngineConfig.Xray -> core.xrayStart(tunFd, engine.json)
            }
            return TunnelSession(core, plan, handle)
        }

        internal fun parseXrayStats(text: String): TunnelStatistics {
            val values = text.lineSequence()
                .mapNotNull { line -> line.split('=', limit = 2).takeIf { it.size == 2 } }
                .associate { (key, value) -> key.trim() to (value.trim().toLongOrNull() ?: 0L) }
            return TunnelStatistics(rxBytes = values["downlink"] ?: 0, txBytes = values["uplink"] ?: 0)
        }
    }
}
