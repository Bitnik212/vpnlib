package io.github.bitnik212.vpnlib.tunnel

import kotlinx.serialization.Serializable

/** Lifecycle of the VPN tunnel as seen by the app. */
public sealed interface TunnelState {
    /** Id of the profile this state refers to, if any. */
    public val profileId: String?

    public data object Disconnected : TunnelState {
        override val profileId: String? get() = null
    }

    public data class Connecting(override val profileId: String) : TunnelState

    public data class Connected(
        override val profileId: String,
        /** Wall clock time the tunnel came up, in epoch milliseconds. */
        val sinceEpochMillis: Long,
    ) : TunnelState

    /** The tunnel is up but the OS is re-establishing it (network change). */
    public data class Reconnecting(override val profileId: String) : TunnelState

    public data class Disconnecting(override val profileId: String?) : TunnelState

    public data class Error(override val profileId: String?, val message: String) : TunnelState
}

/** Traffic counters of a running tunnel. */
@Serializable
public data class TunnelStatistics(
    val rxBytes: Long,
    val txBytes: Long,
    /** Most recent WireGuard handshake, epoch seconds (WireGuard / AmneziaWG only). */
    val lastHandshakeEpochSeconds: Long? = null,
    val peers: List<PeerStatistics> = emptyList(),
)

@Serializable
public data class PeerStatistics(
    val publicKey: String,
    val rxBytes: Long,
    val txBytes: Long,
    val lastHandshakeEpochSeconds: Long? = null,
)
