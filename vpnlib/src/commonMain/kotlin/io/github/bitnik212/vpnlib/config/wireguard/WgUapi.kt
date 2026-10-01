package io.github.bitnik212.vpnlib.config.wireguard

import io.github.bitnik212.vpnlib.config.WgBasedConfig
import io.github.bitnik212.vpnlib.net.Endpoint
import io.github.bitnik212.vpnlib.tunnel.PeerStatistics
import io.github.bitnik212.vpnlib.tunnel.TunnelStatistics

/**
 * Builds and parses the cross-platform userspace API (UAPI) text understood by
 * wireguard-go / amneziawg-go (`set=1` bodies and `get=1` replies).
 */
public object WgUapi {

    /**
     * UAPI configuration for [config].
     *
     * wireguard-go only accepts IP literals as endpoints, so hostnames must be
     * resolved first: [resolvedEndpoints] maps every hostname endpoint of the
     * config to an IP endpoint.
     */
    public fun build(config: WgBasedConfig, resolvedEndpoints: Map<Endpoint, Endpoint> = emptyMap()): String =
        buildString {
            fun line(key: String, value: Any) = append(key).append('=').append(value).append('\n')

            line("private_key", WgKey.toHex(config.iface.privateKey))
            config.iface.listenPort?.let { line("listen_port", it) }
            config.amneziaParams?.entries()?.forEach { (key, value) -> line(key.lowercase(), value) }
            line("replace_peers", "true")
            for (peer in config.peers) {
                line("public_key", WgKey.toHex(peer.publicKey))
                peer.presharedKey?.let { line("preshared_key", WgKey.toHex(it)) }
                peer.endpoint?.let { endpoint ->
                    val resolved = if (endpoint.isResolved) endpoint else resolvedEndpoints[endpoint]
                    requireNotNull(resolved) { "Endpoint $endpoint has not been resolved" }
                    line("endpoint", resolved)
                }
                line("persistent_keepalive_interval", peer.persistentKeepalive ?: 0)
                line("replace_allowed_ips", "true")
                peer.allowedIps.forEach { line("allowed_ip", it.network) }
            }
        }

    /** Parses traffic counters from a UAPI `get=1` reply. */
    public fun parseStatistics(uapi: String): TunnelStatistics {
        val peers = mutableListOf<PeerStatistics>()
        var publicKey: String? = null
        var rx = 0L
        var tx = 0L
        var handshake: Long? = null

        fun flush() {
            publicKey?.let { peers += PeerStatistics(WgKey.fromHex(it), rx, tx, handshake) }
            rx = 0
            tx = 0
            handshake = null
        }

        for (line in uapi.lineSequence()) {
            val key = line.substringBefore('=', missingDelimiterValue = "")
            val value = line.substringAfter('=', missingDelimiterValue = "")
            when (key) {
                "public_key" -> {
                    flush()
                    publicKey = value
                }
                "rx_bytes" -> rx = value.toLongOrNull() ?: 0
                "tx_bytes" -> tx = value.toLongOrNull() ?: 0
                "last_handshake_time_sec" -> handshake = value.toLongOrNull()?.takeIf { it > 0 }
            }
        }
        flush()
        return TunnelStatistics(
            rxBytes = peers.sumOf { it.rxBytes },
            txBytes = peers.sumOf { it.txBytes },
            lastHandshakeEpochSeconds = peers.mapNotNull { it.lastHandshakeEpochSeconds }.maxOrNull(),
            peers = peers,
        )
    }
}
