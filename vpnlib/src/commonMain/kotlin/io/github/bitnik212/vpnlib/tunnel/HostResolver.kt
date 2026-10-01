package io.github.bitnik212.vpnlib.tunnel

/**
 * Resolves server hostnames before the tunnel is up. Platform resolvers use
 * the system DNS of the underlying network.
 */
public fun interface HostResolver {
    /** IP literals for [host], IPv4 first; throws if nothing can be resolved. */
    public suspend fun resolve(host: String): List<String>
}
