package io.github.bitnik212.vpnlib.android

import android.net.Network
import io.github.bitnik212.vpnlib.tunnel.HostResolver
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.Inet4Address
import java.net.InetAddress

/**
 * Resolves with the system resolver, optionally on a specific (underlying,
 * non-VPN) [network].
 */
public class AndroidHostResolver(private val network: Network? = null) : HostResolver {
    override suspend fun resolve(host: String): List<String> = withContext(Dispatchers.IO) {
        val addresses = network?.getAllByName(host) ?: InetAddress.getAllByName(host)
        addresses.sortedBy { if (it is Inet4Address) 0 else 1 }.mapNotNull { it.hostAddress?.substringBefore('%') }
    }
}
