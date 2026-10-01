package io.github.bitnik212.vpnlib.ios

import io.github.bitnik212.vpnlib.tunnel.HostResolver
import io.github.bitnik212.vpnlib.tunnel.VpnException
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.toKString
import kotlinx.cinterop.value
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withContext
import platform.posix.AF_INET
import platform.posix.AF_INET6
import platform.posix.AF_UNSPEC
import platform.posix.SOCK_STREAM
import platform.posix.addrinfo
import platform.posix.freeaddrinfo
import platform.posix.gai_strerror
import platform.posix.getaddrinfo
import platform.darwin.inet_ntop
import platform.posix.memset
import platform.posix.sockaddr_in
import platform.posix.sockaddr_in6

/** Resolves hostnames with getaddrinfo (system DNS, outside the tunnel). */
public class IosHostResolver : HostResolver {
    override suspend fun resolve(host: String): List<String> = withContext(Dispatchers.IO) { resolveBlocking(host) }

    private fun resolveBlocking(host: String): List<String> = memScoped {
        val hints = alloc<addrinfo>()
        memset(hints.ptr, 0, sizeOf<addrinfo>().convert())
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM

        val result = alloc<CPointerVar<addrinfo>>()
        val rc = getaddrinfo(host, null, hints.ptr, result.ptr)
        if (rc != 0) throw VpnException("getaddrinfo($host): ${gai_strerror(rc)?.toKString()}")

        val buffer = allocArray<ByteVar>(INET6_ADDRSTRLEN)
        val addresses = mutableListOf<String>()
        try {
            var node = result.value
            while (node != null) {
                val info = node.pointed
                val sockaddr = info.ai_addr
                val text = when {
                    sockaddr == null -> null
                    info.ai_family == AF_INET -> inet_ntop(
                        AF_INET,
                        sockaddr.reinterpret<sockaddr_in>().pointed.sin_addr.ptr,
                        buffer,
                        INET6_ADDRSTRLEN.convert(),
                    )
                    info.ai_family == AF_INET6 -> inet_ntop(
                        AF_INET6,
                        sockaddr.reinterpret<sockaddr_in6>().pointed.sin6_addr.ptr,
                        buffer,
                        INET6_ADDRSTRLEN.convert(),
                    )
                    else -> null
                }
                text?.toKString()?.let { addresses += it }
                node = info.ai_next
            }
        } finally {
            freeaddrinfo(result.value)
        }
        addresses.distinct().sortedBy { if (':' in it) 1 else 0 }
    }

    private companion object {
        const val INET6_ADDRSTRLEN = 46
    }
}
