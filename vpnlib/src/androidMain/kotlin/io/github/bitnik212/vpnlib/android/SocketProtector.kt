package io.github.bitnik212.vpnlib.android

/**
 * Excludes a socket from the VPN, normally [android.net.VpnService.protect].
 * Called from native code through JNI.
 */
public fun interface SocketProtector {
    public fun protect(fd: Int): Boolean
}
