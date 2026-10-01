package io.github.bitnik212.vpnlib.android.internal

import io.github.bitnik212.vpnlib.android.SocketProtector

/** JNI bindings of libvpncore.so (native/vpncore/jni_android.c). */
internal object NativeCore {
    init {
        System.loadLibrary("vpncore")
        nativeInit()
    }

    private external fun nativeInit()

    external fun version(): String

    external fun lastError(): String?

    external fun setProtector(protector: SocketProtector?)

    external fun setDnsServers(servers: String)

    external fun awgTurnOn(tunFd: Int, settings: String): Int

    external fun awgTurnOff(handle: Int)

    external fun awgGetConfig(handle: Int): String?

    external fun awgBumpSockets(handle: Int)

    external fun xrayStart(tunFd: Int, config: String): Int

    external fun xrayStop(handle: Int)

    external fun xrayGetStats(handle: Int): String?
}
