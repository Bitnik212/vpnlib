package io.github.bitnik212.vpnlib.tunnel

/**
 * Bindings to the native engines in libvpncore (see native/vpncore). Each
 * platform provides an implementation; tests use fakes.
 *
 * Engines never take ownership of `tunFd`, they work on their own duplicate.
 */
public interface VpnCore {
    /** Starts WireGuard / AmneziaWG with a UAPI config and returns a handle. */
    public fun wireGuardStart(tunFd: Int, uapiConfig: String): Int

    public fun wireGuardStop(handle: Int)

    /** UAPI `get` output for [handle]. */
    public fun wireGuardGetConfig(handle: Int): String?

    /** Starts Xray with a JSON config and returns a handle. */
    public fun xrayStart(tunFd: Int, jsonConfig: String): Int

    public fun xrayStop(handle: Int)

    /** `uplink=N\ndownlink=N` counters for [handle]. */
    public fun xrayGetStats(handle: Int): String?

    public fun version(): String
}

/** Failure reported by the native engines or the platform VPN API. */
public class VpnException(message: String, cause: Throwable? = null) : Exception(message, cause)
