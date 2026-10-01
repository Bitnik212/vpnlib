package io.github.bitnik212.vpnlib.config

import kotlinx.serialization.Serializable

/** VPN protocols supported by the library. */
@Serializable
public enum class VpnProtocol {
    WIREGUARD,
    AMNEZIA_WG,
    XRAY,
}

/**
 * Protocol specific connection configuration.
 *
 * Implementations: [io.github.bitnik212.vpnlib.config.wireguard.WireGuardConfig],
 * [io.github.bitnik212.vpnlib.config.wireguard.AmneziaWgConfig] and
 * [io.github.bitnik212.vpnlib.config.xray.XrayConfig].
 */
@Serializable
public sealed interface VpnConfig {
    public val protocol: VpnProtocol

    /**
     * Checks the configuration for errors that would prevent the tunnel from
     * starting.
     *
     * @throws ConfigException describing every problem found.
     */
    @Throws(ConfigException::class)
    public fun validate()
}

/** Thrown for malformed or inconsistent configurations. */
public class ConfigException(message: String, cause: Throwable? = null) : IllegalArgumentException(message, cause)

internal fun throwIfProblems(subject: String, problems: List<String>) {
    if (problems.isNotEmpty()) {
        throw ConfigException("Invalid $subject: " + problems.joinToString("; "))
    }
}
