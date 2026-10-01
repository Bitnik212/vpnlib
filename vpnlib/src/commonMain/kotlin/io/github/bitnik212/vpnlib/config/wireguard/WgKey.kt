package io.github.bitnik212.vpnlib.config.wireguard

import kotlin.io.encoding.Base64

/** Helpers for 32-byte Curve25519 keys in their base64 text form. */
public object WgKey {
    public const val SIZE: Int = 32

    public fun isValid(base64: String): Boolean = decodeOrNull(base64) != null

    /** Lowercase hex, the encoding used by the WireGuard UAPI. */
    public fun toHex(base64: String): String {
        val bytes = decodeOrNull(base64) ?: throw IllegalArgumentException("Invalid WireGuard key")
        return bytes.toHexString()
    }

    public fun fromHex(hex: String): String {
        require(hex.length == SIZE * 2) { "Invalid WireGuard key" }
        return Base64.encode(hex.hexToByteArray())
    }

    private fun decodeOrNull(base64: String): ByteArray? {
        val value = base64.trim()
        if (value.length != 44 || !value.endsWith("=")) return null
        return runCatching { Base64.decode(value) }.getOrNull()?.takeIf { it.size == SIZE }
    }
}
