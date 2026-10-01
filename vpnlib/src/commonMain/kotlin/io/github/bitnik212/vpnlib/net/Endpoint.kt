package io.github.bitnik212.vpnlib.net

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * A remote `host:port`. [host] is a hostname or an IP literal (IPv6 without
 * brackets).
 */
@Serializable(with = EndpointSerializer::class)
public data class Endpoint(val host: String, val port: Int) {

    init {
        require(host.isNotBlank()) { "Endpoint host must not be blank" }
        require(port in 1..65535) { "Invalid port $port" }
    }

    /** The host as an IP address, or null when it is a hostname. */
    public val ipAddress: IpAddress? get() = IpAddress.parseOrNull(host)

    public val isResolved: Boolean get() = ipAddress != null

    /** `host:port`, with brackets around IPv6 literals. */
    override fun toString(): String = if (ipAddress?.isIpv6 == true) "[$host]:$port" else "$host:$port"

    public companion object {
        public fun parse(text: String): Endpoint =
            parseOrNull(text) ?: throw IllegalArgumentException("Invalid endpoint: '$text'")

        public fun parseOrNull(text: String): Endpoint? {
            val value = text.trim()
            val host: String
            val portText: String
            if (value.startsWith("[")) {
                val end = value.indexOf("]:")
                if (end < 0) return null
                host = value.substring(1, end)
                portText = value.substring(end + 2)
                if (IpAddress.parseOrNull(host)?.isIpv6 != true) return null
            } else {
                val colon = value.lastIndexOf(':')
                if (colon <= 0 || value.indexOf(':') != colon) return null
                host = value.substring(0, colon)
                portText = value.substring(colon + 1)
            }
            val port = portText.toIntOrNull() ?: return null
            if (host.isBlank() || port !in 1..65535) return null
            return Endpoint(host, port)
        }
    }
}

internal object EndpointSerializer : KSerializer<Endpoint> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("io.github.bitnik212.vpnlib.net.Endpoint", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Endpoint): Unit = encoder.encodeString(value.toString())

    override fun deserialize(decoder: Decoder): Endpoint = Endpoint.parse(decoder.decodeString())
}
