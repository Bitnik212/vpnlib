package io.github.bitnik212.vpnlib.net

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * An address with a prefix length in CIDR notation, e.g. `10.0.0.2/32` or
 * `::/0`. The address may contain host bits (interface addresses do); use
 * [network] to get the normalized network prefix (routes need it).
 */
@Serializable(with = IpPrefixSerializer::class)
public data class IpPrefix(val address: IpAddress, val prefixLength: Int) {

    init {
        require(prefixLength in 0..address.bitLength) {
            "Invalid prefix length $prefixLength for $address"
        }
    }

    public val isIpv4: Boolean get() = address.isIpv4
    public val isIpv6: Boolean get() = address.isIpv6

    /** The prefix with host bits cleared. */
    public val network: IpPrefix get() = IpPrefix(address.masked(prefixLength), prefixLength)

    /** True when this is a whole address family route (`0.0.0.0/0`, `::/0`). */
    public val isDefaultRoute: Boolean get() = prefixLength == 0

    public operator fun contains(other: IpPrefix): Boolean =
        address.bitLength == other.address.bitLength &&
            prefixLength <= other.prefixLength &&
            other.address.masked(prefixLength) == address.masked(prefixLength)

    public operator fun contains(other: IpAddress): Boolean =
        contains(IpPrefix(other, other.bitLength))

    public fun overlaps(other: IpPrefix): Boolean = contains(other) || other.contains(this)

    /** IPv4 netmask in dotted form, e.g. `255.255.255.0` for /24. */
    public fun ipv4Netmask(): String {
        check(isIpv4) { "netmask is only defined for IPv4 prefixes" }
        val mask = if (prefixLength == 0) 0L else (0xffffffffL shl (32 - prefixLength)) and 0xffffffffL
        return listOf(24, 16, 8, 0).joinToString(".") { ((mask shr it) and 0xff).toString() }
    }

    /** Splits the prefix into its two halves (one bit longer). */
    internal fun split(): Pair<IpPrefix, IpPrefix> {
        check(prefixLength < address.bitLength) { "cannot split a host prefix" }
        val base = address.masked(prefixLength)
        return IpPrefix(base, prefixLength + 1) to IpPrefix(base.withBit(prefixLength, true), prefixLength + 1)
    }

    override fun toString(): String = "$address/$prefixLength"

    public companion object {
        /** Parses `addr/len`; a bare address becomes a host prefix (/32 or /128). */
        public fun parse(text: String): IpPrefix =
            parseOrNull(text) ?: throw IllegalArgumentException("Invalid IP prefix: '$text'")

        public fun parseOrNull(text: String): IpPrefix? {
            val value = text.trim()
            val slash = value.lastIndexOf('/')
            val address = IpAddress.parseOrNull(if (slash >= 0) value.substring(0, slash) else value) ?: return null
            val length = if (slash >= 0) {
                value.substring(slash + 1).toIntOrNull() ?: return null
            } else {
                address.bitLength
            }
            if (length !in 0..address.bitLength) return null
            return IpPrefix(address, length)
        }

        public val IPV4_DEFAULT: IpPrefix = parse("0.0.0.0/0")
        public val IPV6_DEFAULT: IpPrefix = parse("::/0")
    }
}

internal object IpPrefixSerializer : KSerializer<IpPrefix> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("io.github.bitnik212.vpnlib.net.IpPrefix", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: IpPrefix): Unit = encoder.encodeString(value.toString())

    override fun deserialize(decoder: Decoder): IpPrefix = IpPrefix.parse(decoder.decodeString())
}
