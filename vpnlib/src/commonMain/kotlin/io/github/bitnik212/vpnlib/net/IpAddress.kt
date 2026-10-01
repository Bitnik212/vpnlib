package io.github.bitnik212.vpnlib.net

/**
 * An IPv4 or IPv6 address literal (no hostnames).
 */
public class IpAddress private constructor(private val bytes: ByteArray) : Comparable<IpAddress> {

    public val isIpv4: Boolean get() = bytes.size == 4
    public val isIpv6: Boolean get() = bytes.size == 16

    /** Size of the address in bits: 32 or 128. */
    public val bitLength: Int get() = bytes.size * 8

    public fun toByteArray(): ByteArray = bytes.copyOf()

    internal fun bit(index: Int): Boolean = (bytes[index / 8].toInt() shr (7 - index % 8)) and 1 == 1

    /** Keeps the first [prefixLength] bits and zeroes the rest. */
    public fun masked(prefixLength: Int): IpAddress {
        require(prefixLength in 0..bitLength) { "prefix length $prefixLength out of range for $this" }
        val result = bytes.copyOf()
        for (i in result.indices) {
            val bitsInByte = (prefixLength - i * 8).coerceIn(0, 8)
            result[i] = (result[i].toInt() and (0xff shl (8 - bitsInByte))).toByte()
        }
        return IpAddress(result)
    }

    /** Returns a copy with bit [index] set to [value]. */
    internal fun withBit(index: Int, value: Boolean): IpAddress {
        val result = bytes.copyOf()
        val mask = 1 shl (7 - index % 8)
        val current = result[index / 8].toInt()
        result[index / 8] = (if (value) current or mask else current and mask.inv()).toByte()
        return IpAddress(result)
    }

    override fun compareTo(other: IpAddress): Int {
        if (bytes.size != other.bytes.size) return bytes.size - other.bytes.size
        for (i in bytes.indices) {
            val diff = (bytes[i].toInt() and 0xff) - (other.bytes[i].toInt() and 0xff)
            if (diff != 0) return diff
        }
        return 0
    }

    override fun equals(other: Any?): Boolean = other is IpAddress && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()

    /** Canonical text form (RFC 5952 for IPv6). */
    override fun toString(): String = if (isIpv4) formatV4() else formatV6()

    private fun formatV4(): String = bytes.joinToString(".") { (it.toInt() and 0xff).toString() }

    private fun formatV6(): String {
        val groups = IntArray(8) { ((bytes[it * 2].toInt() and 0xff) shl 8) or (bytes[it * 2 + 1].toInt() and 0xff) }
        // Longest run of zero groups (length >= 2) is compressed to "::".
        var bestStart = -1
        var bestLength = 0
        var i = 0
        while (i < 8) {
            if (groups[i] == 0) {
                var j = i
                while (j < 8 && groups[j] == 0) j++
                if (j - i > bestLength && j - i >= 2) {
                    bestStart = i
                    bestLength = j - i
                }
                i = j
            } else {
                i++
            }
        }
        if (bestStart < 0) return groups.joinToString(":") { it.toString(16) }
        val head = groups.copyOfRange(0, bestStart).joinToString(":") { it.toString(16) }
        val tail = groups.copyOfRange(bestStart + bestLength, 8).joinToString(":") { it.toString(16) }
        return "$head::$tail"
    }

    public companion object {
        /** Parses an IPv4 or IPv6 literal. IPv6 zone ids ("%eth0") are dropped. */
        public fun parse(text: String): IpAddress =
            parseOrNull(text) ?: throw IllegalArgumentException("Invalid IP address: '$text'")

        public fun parseOrNull(text: String): IpAddress? {
            val value = text.trim().removePrefix("[").removeSuffix("]")
            if (value.isEmpty()) return null
            val bytes = if (':' in value) parseV6(value.substringBefore('%')) else parseV4(value)
            return bytes?.let(::IpAddress)
        }

        public fun isValid(text: String): Boolean = parseOrNull(text) != null

        internal fun fromBytes(bytes: ByteArray): IpAddress {
            require(bytes.size == 4 || bytes.size == 16) { "IP address must have 4 or 16 bytes" }
            return IpAddress(bytes.copyOf())
        }

        private fun parseV4(text: String): ByteArray? {
            val parts = text.split('.')
            if (parts.size != 4) return null
            val result = ByteArray(4)
            for ((i, part) in parts.withIndex()) {
                if (part.isEmpty() || part.length > 3 || !part.all { it in '0'..'9' }) return null
                val value = part.toInt()
                if (value > 255) return null
                result[i] = value.toByte()
            }
            return result
        }

        private fun parseV6(text: String): ByteArray? {
            if (text.count { it == ':' } < 2) return null
            val doubleColon = text.indexOf("::")
            if (doubleColon >= 0 && text.indexOf("::", doubleColon + 1) >= 0) return null

            fun parseGroups(part: String, allowV4Tail: Boolean): List<Int>? {
                if (part.isEmpty()) return emptyList()
                val tokens = part.split(':')
                val result = mutableListOf<Int>()
                for ((i, token) in tokens.withIndex()) {
                    if (allowV4Tail && i == tokens.lastIndex && '.' in token) {
                        val v4 = parseV4(token) ?: return null
                        result += ((v4[0].toInt() and 0xff) shl 8) or (v4[1].toInt() and 0xff)
                        result += ((v4[2].toInt() and 0xff) shl 8) or (v4[3].toInt() and 0xff)
                        continue
                    }
                    if (token.isEmpty() || token.length > 4) return null
                    result += token.toIntOrNull(16) ?: return null
                }
                return result
            }

            val groups: List<Int> = if (doubleColon >= 0) {
                val head = parseGroups(text.substring(0, doubleColon), allowV4Tail = false) ?: return null
                val tail = parseGroups(text.substring(doubleColon + 2), allowV4Tail = true) ?: return null
                val missing = 8 - head.size - tail.size
                if (missing < 1) return null
                head + List(missing) { 0 } + tail
            } else {
                parseGroups(text, allowV4Tail = true) ?: return null
            }
            if (groups.size != 8) return null
            val result = ByteArray(16)
            for ((i, group) in groups.withIndex()) {
                result[i * 2] = (group shr 8).toByte()
                result[i * 2 + 1] = group.toByte()
            }
            return result
        }
    }
}
