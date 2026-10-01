package io.github.bitnik212.vpnlib.config.wireguard

import kotlinx.serialization.Serializable

/**
 * AmneziaWG obfuscation parameters. All are optional; a config without any of
 * them is wire compatible with plain WireGuard.
 *
 * - `Jc`, `Jmin`, `Jmax`: count and size range of junk packets sent before a handshake.
 * - `S1`..`S4`: random padding added to init / response / cookie / transport packets.
 * - `H1`..`H4`: message type headers replacing WireGuard's 1..4 (number or `min-max` range).
 * - `I1`..`I5`: AmneziaWG 1.5 "special junk" packets in tag syntax, e.g. `<b 0xf6ab3267fa><r 10>`.
 * - `J1`..`J3`, `Itime`: AmneziaWG 1.5 controlled junk packets and their interval.
 *
 * Both sides of the tunnel must use identical values (except `J*`/`I*`).
 */
@Serializable
public data class AmneziaParams(
    val jc: Int? = null,
    val jmin: Int? = null,
    val jmax: Int? = null,
    val s1: Int? = null,
    val s2: Int? = null,
    val s3: Int? = null,
    val s4: Int? = null,
    val h1: String? = null,
    val h2: String? = null,
    val h3: String? = null,
    val h4: String? = null,
    val i1: String? = null,
    val i2: String? = null,
    val i3: String? = null,
    val i4: String? = null,
    val i5: String? = null,
    val j1: String? = null,
    val j2: String? = null,
    val j3: String? = null,
    val itime: Int? = null,
) {
    /** True when no parameter is set (behaves like plain WireGuard). */
    public val isEmpty: Boolean get() = entries().isEmpty()

    /** Set parameters as (config key, value) pairs in canonical order. */
    public fun entries(): List<Pair<String, String>> = listOfNotNull(
        jc?.let { "Jc" to it.toString() },
        jmin?.let { "Jmin" to it.toString() },
        jmax?.let { "Jmax" to it.toString() },
        s1?.let { "S1" to it.toString() },
        s2?.let { "S2" to it.toString() },
        s3?.let { "S3" to it.toString() },
        s4?.let { "S4" to it.toString() },
        h1?.let { "H1" to it },
        h2?.let { "H2" to it },
        h3?.let { "H3" to it },
        h4?.let { "H4" to it },
        i1?.let { "I1" to it },
        i2?.let { "I2" to it },
        i3?.let { "I3" to it },
        i4?.let { "I4" to it },
        i5?.let { "I5" to it },
        j1?.let { "J1" to it },
        j2?.let { "J2" to it },
        j3?.let { "J3" to it },
        itime?.let { "Itime" to it.toString() },
    )

    internal fun problems(): List<String> = buildList {
        if (jc != null && jc !in 0..128) add("Jc must be within 0..128")
        listOf("Jmin" to jmin, "Jmax" to jmax).forEach { (key, value) ->
            if (value != null && value !in 0..MAX_JUNK_SIZE) add("$key must be within 0..$MAX_JUNK_SIZE")
        }
        if (jmin != null && jmax != null && jmin > jmax) add("Jmin must not be greater than Jmax")
        if ((jc ?: 0) > 0 && (jmin == null || jmax == null)) add("Jmin and Jmax are required when Jc > 0")
        listOf("S1" to s1, "S2" to s2, "S3" to s3, "S4" to s4).forEach { (key, value) ->
            if (value != null && value !in 0..MAX_JUNK_SIZE) add("$key must be within 0..$MAX_JUNK_SIZE")
        }
        // Init (148 bytes) and response (92 bytes) messages must stay distinguishable by size.
        if (s1 != null && s2 != null && s1 + INIT_RESPONSE_SIZE_DIFF == s2) add("S1 + 56 must not equal S2")
        val headers = listOfNotNull(h1, h2, h3, h4)
        headers.forEach { if (parseHeaderRange(it) == null) add("H value '$it' is not a number or range") }
        val ranges = headers.mapNotNull(::parseHeaderRange)
        for (a in ranges.indices) for (b in a + 1 until ranges.size) {
            if (ranges[a].first <= ranges[b].last && ranges[b].first <= ranges[a].last) {
                add("H1..H4 must not overlap")
            }
        }
        if (itime != null && itime < 0) add("Itime must not be negative")
    }

    public companion object {
        private const val MAX_JUNK_SIZE = 1280
        private const val INIT_RESPONSE_SIZE_DIFF = 56

        /** Parses `123` or `100-200` into an inclusive range of uint32 values. */
        internal fun parseHeaderRange(value: String): LongRange? {
            val parts = value.trim().split('-')
            val numbers = parts.map { it.trim().toLongOrNull() ?: return null }
            if (numbers.any { it !in 0..0xffffffffL }) return null
            return when (numbers.size) {
                1 -> numbers[0]..numbers[0]
                2 -> if (numbers[0] <= numbers[1]) numbers[0]..numbers[1] else null
                else -> null
            }
        }
    }
}
