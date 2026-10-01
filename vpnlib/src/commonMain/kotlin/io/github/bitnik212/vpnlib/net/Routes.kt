package io.github.bitnik212.vpnlib.net

/**
 * Route set arithmetic used to build tunnel routing tables. Platforms differ
 * in how they support excluded routes (Android only from API 33), so
 * exclusions are applied up front by computing the complement.
 */
public object Routes {

    /** Private, link-local and multicast ranges kept outside the tunnel when LAN access is allowed. */
    public val LOCAL_NETWORKS: List<IpPrefix> = listOf(
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "255.255.255.255/32",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ).map(IpPrefix::parse)

    /**
     * Normalizes [prefixes]: clears host bits, removes duplicates and prefixes
     * covered by others, and sorts the result.
     */
    public fun normalize(prefixes: Iterable<IpPrefix>): List<IpPrefix> {
        val sorted = prefixes.map { it.network }.distinct()
            .sortedWith(compareBy<IpPrefix> { it.address.bitLength }.thenBy { it.address }.thenBy { it.prefixLength })
        val result = mutableListOf<IpPrefix>()
        for (prefix in sorted) {
            if (result.none { it.contains(prefix) }) result += prefix
        }
        return result
    }

    /** Returns [included] minus every prefix in [excluded]. */
    public fun subtract(included: Iterable<IpPrefix>, excluded: Iterable<IpPrefix>): List<IpPrefix> {
        var current = normalize(included)
        for (exclusion in normalize(excluded)) {
            current = current.flatMap { subtract(it, exclusion) }
        }
        return normalize(current)
    }

    private fun subtract(prefix: IpPrefix, exclusion: IpPrefix): List<IpPrefix> = when {
        !prefix.overlaps(exclusion) -> listOf(prefix)
        exclusion.contains(prefix) -> emptyList()
        else -> {
            // prefix strictly contains exclusion: keep the half that does not
            // contain it and recurse into the other one.
            val (low, high) = prefix.split()
            if (low.contains(exclusion)) subtract(low, exclusion) + high else listOf(low) + subtract(high, exclusion)
        }
    }
}
