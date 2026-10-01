package io.github.bitnik212.vpnlib.config.wireguard

import io.github.bitnik212.vpnlib.config.WgBasedConfig
import io.github.bitnik212.vpnlib.config.WireGuardConfig
import io.github.bitnik212.vpnlib.config.AmneziaWgConfig
import io.github.bitnik212.vpnlib.config.WgInterface
import io.github.bitnik212.vpnlib.config.WgPeer
import io.github.bitnik212.vpnlib.config.ConfigException
import io.github.bitnik212.vpnlib.net.Endpoint
import io.github.bitnik212.vpnlib.net.IpAddress
import io.github.bitnik212.vpnlib.net.IpPrefix

/**
 * Reader / writer for wg-quick style `.conf` files, including the AmneziaWG
 * keys (`Jc`, `S1`, `H1`, `I1`, ...) and wireguard-android's
 * `IncludedApplications` / `ExcludedApplications`.
 *
 * wg-quick-only keys that have no meaning on mobile (`Table`, `PreUp`,
 * `PostDown`, `SaveConfig`, `FwMark`, ...) are ignored.
 */
public object WgQuickFormat {

    private val IGNORED_KEYS = setOf(
        "table", "preup", "postup", "predown", "postdown", "saveconfig", "fwmark",
    )

    /**
     * Parses a config. Returns [AmneziaWgConfig] when any AmneziaWG parameter
     * is present, [WireGuardConfig] otherwise. The result is not validated,
     * call [WgBasedConfig.validate] before use.
     */
    @Throws(ConfigException::class)
    public fun parse(text: String): WgBasedConfig {
        var section: String? = null
        var iface: MutableMap<String, MutableList<String>>? = null
        val peers = mutableListOf<MutableMap<String, MutableList<String>>>()

        text.lineSequence().forEachIndexed { index, rawLine ->
            val line = rawLine.substringBefore('#').trim()
            if (line.isEmpty()) return@forEachIndexed
            if (line.startsWith("[") && line.endsWith("]")) {
                section = line.substring(1, line.length - 1).trim().lowercase()
                when (section) {
                    "interface" -> {
                        if (iface != null) throw ConfigException("Line ${index + 1}: duplicate [Interface] section")
                        iface = mutableMapOf()
                    }
                    "peer" -> peers += mutableMapOf()
                    else -> throw ConfigException("Line ${index + 1}: unknown section [$section]")
                }
                return@forEachIndexed
            }
            val eq = line.indexOf('=')
            if (eq <= 0) throw ConfigException("Line ${index + 1}: expected 'Key = Value'")
            val key = line.substring(0, eq).trim().lowercase()
            val value = line.substring(eq + 1).trim()
            val target = when (section) {
                "interface" -> iface!!
                "peer" -> peers.last()
                else -> throw ConfigException("Line ${index + 1}: key outside of a section")
            }
            target.getOrPut(key) { mutableListOf() } += value
        }

        val ifaceValues = iface ?: throw ConfigException("Missing [Interface] section")
        return try {
            build(ifaceValues, peers)
        } catch (e: ConfigException) {
            throw e
        } catch (e: IllegalArgumentException) {
            throw ConfigException(e.message ?: "Invalid config", e)
        }
    }

    private fun build(
        values: Map<String, List<String>>,
        peerValues: List<Map<String, List<String>>>,
    ): WgBasedConfig {
        fun Map<String, List<String>>.single(key: String): String? = this[key]?.last()
        fun Map<String, List<String>>.list(key: String): List<String> =
            this[key].orEmpty().flatMap { it.split(',') }.map { it.trim() }.filter { it.isNotEmpty() }
        fun Map<String, List<String>>.int(key: String): Int? =
            single(key)?.let { it.toIntOrNull() ?: throw ConfigException("$key: '$it' is not a number") }

        val known = setOf(
            "privatekey", "address", "dns", "listenport", "mtu",
            "includedapplications", "excludedapplications",
        ) + AMNEZIA_KEYS + IGNORED_KEYS
        values.keys.firstOrNull { it !in known }?.let { throw ConfigException("Unknown [Interface] key '$it'") }

        val dns = values.list("dns")
        val iface = WgInterface(
            privateKey = values.single("privatekey") ?: throw ConfigException("PrivateKey is required"),
            addresses = values.list("address").map(IpPrefix::parse),
            dnsServers = dns.filter(IpAddress::isValid),
            dnsSearchDomains = dns.filterNot(IpAddress::isValid),
            listenPort = values.int("listenport"),
            mtu = values.int("mtu"),
            includedApplications = values.list("includedapplications"),
            excludedApplications = values.list("excludedapplications"),
        )

        val peerKeys = setOf("publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive")
        val peers = peerValues.mapIndexed { i, peer ->
            peer.keys.firstOrNull { it !in peerKeys }?.let { throw ConfigException("Unknown [Peer] key '$it'") }
            WgPeer(
                publicKey = peer.single("publickey") ?: throw ConfigException("peer #${i + 1}: PublicKey is required"),
                presharedKey = peer.single("presharedkey"),
                allowedIps = peer.list("allowedips").map(IpPrefix::parse),
                endpoint = peer.single("endpoint")?.let {
                    Endpoint.parseOrNull(it) ?: throw ConfigException("peer #${i + 1}: invalid Endpoint '$it'")
                },
                persistentKeepalive = peer.single("persistentkeepalive")?.let {
                    if (it.equals("off", ignoreCase = true)) 0 else it.toIntOrNull()
                        ?: throw ConfigException("PersistentKeepalive: '$it' is not a number")
                },
            )
        }

        val amnezia = AmneziaParams(
            jc = values.int("jc"),
            jmin = values.int("jmin"),
            jmax = values.int("jmax"),
            s1 = values.int("s1"),
            s2 = values.int("s2"),
            s3 = values.int("s3"),
            s4 = values.int("s4"),
            h1 = values.single("h1"),
            h2 = values.single("h2"),
            h3 = values.single("h3"),
            h4 = values.single("h4"),
            i1 = values.single("i1"),
            i2 = values.single("i2"),
            i3 = values.single("i3"),
            i4 = values.single("i4"),
            i5 = values.single("i5"),
            j1 = values.single("j1"),
            j2 = values.single("j2"),
            j3 = values.single("j3"),
            itime = values.int("itime"),
        )
        return if (amnezia.isEmpty) WireGuardConfig(iface, peers) else AmneziaWgConfig(iface, peers, amnezia)
    }

    /** Formats a config in wg-quick syntax. */
    public fun format(config: WgBasedConfig): String = buildString {
        val iface = config.iface
        appendLine("[Interface]")
        appendLine("PrivateKey = ${iface.privateKey}")
        if (iface.addresses.isNotEmpty()) appendLine("Address = ${iface.addresses.joinToString(", ")}")
        val dns = iface.dnsServers + iface.dnsSearchDomains
        if (dns.isNotEmpty()) appendLine("DNS = ${dns.joinToString(", ")}")
        iface.listenPort?.let { appendLine("ListenPort = $it") }
        iface.mtu?.let { appendLine("MTU = $it") }
        if (iface.includedApplications.isNotEmpty()) {
            appendLine("IncludedApplications = ${iface.includedApplications.joinToString(", ")}")
        }
        if (iface.excludedApplications.isNotEmpty()) {
            appendLine("ExcludedApplications = ${iface.excludedApplications.joinToString(", ")}")
        }
        config.amneziaParams?.entries()?.forEach { (key, value) -> appendLine("$key = $value") }
        for (peer in config.peers) {
            appendLine()
            appendLine("[Peer]")
            appendLine("PublicKey = ${peer.publicKey}")
            peer.presharedKey?.let { appendLine("PresharedKey = $it") }
            if (peer.allowedIps.isNotEmpty()) appendLine("AllowedIPs = ${peer.allowedIps.joinToString(", ")}")
            peer.endpoint?.let { appendLine("Endpoint = $it") }
            peer.persistentKeepalive?.takeIf { it > 0 }?.let { appendLine("PersistentKeepalive = $it") }
        }
    }

    private val AMNEZIA_KEYS = setOf(
        "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
        "i1", "i2", "i3", "i4", "i5", "j1", "j2", "j3", "itime",
    )
}
