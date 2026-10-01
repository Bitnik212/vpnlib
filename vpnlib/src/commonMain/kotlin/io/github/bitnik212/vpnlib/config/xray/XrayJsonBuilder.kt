package io.github.bitnik212.vpnlib.config.xray

import io.github.bitnik212.vpnlib.config.XrayConfig
import io.github.bitnik212.vpnlib.config.ConfigException
import io.github.bitnik212.vpnlib.net.IpAddress
import io.github.bitnik212.vpnlib.net.Routes
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject

/**
 * Generates Xray-core JSON configs that read packets from the OS tunnel
 * through Xray's `tun` inbound.
 */
public object XrayJsonBuilder {

    public const val TUN_INBOUND_TAG: String = "tun-in"
    public const val PROXY_TAG: String = "proxy"
    public const val DIRECT_TAG: String = "direct"
    public const val BLOCK_TAG: String = "block"
    public const val DNS_TAG: String = "dns-out"

    private val prettyJson = Json { prettyPrint = true }

    /**
     * @param resolvedServerAddress IP to connect to instead of the outbound's
     *   hostname. The hostname is kept for TLS SNI and HTTP host headers.
     */
    public fun build(config: XrayConfig, resolvedServerAddress: String? = null): String {
        val root = when {
            config.outbound != null -> generate(config, config.outbound, resolvedServerAddress)
            config.rawJson != null -> injectTun(config, config.rawJson)
            else -> throw ConfigException("Xray config has neither an outbound nor raw JSON")
        }
        return prettyJson.encodeToString(JsonObject.serializer(), root)
    }

    private fun generate(config: XrayConfig, original: XrayOutbound, resolvedAddress: String?): JsonObject {
        val outbound = if (resolvedAddress != null && !original.isAddressResolved) {
            require(IpAddress.isValid(resolvedAddress)) { "resolved server address must be an IP" }
            original.withAddress(resolvedAddress)
        } else {
            original
        }
        // When connecting to an IP, keep the original hostname for TLS / Host headers.
        val hostnameHint = original.address.takeIf { !original.isAddressResolved }

        return buildJsonObject {
            putJsonObject("log") { put("loglevel", config.logLevel) }
            putStatsConfig()
            putJsonObject("dns") {
                putJsonArray("servers") { config.dnsServers.forEach { add(it) } }
                put("queryStrategy", if (config.ipv6) "UseIP" else "UseIPv4")
            }
            putJsonArray("inbounds") { add(tunInbound(config)) }
            putJsonArray("outbounds") {
                add(outboundJson(outbound, hostnameHint))
                addJsonObject {
                    put("tag", DIRECT_TAG)
                    put("protocol", "freedom")
                    putJsonObject("settings") { put("domainStrategy", if (config.ipv6) "UseIP" else "UseIPv4") }
                }
                addJsonObject {
                    put("tag", BLOCK_TAG)
                    put("protocol", "blackhole")
                }
                addJsonObject {
                    put("tag", DNS_TAG)
                    put("protocol", "dns")
                }
            }
            putJsonObject("routing") {
                put("domainStrategy", "AsIs")
                putJsonArray("rules") {
                    // DNS queries entering the tunnel are answered by Xray's DNS
                    // module, which itself queries the configured servers via the proxy.
                    addJsonObject {
                        put("type", "field")
                        putJsonArray("inboundTag") { add(TUN_INBOUND_TAG) }
                        put("port", "53")
                        put("outboundTag", DNS_TAG)
                    }
                    // Never send private destinations to the proxy server.
                    addJsonObject {
                        put("type", "field")
                        putJsonArray("ip") { Routes.LOCAL_NETWORKS.forEach { add(it.toString()) } }
                        put("outboundTag", DIRECT_TAG)
                    }
                    addJsonObject {
                        put("type", "field")
                        putJsonArray("inboundTag") { add(TUN_INBOUND_TAG) }
                        put("outboundTag", PROXY_TAG)
                    }
                }
            }
        }
    }

    private fun injectTun(config: XrayConfig, rawJson: String): JsonObject {
        val root = runCatching { Json.parseToJsonElement(rawJson) }.getOrNull() as? JsonObject
            ?: throw ConfigException("Xray config is not a JSON object")
        val inbounds = (root["inbounds"] as? JsonArray).orEmpty()
            .filterNot { (it as? JsonObject)?.get("protocol")?.stringOrNull() == "tun" }
        return JsonObject(
            root + mapOf(
                "inbounds" to JsonArray(listOf(tunInbound(config)) + inbounds),
                "stats" to (root["stats"] ?: JsonObject(emptyMap())),
                "policy" to mergePolicy(root["policy"] as? JsonObject),
            ),
        )
    }

    private fun tunInbound(config: XrayConfig): JsonObject = buildJsonObject {
        put("tag", TUN_INBOUND_TAG)
        put("port", 0)
        put("protocol", "tun")
        putJsonObject("settings") {
            put("name", "xray0")
            put("MTU", config.mtu)
        }
        if (config.sniffing) {
            putJsonObject("sniffing") {
                put("enabled", true)
                putJsonArray("destOverride") {
                    add("http")
                    add("tls")
                    add("quic")
                }
                put("routeOnly", true)
            }
        }
    }

    private fun JsonObjectBuilder.putStatsConfig() {
        putJsonObject("stats") {}
        put("policy", mergePolicy(null))
    }

    /** Enables outbound traffic counters, used for [io.github.bitnik212.vpnlib.tunnel.TunnelStatistics]. */
    private fun mergePolicy(existing: JsonObject?): JsonObject {
        val system = (existing?.get("system") as? JsonObject).orEmpty()
        return JsonObject(
            existing.orEmpty() + mapOf(
                "system" to JsonObject(
                    system + mapOf(
                        "statsOutboundUplink" to JsonPrimitive(true),
                        "statsOutboundDownlink" to JsonPrimitive(true),
                    ),
                ),
            ),
        )
    }

    private fun outboundJson(outbound: XrayOutbound, hostnameHint: String?): JsonObject = buildJsonObject {
        put("tag", PROXY_TAG)
        when (outbound) {
            is XrayOutbound.Vless -> {
                put("protocol", "vless")
                putJsonObject("settings") {
                    putJsonArray("vnext") {
                        addJsonObject {
                            put("address", outbound.address)
                            put("port", outbound.port)
                            putJsonArray("users") {
                                addJsonObject {
                                    put("id", outbound.id)
                                    put("encryption", outbound.encryption)
                                    outbound.flow?.let { put("flow", it) }
                                }
                            }
                        }
                    }
                }
            }
            is XrayOutbound.Vmess -> {
                put("protocol", "vmess")
                putJsonObject("settings") {
                    putJsonArray("vnext") {
                        addJsonObject {
                            put("address", outbound.address)
                            put("port", outbound.port)
                            putJsonArray("users") {
                                addJsonObject {
                                    put("id", outbound.id)
                                    put("alterId", outbound.alterId)
                                    put("security", outbound.security)
                                }
                            }
                        }
                    }
                }
            }
            is XrayOutbound.Trojan -> {
                put("protocol", "trojan")
                putJsonObject("settings") {
                    putJsonArray("servers") {
                        addJsonObject {
                            put("address", outbound.address)
                            put("port", outbound.port)
                            put("password", outbound.password)
                        }
                    }
                }
            }
            is XrayOutbound.Shadowsocks -> {
                put("protocol", "shadowsocks")
                putJsonObject("settings") {
                    putJsonArray("servers") {
                        addJsonObject {
                            put("address", outbound.address)
                            put("port", outbound.port)
                            put("method", outbound.method)
                            put("password", outbound.password)
                            if (outbound.udpOverTcp) put("uot", true)
                        }
                    }
                }
            }
        }
        put("streamSettings", streamJson(outbound.stream, hostnameHint))
    }

    private fun streamJson(stream: StreamSettings, hostnameHint: String?): JsonObject = buildJsonObject {
        put("network", stream.network.id)
        val security = stream.security
        put("security", security.name.lowercase())

        val host = stream.host ?: hostnameHint
        when (security) {
            XraySecurity.TLS -> putJsonObject("tlsSettings") {
                val tls = stream.tls ?: TlsSettings()
                (tls.serverName ?: stream.host ?: hostnameHint)?.let { put("serverName", it) }
                if (tls.alpn.isNotEmpty()) putJsonArray("alpn") { tls.alpn.forEach { add(it) } }
                tls.fingerprint?.let { put("fingerprint", it) }
                if (tls.allowInsecure) put("allowInsecure", true)
            }
            XraySecurity.REALITY -> putJsonObject("realitySettings") {
                val reality = stream.reality ?: throw ConfigException("REALITY settings are missing")
                reality.serverName?.let { put("serverName", it) }
                put("publicKey", reality.publicKey)
                reality.shortId?.let { put("shortId", it) }
                reality.spiderX?.let { put("spiderX", it) }
                reality.fingerprint?.let { put("fingerprint", it) }
                reality.mldsa65Verify?.let { put("mldsa65Verify", it) }
            }
            XraySecurity.NONE -> Unit
        }

        when (stream.network) {
            XrayTransport.RAW -> if (stream.headerType == "http") {
                putJsonObject("rawSettings") {
                    putJsonObject("header") {
                        put("type", "http")
                        putJsonObject("request") {
                            putJsonArray("path") {
                                (stream.path ?: "/").split(',').forEach { add(it.trim()) }
                            }
                            putJsonObject("headers") {
                                host?.let { h -> putJsonArray("Host") { h.split(',').forEach { add(it.trim()) } } }
                            }
                        }
                    }
                }
            }
            XrayTransport.WEBSOCKET -> putJsonObject("wsSettings") {
                put("path", stream.path ?: "/")
                host?.let { put("host", it) }
            }
            XrayTransport.HTTP_UPGRADE -> putJsonObject("httpupgradeSettings") {
                put("path", stream.path ?: "/")
                host?.let { put("host", it) }
            }
            XrayTransport.XHTTP -> putJsonObject("xhttpSettings") {
                put("path", stream.path ?: "/")
                host?.let { put("host", it) }
                stream.xhttpMode?.let { put("mode", it) }
                stream.xhttpExtra?.let { extra ->
                    val parsed = runCatching { Json.parseToJsonElement(extra) }.getOrNull()
                        ?: throw ConfigException("xhttp extra is not valid JSON")
                    put("extra", parsed)
                }
            }
            XrayTransport.GRPC -> putJsonObject("grpcSettings") {
                stream.serviceName?.let { put("serviceName", it) }
                put("multiMode", stream.grpcMultiMode)
                stream.host?.let { put("authority", it) }
            }
            XrayTransport.KCP -> putJsonObject("kcpSettings") {
                stream.headerType?.takeIf { it != "none" }?.let { put("header", buildJsonObject { put("type", it) }) }
                stream.kcpSeed?.let { put("seed", it) }
            }
        }
    }

    private fun JsonElement.stringOrNull(): String? = (this as? JsonPrimitive)?.contentOrNull

    private fun JsonObject?.orEmpty(): JsonObject = this ?: JsonObject(emptyMap())

    private fun JsonArray?.orEmpty(): JsonArray = this ?: buildJsonArray { }
}
