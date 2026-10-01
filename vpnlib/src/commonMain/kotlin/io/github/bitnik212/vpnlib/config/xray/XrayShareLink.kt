package io.github.bitnik212.vpnlib.config.xray

import io.github.bitnik212.vpnlib.config.ConfigException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlin.io.encoding.Base64

/**
 * Parser for the common proxy share link formats:
 *
 * - `vless://uuid@host:port?type=..&security=..#name` (Xray standard)
 * - `vmess://<base64 json>` (v2rayN format)
 * - `trojan://password@host:port?...#name`
 * - `ss://<base64(method:password)>@host:port#name` (SIP002) and the legacy
 *   `ss://<base64(method:password@host:port)>#name`
 */
public object XrayShareLink {

    @Throws(ConfigException::class)
    public fun parse(link: String): XrayOutbound {
        val value = link.trim()
        return try {
            when (value.substringBefore("://").lowercase()) {
                "vless" -> parseVless(value)
                "vmess" -> parseVmess(value)
                "trojan" -> parseTrojan(value)
                "ss" -> parseShadowsocks(value)
                else -> throw ConfigException("Unsupported share link scheme in '${value.take(16)}...'")
            }
        } catch (e: ConfigException) {
            throw e
        } catch (e: IllegalArgumentException) {
            throw ConfigException("Invalid share link: ${e.message}", e)
        }
    }

    private fun parseVless(link: String): XrayOutbound.Vless {
        val url = ShareUrl.parse(link)
        val id = url.userInfo?.takeIf { it.isNotBlank() } ?: throw ConfigException("VLESS link has no id")
        return XrayOutbound.Vless(
            address = url.host,
            port = url.requirePort(),
            id = id,
            flow = url.query["flow"]?.takeIf { it.isNotBlank() },
            encryption = url.query["encryption"]?.takeIf { it.isNotBlank() } ?: "none",
            stream = streamFromQuery(url.query, defaultSecurity = XraySecurity.NONE),
            remarks = url.fragment,
        )
    }

    private fun parseTrojan(link: String): XrayOutbound.Trojan {
        val url = ShareUrl.parse(link)
        val password = url.userInfo?.takeIf { it.isNotEmpty() } ?: throw ConfigException("Trojan link has no password")
        return XrayOutbound.Trojan(
            address = url.host,
            port = url.requirePort(),
            password = password,
            stream = streamFromQuery(url.query, defaultSecurity = XraySecurity.TLS),
            remarks = url.fragment,
        )
    }

    private fun parseVmess(link: String): XrayOutbound.Vmess {
        val payload = decodeBase64Text(link.substringAfter("://").substringBefore('#'))
            ?: throw ConfigException("VMess link is not base64 encoded JSON")
        val json = runCatching { Json.parseToJsonElement(payload) as? JsonObject }.getOrNull()
            ?: throw ConfigException("VMess link payload is not a JSON object")
        fun field(name: String): String? =
            (json[name] as? JsonPrimitive)?.contentOrNull?.trim()?.takeIf { it.isNotEmpty() }

        val query = buildMap {
            field("net")?.let { put("type", it) }
            field("type")?.let { put("headerType", it) }
            field("host")?.let { put("host", it) }
            field("path")?.let { put("path", it) }
            field("tls")?.let { put("security", it) }
            field("sni")?.let { put("sni", it) }
            field("alpn")?.let { put("alpn", it) }
            field("fp")?.let { put("fp", it) }
            field("mode")?.let { put("mode", it) }
            field("allowInsecure")?.let { put("allowInsecure", it) }
        }.toMutableMap()
        // In v2rayN links gRPC keeps its service name in "path" and its mode in "type".
        if (query["type"] == "grpc") {
            query["path"]?.let { query["serviceName"] = it }
            if (query["headerType"] == "multi") query["mode"] = "multi"
            query.remove("headerType")
        }
        return XrayOutbound.Vmess(
            address = field("add") ?: throw ConfigException("VMess link has no address"),
            port = field("port")?.toIntOrNull() ?: throw ConfigException("VMess link has no valid port"),
            id = field("id") ?: throw ConfigException("VMess link has no id"),
            alterId = field("aid")?.toIntOrNull() ?: 0,
            security = field("scy") ?: "auto",
            stream = streamFromQuery(query, defaultSecurity = XraySecurity.NONE),
            remarks = field("ps"),
        )
    }

    private fun parseShadowsocks(link: String): XrayOutbound.Shadowsocks {
        val body = link.substringAfter("://")
        val fragment = body.substringAfter('#', missingDelimiterValue = "").takeIf { it.isNotEmpty() }?.let(::percentDecode)
        val main = body.substringBefore('#')

        val url = if ('@' in main.substringBefore('?')) {
            ShareUrl.parse(link)
        } else {
            // Legacy: the whole "method:password@host:port" is base64 encoded.
            val decoded = decodeBase64Text(main.substringBefore('?').substringBefore('/'))
                ?: throw ConfigException("Shadowsocks link is not base64 encoded")
            ShareUrl.parse("ss://$decoded")
        }
        val rawUserInfo = url.rawUserInfo ?: throw ConfigException("Shadowsocks link has no credentials")
        // SIP002: userinfo is base64(method:password), or percent-encoded plain text for 2022 ciphers.
        val credentials = if (':' in percentDecode(rawUserInfo)) {
            percentDecode(rawUserInfo)
        } else {
            decodeBase64Text(percentDecode(rawUserInfo)) ?: throw ConfigException("Shadowsocks credentials are invalid")
        }
        val method = credentials.substringBefore(':')
        val password = credentials.substringAfter(':', missingDelimiterValue = "")
        if (method.isBlank() || password.isEmpty()) throw ConfigException("Shadowsocks link has no method or password")
        if (url.query["plugin"] != null) throw ConfigException("Shadowsocks plugins are not supported")
        return XrayOutbound.Shadowsocks(
            address = url.host,
            port = url.requirePort(),
            method = method,
            password = password,
            udpOverTcp = url.query["uot"].let { it == "1" || it == "true" },
            stream = streamFromQuery(url.query, defaultSecurity = XraySecurity.NONE),
            remarks = fragment ?: url.fragment,
        )
    }

    private fun streamFromQuery(query: Map<String, String>, defaultSecurity: XraySecurity): StreamSettings {
        fun q(key: String): String? = query[key]?.takeIf { it.isNotBlank() }

        val network = XrayTransport.fromId(q("type"))
        val security = when (q("security")?.lowercase()) {
            null -> defaultSecurity
            "none" -> XraySecurity.NONE
            "tls", "xtls" -> XraySecurity.TLS
            "reality" -> XraySecurity.REALITY
            else -> throw ConfigException("Unsupported security '${q("security")}'")
        }
        val fingerprint = q("fp")
        val serverName = q("sni") ?: q("peer")
        val alpn = q("alpn")?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() }.orEmpty()
        val allowInsecure = q("allowInsecure").let { it == "1" || it == "true" } || q("insecure") == "1"

        return StreamSettings(
            network = network,
            security = security,
            tls = if (security == XraySecurity.TLS) {
                TlsSettings(serverName, alpn, fingerprint, allowInsecure)
            } else {
                null
            },
            reality = if (security == XraySecurity.REALITY) {
                RealitySettings(
                    serverName = serverName,
                    publicKey = q("pbk") ?: throw ConfigException("REALITY link has no public key (pbk)"),
                    shortId = q("sid"),
                    spiderX = q("spx"),
                    fingerprint = fingerprint ?: "chrome",
                    mldsa65Verify = q("pqv"),
                )
            } else {
                null
            },
            path = q("path"),
            host = q("host"),
            headerType = q("headerType"),
            serviceName = q("serviceName") ?: if (network == XrayTransport.GRPC) q("path") else null,
            grpcMultiMode = q("mode") == "multi",
            xhttpMode = if (network == XrayTransport.XHTTP) q("mode") else null,
            xhttpExtra = q("extra"),
            kcpSeed = q("seed"),
        )
    }

    internal fun decodeBase64Text(value: String): String? {
        val normalized = value.trim().replace('-', '+').replace('_', '/').filterNot { it.isWhitespace() }
        if (normalized.isEmpty()) return null
        val padded = normalized.trimEnd('=').let { it + "=".repeat((4 - it.length % 4) % 4) }
        return runCatching { Base64.decode(padded).decodeToString() }.getOrNull()
    }
}

/** Minimal URL parser for share links (`scheme://userinfo@host:port/path?query#fragment`). */
internal class ShareUrl(
    val rawUserInfo: String?,
    val host: String,
    val port: Int?,
    val query: Map<String, String>,
    val fragment: String?,
) {
    val userInfo: String? get() = rawUserInfo?.let(::percentDecode)

    fun requirePort(): Int = port ?: throw ConfigException("Share link has no port")

    companion object {
        fun parse(link: String): ShareUrl {
            var rest = link.substringAfter("://")
            val fragment = rest.substringAfter('#', missingDelimiterValue = "").takeIf { it.isNotEmpty() }
                ?.let(::percentDecode)
            rest = rest.substringBefore('#')
            val queryText = rest.substringAfter('?', missingDelimiterValue = "")
            rest = rest.substringBefore('?')
            val authority = rest.substringBefore('/')

            val at = authority.lastIndexOf('@')
            val userInfo = if (at >= 0) authority.substring(0, at) else null
            val hostPort = if (at >= 0) authority.substring(at + 1) else authority

            val host: String
            val port: Int?
            if (hostPort.startsWith("[")) {
                val end = hostPort.indexOf(']')
                if (end < 0) throw ConfigException("Unterminated IPv6 address in share link")
                host = hostPort.substring(1, end)
                port = hostPort.substring(end + 1).removePrefix(":").takeIf { it.isNotEmpty() }?.toIntOrNull()
                    ?: if (hostPort.length > end + 1) throw ConfigException("Invalid port in share link") else null
            } else {
                host = hostPort.substringBefore(':')
                val portText = hostPort.substringAfter(':', missingDelimiterValue = "")
                port = if (portText.isEmpty()) null else portText.toIntOrNull()
                    ?: throw ConfigException("Invalid port '$portText' in share link")
            }
            if (host.isBlank()) throw ConfigException("Share link has no host")

            val query = queryText.split('&').filter { it.isNotEmpty() }.associate { pair ->
                percentDecode(pair.substringBefore('=')) to percentDecode(pair.substringAfter('=', missingDelimiterValue = ""))
            }
            return ShareUrl(userInfo, host, port, query, fragment)
        }
    }
}

/** Decodes %XX escapes (UTF-8). `+` is kept, as share links use RFC 3986 encoding. */
internal fun percentDecode(value: String): String {
    if ('%' !in value) return value
    // '%' and hex digits are ASCII, so decoding on the UTF-8 bytes is safe.
    val input = value.encodeToByteArray()
    val output = ByteArray(input.size)
    var length = 0
    var i = 0
    while (i < input.size) {
        val byte = input[i]
        if (byte == '%'.code.toByte() && i + 2 < input.size) {
            val decoded = input.decodeToString(i + 1, i + 3).toIntOrNull(16)
            if (decoded != null) {
                output[length++] = decoded.toByte()
                i += 3
                continue
            }
        }
        output[length++] = byte
        i++
    }
    return output.decodeToString(0, length)
}
