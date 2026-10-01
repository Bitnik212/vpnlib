package io.github.bitnik212.vpnlib.config.xray

import io.github.bitnik212.vpnlib.net.IpAddress
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** A proxy server Xray connects to. */
@Serializable
public sealed interface XrayOutbound {
    /** Server hostname or IP. */
    public val address: String
    public val port: Int
    public val stream: StreamSettings

    /** Human readable name (share link fragment). */
    public val remarks: String?

    /** Copy pointing at another server address (e.g. the resolved IP). */
    public fun withAddress(address: String): XrayOutbound

    @Serializable
    @SerialName("vless")
    public data class Vless(
        override val address: String,
        override val port: Int,
        val id: String,
        /** e.g. `xtls-rprx-vision` */
        val flow: String? = null,
        /** `none`, or a VLESS post-quantum encryption string. */
        val encryption: String = "none",
        override val stream: StreamSettings = StreamSettings(),
        override val remarks: String? = null,
    ) : XrayOutbound {
        override fun withAddress(address: String): Vless = copy(address = address)
    }

    @Serializable
    @SerialName("vmess")
    public data class Vmess(
        override val address: String,
        override val port: Int,
        val id: String,
        val alterId: Int = 0,
        /** auto, aes-128-gcm, chacha20-poly1305, none, zero */
        val security: String = "auto",
        override val stream: StreamSettings = StreamSettings(),
        override val remarks: String? = null,
    ) : XrayOutbound {
        override fun withAddress(address: String): Vmess = copy(address = address)
    }

    @Serializable
    @SerialName("trojan")
    public data class Trojan(
        override val address: String,
        override val port: Int,
        val password: String,
        override val stream: StreamSettings = StreamSettings(security = XraySecurity.TLS),
        override val remarks: String? = null,
    ) : XrayOutbound {
        override fun withAddress(address: String): Trojan = copy(address = address)
    }

    @Serializable
    @SerialName("shadowsocks")
    public data class Shadowsocks(
        override val address: String,
        override val port: Int,
        /** e.g. `aes-256-gcm`, `chacha20-ietf-poly1305`, `2022-blake3-aes-128-gcm` */
        val method: String,
        val password: String,
        /** UDP over TCP. */
        val udpOverTcp: Boolean = false,
        override val stream: StreamSettings = StreamSettings(),
        override val remarks: String? = null,
    ) : XrayOutbound {
        override fun withAddress(address: String): Shadowsocks = copy(address = address)
    }
}

internal fun XrayOutbound.problems(): List<String> = buildList {
    if (address.isBlank()) add("server address is empty")
    if (port !in 1..65535) add("server port $port is out of range")
    when (val outbound = this@problems) {
        is XrayOutbound.Vless -> if (outbound.id.isBlank()) add("VLESS id is empty")
        is XrayOutbound.Vmess -> if (outbound.id.isBlank()) add("VMess id is empty")
        is XrayOutbound.Trojan -> if (outbound.password.isEmpty()) add("Trojan password is empty")
        is XrayOutbound.Shadowsocks -> {
            if (outbound.method.isBlank()) add("Shadowsocks method is empty")
            if (outbound.password.isEmpty()) add("Shadowsocks password is empty")
        }
    }
    if (stream.security == XraySecurity.REALITY) {
        val reality = stream.reality
        if (reality == null || reality.publicKey.isBlank()) add("REALITY requires a public key")
        if (reality != null && reality.serverName.isNullOrBlank()) add("REALITY requires a server name")
    }
}

internal val XrayOutbound.isAddressResolved: Boolean get() = IpAddress.isValid(address)

/** Transport ("network") of an Xray stream. */
@Serializable
public enum class XrayTransport(public val id: String) {
    @SerialName("raw")
    RAW("raw"),

    @SerialName("ws")
    WEBSOCKET("ws"),

    @SerialName("grpc")
    GRPC("grpc"),

    @SerialName("httpupgrade")
    HTTP_UPGRADE("httpupgrade"),

    @SerialName("xhttp")
    XHTTP("xhttp"),

    @SerialName("kcp")
    KCP("kcp"),
    ;

    public companion object {
        /** Maps share link `type` values (with legacy aliases) to a transport. */
        public fun fromId(id: String?): XrayTransport = when (id?.lowercase()) {
            null, "", "tcp", "raw" -> RAW
            "ws", "websocket" -> WEBSOCKET
            "grpc", "gun" -> GRPC
            "httpupgrade" -> HTTP_UPGRADE
            "xhttp", "splithttp" -> XHTTP
            "kcp", "mkcp" -> KCP
            else -> throw IllegalArgumentException("Unsupported transport '$id'")
        }
    }
}

@Serializable
public enum class XraySecurity {
    @SerialName("none")
    NONE,

    @SerialName("tls")
    TLS,

    @SerialName("reality")
    REALITY,
}

@Serializable
public data class TlsSettings(
    val serverName: String? = null,
    val alpn: List<String> = emptyList(),
    /** uTLS fingerprint, e.g. `chrome`. */
    val fingerprint: String? = null,
    val allowInsecure: Boolean = false,
)

@Serializable
public data class RealitySettings(
    val serverName: String? = null,
    val publicKey: String,
    val shortId: String? = null,
    val spiderX: String? = null,
    val fingerprint: String? = "chrome",
    /** ML-DSA-65 public key for post-quantum verification (optional). */
    val mldsa65Verify: String? = null,
)

/** Transport and security settings ("streamSettings"). */
@Serializable
public data class StreamSettings(
    val network: XrayTransport = XrayTransport.RAW,
    val security: XraySecurity = XraySecurity.NONE,
    val tls: TlsSettings? = null,
    val reality: RealitySettings? = null,
    /** ws / httpupgrade / xhttp path, or the raw "http" header path. */
    val path: String? = null,
    /** ws / httpupgrade / xhttp host header, or the raw "http" header host. */
    val host: String? = null,
    /** raw: `none` or `http`; kcp: header obfuscation type. */
    val headerType: String? = null,
    /** gRPC service name. */
    val serviceName: String? = null,
    val grpcMultiMode: Boolean = false,
    /** xhttp mode: auto, packet-up, stream-up, stream-one. */
    val xhttpMode: String? = null,
    /** xhttp "extra" object as JSON. */
    val xhttpExtra: String? = null,
    val kcpSeed: String? = null,
)
