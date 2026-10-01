package io.github.bitnik212.vpnlib.config

import io.github.bitnik212.vpnlib.config.XrayConfig
import io.github.bitnik212.vpnlib.config.xray.XrayJsonBuilder
import io.github.bitnik212.vpnlib.config.xray.XrayOutbound
import io.github.bitnik212.vpnlib.config.xray.XraySecurity
import io.github.bitnik212.vpnlib.config.xray.XrayShareLink
import io.github.bitnik212.vpnlib.config.xray.XrayTransport
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

internal const val VLESS_REALITY =
    "vless://8f5b2a4e-5c6d-4e7f-8a9b-0c1d2e3f4a5b@vpn.example.com:443" +
        "?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome" +
        "&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=6ba85179e30d4fc2&spx=%2F&type=tcp" +
        "#My%20Server%20%F0%9F%87%B3%F0%9F%87%B1"

class XrayTest {
    private fun obj(json: String) = Json.parseToJsonElement(json).jsonObject

    @Test
    fun parsesVlessReality() {
        val outbound = assertIs<XrayOutbound.Vless>(XrayShareLink.parse(VLESS_REALITY))
        assertEquals("vpn.example.com", outbound.address)
        assertEquals(443, outbound.port)
        assertEquals("xtls-rprx-vision", outbound.flow)
        assertEquals("My Server 🇳🇱", outbound.remarks)
        assertEquals(XrayTransport.RAW, outbound.stream.network)
        assertEquals(XraySecurity.REALITY, outbound.stream.security)
        val reality = outbound.stream.reality!!
        assertEquals("www.microsoft.com", reality.serverName)
        assertEquals("Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw", reality.publicKey)
        assertEquals("6ba85179e30d4fc2", reality.shortId)
        assertEquals("/", reality.spiderX)
    }

    @Test
    fun parsesVlessWebsocketTlsWithIpv6Host() {
        val outbound = assertIs<XrayOutbound.Vless>(
            XrayShareLink.parse(
                "vless://id@[2001:db8::10]:8443?type=ws&security=tls&path=%2Fws%3Fed%3D2048&host=cdn.example.com&alpn=h2,http/1.1",
            ),
        )
        assertEquals("2001:db8::10", outbound.address)
        assertEquals(XrayTransport.WEBSOCKET, outbound.stream.network)
        assertEquals("/ws?ed=2048", outbound.stream.path)
        assertEquals(listOf("h2", "http/1.1"), outbound.stream.tls!!.alpn)
    }

    @Test
    fun parsesVmess() {
        val json = """{"v":"2","ps":"vm","add":"1.2.3.4","port":"8080","id":"uuid-1","aid":"0","scy":"auto",""" +
            """"net":"grpc","type":"multi","host":"","path":"svc","tls":"tls","sni":"sni.example.com"}"""
        val outbound = assertIs<XrayOutbound.Vmess>(XrayShareLink.parse("vmess://" + Base64.encode(json.encodeToByteArray())))
        assertEquals("1.2.3.4", outbound.address)
        assertEquals(8080, outbound.port)
        assertEquals("vm", outbound.remarks)
        assertEquals(XrayTransport.GRPC, outbound.stream.network)
        assertEquals("svc", outbound.stream.serviceName)
        assertTrue(outbound.stream.grpcMultiMode)
        assertEquals("sni.example.com", outbound.stream.tls!!.serverName)
    }

    @Test
    fun parsesTrojanWithDefaultTls() {
        val outbound = assertIs<XrayOutbound.Trojan>(XrayShareLink.parse("trojan://p%40ss@t.example.com:443?sni=t.example.com#t"))
        assertEquals("p@ss", outbound.password)
        assertEquals(XraySecurity.TLS, outbound.stream.security)
    }

    @Test
    fun parsesShadowsocksVariants() {
        val userInfo = Base64.UrlSafe.encode("chacha20-ietf-poly1305:secret".encodeToByteArray()).trimEnd('=')
        val sip002 = assertIs<XrayOutbound.Shadowsocks>(XrayShareLink.parse("ss://$userInfo@ss.example.com:8388#ss"))
        assertEquals("chacha20-ietf-poly1305", sip002.method)
        assertEquals("secret", sip002.password)
        assertEquals("ss", sip002.remarks)

        val plain = assertIs<XrayOutbound.Shadowsocks>(
            XrayShareLink.parse("ss://2022-blake3-aes-128-gcm:YWJjZGVmZ2hpamtsbW5vcA%3D%3D@1.2.3.4:443"),
        )
        assertEquals("2022-blake3-aes-128-gcm", plain.method)
        assertEquals("YWJjZGVmZ2hpamtsbW5vcA==", plain.password)

        val legacy = Base64.encode("aes-256-gcm:pw@legacy.example.com:1234".encodeToByteArray())
        val old = assertIs<XrayOutbound.Shadowsocks>(XrayShareLink.parse("ss://$legacy#old"))
        assertEquals("legacy.example.com", old.address)
        assertEquals(1234, old.port)
        assertEquals("pw", old.password)
    }

    @Test
    fun rejectsUnsupportedLinks() {
        assertFailsWith<ConfigException> { XrayShareLink.parse("hysteria2://x@y:1") }
        assertFailsWith<ConfigException> { XrayShareLink.parse("vless://id@host:443?type=h2") }
        assertFailsWith<ConfigException> { XrayShareLink.parse("vless://id@host:443?security=reality") }
        assertFailsWith<ConfigException> { XrayShareLink.parse("vless://id@host") }
    }

    @Test
    fun generatesConfigWithTunInboundAndResolvedAddress() {
        val config = XrayConfig.fromShareLink(VLESS_REALITY)
        config.validate()
        val root = obj(XrayJsonBuilder.build(config, resolvedServerAddress = "203.0.113.5"))

        val inbound = root["inbounds"]!!.jsonArray.single().jsonObject
        assertEquals("tun", inbound["protocol"]!!.jsonPrimitive.content)
        assertEquals(XrayJsonBuilder.TUN_INBOUND_TAG, inbound["tag"]!!.jsonPrimitive.content)

        val proxy = root["outbounds"]!!.jsonArray.first().jsonObject
        assertEquals("vless", proxy["protocol"]!!.jsonPrimitive.content)
        val server = proxy["settings"]!!.jsonObject["vnext"]!!.jsonArray.single().jsonObject
        assertEquals("203.0.113.5", server["address"]!!.jsonPrimitive.content)
        val user = server["users"]!!.jsonArray.single().jsonObject
        assertEquals("xtls-rprx-vision", user["flow"]!!.jsonPrimitive.content)

        val stream = proxy["streamSettings"]!!.jsonObject
        assertEquals("raw", stream["network"]!!.jsonPrimitive.content)
        assertEquals("reality", stream["security"]!!.jsonPrimitive.content)
        assertEquals("www.microsoft.com", stream["realitySettings"]!!.jsonObject["serverName"]!!.jsonPrimitive.content)
        assertTrue("policy" in root && "stats" in root)
    }

    @Test
    fun keepsHostnameForTlsWhenConnectingToResolvedIp() {
        val config = XrayConfig.fromShareLink("trojan://pw@t.example.com:443?type=ws&path=%2Ft")
        val stream = obj(config.toXrayJson("198.51.100.9"))["outbounds"]!!.jsonArray.first()
            .jsonObject["streamSettings"]!!.jsonObject
        assertEquals("t.example.com", stream["tlsSettings"]!!.jsonObject["serverName"]!!.jsonPrimitive.content)
        assertEquals("t.example.com", stream["wsSettings"]!!.jsonObject["host"]!!.jsonPrimitive.content)
    }

    @Test
    fun injectsTunIntoRawJson() {
        val raw = """
            {"inbounds":[{"protocol":"tun","settings":{"name":"old"}},{"tag":"socks","protocol":"socks","port":1080}],
             "outbounds":[{"protocol":"freedom"}],"policy":{"levels":{"0":{"handshake":4}}}}
        """.trimIndent()
        val root = obj(XrayConfig.fromJson(raw).toXrayJson())
        val inbounds = root["inbounds"] as JsonArray
        assertEquals(listOf("tun-in", "socks"), inbounds.map { it.jsonObject["tag"]!!.jsonPrimitive.content })
        val policy = root["policy"] as JsonObject
        assertTrue("levels" in policy)
        assertEquals("true", policy["system"]!!.jsonObject["statsOutboundUplink"]!!.jsonPrimitive.content)
        assertFailsWith<ConfigException> { XrayConfig.fromJson("[1,2]") }
    }

    @Test
    fun validation() {
        assertFailsWith<ConfigException> { XrayConfig().validate() }
        assertFailsWith<ConfigException> { XrayConfig.fromShareLink(VLESS_REALITY).copy(dnsServers = listOf("dns.google")).validate() }
        assertNull(XrayConfig.fromShareLink(VLESS_REALITY).rawJson)
    }
}
