package dev.davidjosearaujo.zaptun.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.DataInputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URL
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * A Firebase Realtime Database WebSocket session, the way the Firebase Android SDK (TubeSock) opens
 * it, through the real [TcpRelay] and a real ZAP, against a real Firebase database (the public
 * Hacker News one).
 *
 * Needs a running ZAP and internet access, so it only runs when ZAPTUN_LIVE_ZAP is set to ZAP's
 * address, e.g. `ZAPTUN_LIVE_ZAP=127.0.0.1:8080 ./gradlew :app:testDebugUnitTest --tests '*LiveZap*'`.
 * If ZAP's API needs a key, set ZAPTUN_LIVE_ZAP_KEY too, so the test can check ZAP's WebSockets tab.
 */
class LiveZapWebSocketTest {
    private val lo = InetAddress.getLoopbackAddress()
    private val zap: InetSocketAddress? = System.getenv("ZAPTUN_LIVE_ZAP")?.let {
        InetSocketAddress(it.substringBeforeLast(':'), it.substringAfterLast(':').toInt())
    }

    /** Trusts anything: the point is the path through the relay and ZAP, not ZAP's CA. */
    private val tls = SSLContext.getInstance("TLS").apply {
        init(null, arrayOf(object : X509TrustManager {
            override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
            override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}
            override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
        }), SecureRandom())
    }

    private class Result(val status: String, val frames: List<String>, val records: List<ConnectionRecord>) {
        /** The host Firebase tells the client to move to, from its first "h" control message. */
        val redirect get() = frames.firstNotNullOfOrNull { Regex("\"h\":\"([^\"]+)\"").find(it)?.groupValues?.get(1) }
    }

    @Test
    fun firebaseSessionGoesThroughZap() {
        assumeTrue("set ZAPTUN_LIVE_ZAP=host:port to run against a live ZAP", zap != null)

        val first = session("hacker-news.firebaseio.com", holdMs = 5_000)
        assertEquals("HTTP/1.1 101 Switching Protocols", first.status)
        val redirect = first.redirect
        assertNotNull("Firebase sent no host in its handshake message: ${first.frames}", redirect)

        // Long enough for a keepalive from the client (every 45 s, like the SDK) and an idle stretch.
        val second = session(redirect!!, holdMs = 50_000)
        assertEquals("HTTP/1.1 101 Switching Protocols", second.status)
        assertTrue("no frames from $redirect", second.frames.isNotEmpty())

        for (r in first.records + second.records) {
            assertEquals("route of ${r.host}", TcpRelay.Route.PROXY, r.route)
            assertEquals("kind of ${r.host}", Sniffer.Kind.TLS, r.kind)
        }
        zapChannels()?.let { channels ->
            assertTrue("ZAP has no WebSocket channel for $redirect", channels.contains("wss://$redirect"))
        }
    }

    /** Opens the WebSocket through a fresh relay, reads frames for [holdMs], then closes. */
    private fun session(host: String, holdMs: Long): Result {
        val pool: ExecutorService = Executors.newCachedThreadPool { r -> Thread(r).apply { isDaemon = true } }
        val records = CopyOnWriteArrayList<ConnectionRecord>()
        val dst = InetSocketAddress(InetAddress.getByName(host), 443)
        val relay = TcpRelay(
            lo, zap!!, { dst }, { true }, pool,
            intercepts = { it == 443 },
            onFinished = { records += it },
        ).start()
        val frames = mutableListOf<String>()
        val status: String
        try {
            // Like TubeSock: SNI, no ALPN.
            val s = tls.socketFactory.createSocket(Socket(lo, relay.port), host, 443, true) as SSLSocket
            s.use {
                s.startHandshake()
                val key = Base64.getEncoder().encodeToString(ByteArray(16).also { SecureRandom().nextBytes(it) })
                s.getOutputStream().write(
                    ("GET /.ws?ns=hacker-news&v=5 HTTP/1.1\r\nHost: $host\r\nUpgrade: websocket\r\n" +
                        "Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: $key\r\n" +
                        "User-Agent: Firebase/5/21.0.0/34/Android\r\n\r\n").toByteArray(),
                )
                val input = DataInputStream(s.getInputStream())
                status = readHead(input).substringBefore("\r\n")
                if (!status.contains(" 101 ")) return Result(status, frames, records)

                s.soTimeout = 1000
                val end = System.currentTimeMillis() + holdMs
                var lastPing = System.currentTimeMillis()
                while (System.currentTimeMillis() < end) {
                    try {
                        frames += readTextFrame(input) ?: throw IOException("$host closed the WebSocket after ${frames.size} frames")
                    } catch (_: SocketTimeoutException) {
                    }
                    if (System.currentTimeMillis() - lastPing > 45_000) {
                        s.getOutputStream().write(maskedTextFrame("0"))
                        lastPing = System.currentTimeMillis()
                    }
                }
            }
            Thread.sleep(1500) // let the relay see the close and finish its record
        } finally {
            relay.stop()
            pool.shutdownNow()
        }
        return Result(status, frames, records)
    }

    private fun readHead(input: DataInputStream): String {
        val head = StringBuilder()
        while (!head.endsWith("\r\n\r\n")) {
            val c = input.read()
            if (c < 0) throw IOException("closed during the handshake, after '$head'")
            head.append(c.toChar())
        }
        return head.toString()
    }

    /** One unmasked server frame's payload as text, or null at the end of the stream. */
    private fun readTextFrame(input: DataInputStream): String? {
        if (input.read() < 0) return null
        var n = input.read() and 0x7f
        if (n == 126) n = input.readUnsignedShort() else if (n == 127) n = input.readLong().toInt()
        return String(ByteArray(n).also { input.readFully(it) })
    }

    private fun maskedTextFrame(text: String): ByteArray {
        val p = text.toByteArray()
        val mask = ByteArray(4).also { SecureRandom().nextBytes(it) }
        return byteArrayOf(0x81.toByte(), (0x80 or p.size).toByte()) + mask +
            ByteArray(p.size) { (p[it].toInt() xor mask[it % 4].toInt()).toByte() }
    }

    /** ZAP's WebSocket channels as JSON, or null if the API can't be reached. */
    private fun zapChannels(): String? = runCatching {
        val key = System.getenv("ZAPTUN_LIVE_ZAP_KEY")?.let { "?apikey=$it" } ?: ""
        URL("http://${zap!!.hostString}:${zap.port}/JSON/websocket/view/channels/$key").readText()
    }.getOrNull()
}
