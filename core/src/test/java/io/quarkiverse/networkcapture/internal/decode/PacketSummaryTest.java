package io.quarkiverse.networkcapture.internal.decode;

import static io.quarkiverse.networkcapture.TestPackets.clientHello;
import static io.quarkiverse.networkcapture.TestPackets.concat;
import static io.quarkiverse.networkcapture.TestPackets.ethernet;
import static io.quarkiverse.networkcapture.TestPackets.ipv4;
import static io.quarkiverse.networkcapture.TestPackets.ipv6;
import static io.quarkiverse.networkcapture.TestPackets.serverHello;
import static io.quarkiverse.networkcapture.TestPackets.tcp;
import static io.quarkiverse.networkcapture.TestPackets.tlsRecord;
import static io.quarkiverse.networkcapture.TestPackets.udp;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import io.quarkiverse.networkcapture.LinkType;

class PacketSummaryTest {

    @Test
    void ethernetIpv4TcpSyn() {
        byte[] packet = concat(ethernet(0x0800), ipv4(6, new byte[] { 127, 0, 0, 1 }, new byte[] { 10, 0, 0, 2 }, 20),
                tcp(43210, 8080, 0x02));
        PacketSummary s = PacketSummary.decode(LinkType.ETHERNET, packet);
        assertEquals("TCP", s.protocol());
        assertEquals("127.0.0.1:43210", s.source());
        assertEquals("10.0.0.2:8080", s.destination());
        assertEquals("43210 → 8080 [SYN] Seq=7 Len=0", s.info());
        assertEquals(43210, s.sourcePort());
        assertEquals(8080, s.destinationPort());
    }

    @Test
    void httpRequestAndResponse() {
        byte[] lo = { 127, 0, 0, 1 };
        byte[] request = "GET /hello HTTP/1.1\r\nHost: localhost:8080\r\n\r\n".getBytes();
        PacketSummary req = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + request.length), tcp(50000, 8080, 0x18), request));
        assertEquals("HTTP", req.protocol());
        assertEquals("GET /hello HTTP/1.1", req.info());
        assertEquals(8080, req.destinationPort());

        byte[] response = "HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello".getBytes();
        PacketSummary res = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + response.length), tcp(8080, 50000, 0x18), response));
        assertEquals("HTTP", res.protocol());
        assertEquals("HTTP/1.1 200 OK", res.info());

        byte[] body = "hello world, this is not a request line\r\n".getBytes();
        PacketSummary data = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + body.length), tcp(8080, 50000, 0x18), body));
        assertEquals("TCP", data.protocol());
        assertEquals("8080 \u2192 50000 [ACK, PSH] Seq=7 Len=" + body.length, data.info());

        byte[] binary = { 0x16, 0x03, 0x01, 0x00, (byte) 0xC8, 0x01, 0x00, 0x00, (byte) 0xC4, 0x03, 0x03, 0x00, 0x00 };
        PacketSummary tls = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + binary.length), tcp(50000, 443, 0x18), binary));
        assertEquals("HTTPS", tls.protocol()); // truncated hello without ALPN, port 443 decides
        assertEquals("Client Hello", tls.info());
    }

    @Test
    void tls() {
        byte[] lo = { 127, 0, 0, 1 };
        byte[] hello = clientHello("localhost", "h2", "http/1.1");
        PacketSummary h = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + hello.length), tcp(50000, 8443, 0x18), hello));
        assertEquals("HTTPS", h.protocol());
        assertEquals("Client Hello (SNI=localhost, ALPN=h2, http/1.1)", h.info());
        assertEquals("localhost", h.tls().clientHello().serverName());

        // no ALPN: the port decides
        byte[] pg = clientHello("db.internal");
        PacketSummary db = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + pg.length), tcp(50000, 5432, 0x18), pg));
        assertEquals("TLS", db.protocol());
        assertEquals("Client Hello (SNI=db.internal)", db.info());
        PacketSummary web = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + pg.length), tcp(50000, 443, 0x18), pg));
        assertEquals("HTTPS", web.protocol());

        // ALPN that is not HTTP
        byte[] mq = clientHello(null, "mqtt");
        PacketSummary m = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + mq.length), tcp(50000, 8443, 0x18), mq));
        assertEquals("TLS", m.protocol());
        assertEquals("Client Hello (ALPN=mqtt)", m.info());

        // several records in one segment, the last one cut by the segment
        byte[] serverHello = { 2, 0, 0, 4, 3, 3, 0, 0 };
        byte[] reply = concat(tlsRecord(0x16, serverHello), tlsRecord(0x14, new byte[] { 1 }),
                new byte[] { 0x17, 3, 3, 0x10, 0, 1, 2, 3 });
        PacketSummary r = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + reply.length), tcp(8443, 50000, 0x18), reply));
        assertEquals("HTTPS", r.protocol());
        assertEquals("Server Hello, Change Cipher Spec, Application Data", r.info());

        // a valid record header followed by something that is not a record is not TLS
        byte[] fake = concat(tlsRecord(0x17, new byte[] { 1 }), new byte[] { 0x42, 0x42, 0x42, 0x42, 0x42 });
        PacketSummary f = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + fake.length), tcp(8443, 50000, 0x18), fake));
        assertEquals("TCP", f.protocol());
    }

    @Test
    void http2Frames() {
        byte[] lo = { 127, 0, 0, 1 };
        // SETTINGS on stream 0 (6 byte payload) followed by HEADERS on stream 1 with END_HEADERS (4 byte payload)
        byte[] frames = { 0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 100,
                0, 0, 4, 1, 4, 0, 0, 0, 1, (byte) 0x82, (byte) 0x86, (byte) 0x84, 0x41 };
        PacketSummary s = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + frames.length), tcp(50000, 8080, 0x18), frames));
        assertEquals("HTTP2", s.protocol());
        assertEquals("SETTINGS, HEADERS[1]", s.info());

        byte[] preface = concat("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".getBytes(), new byte[] { 0, 0, 0, 4, 0, 0, 0, 0, 0 });
        PacketSummary p = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + preface.length), tcp(50000, 8080, 0x18), preface));
        assertEquals("HTTP2", p.protocol());
        assertEquals("Connection preface, SETTINGS", p.info());

        byte[] partial = { 0, 0x40, 0, 0, 0, 0, 0, 0, 1, 1, 2, 3 }; // a DATA frame of 16 KiB, cut by the segment
        PacketSummary t = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800),
                ipv4(6, lo, lo, 20 + partial.length), tcp(8080, 50000, 0x18), partial));
        assertEquals("TCP", t.protocol());
    }

    @Test
    void vlanTaggedIpv4Udp() {
        byte[] packet = concat(ethernet(0x8100), new byte[] { 0, 1, 0x08, 0x00 },
                ipv4(17, new byte[] { (byte) 192, (byte) 168, 1, 1 }, new byte[] { (byte) 192, (byte) 168, 1, 2 }, 12),
                udp(53, 5353, 12));
        PacketSummary s = PacketSummary.decode(LinkType.ETHERNET, packet);
        assertEquals("UDP", s.protocol());
        assertEquals("192.168.1.1:53", s.source());
        assertEquals("53 → 5353 Len=4", s.info());
    }

    @Test
    void bsdLoopbackIpv6Tcp() {
        byte[] loopbackHeader = { 30, 0, 0, 0 };
        byte[] src = new byte[16];
        src[15] = 1;
        byte[] packet = concat(loopbackHeader, ipv6(6, src, src, 20), tcp(5000, 443, 0x18));
        PacketSummary s = PacketSummary.decode(LinkType.NULL, packet);
        assertEquals("TCP", s.protocol());
        assertEquals("0:0:0:0:0:0:0:1:5000", s.source());
        assertEquals("5000 → 443 [ACK, PSH] Seq=7 Len=0", s.info());
    }

    @Test
    void arpRequest() {
        ByteArrayOutputStream arp = new ByteArrayOutputStream();
        arp.writeBytes(new byte[] { 0, 1, 8, 0, 6, 4, 0, 1 });
        arp.writeBytes(new byte[] { 1, 2, 3, 4, 5, 6 });
        arp.writeBytes(new byte[] { 10, 0, 0, 1 });
        arp.writeBytes(new byte[6]);
        arp.writeBytes(new byte[] { 10, 0, 0, 9 });
        PacketSummary s = PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0806), arp.toByteArray()));
        assertEquals("ARP", s.protocol());
        assertEquals("Who has 10.0.0.9? Tell 10.0.0.1", s.info());
    }

    @Test
    void truncatedPacketDoesNotThrow() {
        PacketSummary s = PacketSummary.decode(LinkType.ETHERNET, new byte[] { 1, 2, 3 });
        assertEquals("Malformed", s.protocol());
    }

    private static PacketSummary tls(byte[] payload, int sport, int dport) {
        byte[] lo = { 127, 0, 0, 1 };
        return PacketSummary.decode(LinkType.ETHERNET, concat(ethernet(0x0800), ipv4(6, lo, lo, 20 + payload.length),
                tcp(sport, dport, 0x18), payload));
    }

    @Test
    void clientHelloKeyExchangeDetails() {
        byte[] hello = clientHello().serverName("localhost").alpn("h2").versions(0x0304, 0x0303).cipherSuites(0x1302, 0x1301, 0xC02F)
                .groups(0x11EC, 0x1D, 0x17, 0x1a1a).keyShares(0x11EC, 0x1D).signatureAlgorithms(0x0403, 0x0807).build();
        PacketSummary s = tls(hello, 50000, 8443);
        assertEquals("Client Hello (SNI=localhost, ALPN=h2, key shares=X25519MLKEM768, x25519)", s.info());
        TlsHandshake.ClientHello c = s.tls().clientHello();
        assertEquals("localhost", c.serverName());
        assertEquals(List.of("h2"), c.protocols());
        assertEquals(List.of("TLS 1.3", "TLS 1.2"), c.versions());
        assertEquals(List.of("TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
                c.cipherSuites());
        assertEquals(List.of("X25519MLKEM768", "x25519", "secp256r1", "0x1a1a"), c.groups());
        assertEquals(List.of("X25519MLKEM768", "x25519"), c.keyShares());
        assertEquals(List.of("ecdsa_secp256r1_sha256", "ed25519"), c.signatureAlgorithms());
        assertTrue(c.offersPostQuantum());
        assertFalse(c.truncated());
        assertNull(s.tls().serverHello());
        assertNull(s.tls().quantumSafety());

        // without supported_versions the legacy version is all that is offered
        TlsHandshake.ClientHello old = tls(clientHello().keyShares(0x1D).build(), 50000, 8443).tls().clientHello();
        assertEquals(List.of("TLS 1.2"), old.versions());
        assertFalse(old.offersPostQuantum());
    }

    @Test
    void clientHelloCutByTheSegment() {
        byte[] hello = clientHello().serverName("localhost").groups(0x11EC, 0x1D).keyShares(0x11EC).build();
        // cut inside the key share extension, which comes last
        PacketSummary s = tls(Arrays.copyOf(hello, hello.length - 3), 50000, 8443);
        TlsHandshake.ClientHello c = s.tls().clientHello();
        assertEquals("Client Hello (SNI=localhost)", s.info());
        assertEquals(List.of("X25519MLKEM768", "x25519"), c.groups());
        assertEquals(List.of(), c.keyShares());
        assertTrue(c.truncated());
    }

    @Test
    void serverHelloWithPostQuantumKeyShare() {
        byte[] hello = serverHello().versions(0x0304).cipherSuites(0x1302).keyShares(0x11EC).build();
        PacketSummary s = tls(concat(hello, tlsRecord(0x14, new byte[] { 1 })), 8443, 50000);
        assertEquals("Server Hello (TLS 1.3, TLS_AES_256_GCM_SHA384, key share X25519MLKEM768), Change Cipher Spec"
                + "; quantum-safe key exchange", s.info());
        TlsHandshake.ServerHello h = s.tls().serverHello();
        assertEquals("TLS 1.3", h.version());
        assertEquals("TLS_AES_256_GCM_SHA384", h.cipherSuite());
        assertEquals("X25519MLKEM768", h.keyShareGroup());
        assertFalse(h.retryRequest());
        assertTrue(s.tls().quantumSafety().safe());
        assertEquals("quantum-safe key exchange", s.tls().quantumSafety().reason());
        assertNull(s.tls().clientHello());
    }

    @Test
    void serverHelloWithClassicalKeyShare() {
        PacketSummary s = tls(serverHello().versions(0x0304).cipherSuites(0x1301).keyShares(0x1D).build(), 8443, 50000);
        assertEquals("Server Hello (TLS 1.3, TLS_AES_128_GCM_SHA256, key share x25519); not quantum safe: the server chose x25519",
                s.info());
        assertFalse(s.tls().quantumSafety().safe());
        assertEquals("not quantum safe: the server chose x25519", s.tls().quantumSafety().reason());
    }

    @Test
    void tls12ServerHello() {
        PacketSummary s = tls(serverHello().cipherSuites(0xC030).build(), 8443, 50000);
        assertEquals("Server Hello (TLS 1.2, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384); not quantum safe: TLS 1.2 has no post-quantum key exchange",
                s.info());
        TlsHandshake.ServerHello h = s.tls().serverHello();
        assertEquals("TLS 1.2", h.version());
        assertNull(h.keyShareGroup());
        assertFalse(s.tls().quantumSafety().safe());
    }

    @Test
    void helloRetryRequest() {
        PacketSummary s = tls(serverHello().versions(0x0304).cipherSuites(0x1301).keyShares(0x11EC).retryRequest().build(), 8443, 50000);
        assertEquals("Hello Retry Request (TLS 1.3, TLS_AES_128_GCM_SHA256, asks for key share X25519MLKEM768)", s.info());
        assertTrue(s.tls().serverHello().retryRequest());
        assertEquals("X25519MLKEM768", s.tls().serverHello().keyShareGroup());
        assertNull(s.tls().quantumSafety());
    }

    @Test
    void serverHelloWithoutKeyShareHasNoVerdict() {
        // a resumed session with psk_ke has no key share, so nothing can be said about its key exchange
        PacketSummary s = tls(serverHello().versions(0x0304).cipherSuites(0x1301).build(), 8443, 50000);
        assertEquals("Server Hello (TLS 1.3, TLS_AES_128_GCM_SHA256)", s.info());
        assertNull(s.tls().quantumSafety());
    }

    @Test
    void serverHelloCutByTheSegmentHasNoVerdict() {
        byte[] hello = serverHello().versions(0x0304).cipherSuites(0x1301).keyShares(0x1D).build();
        PacketSummary s = tls(Arrays.copyOf(hello, hello.length - 3), 8443, 50000);
        assertEquals("Server Hello (TLS 1.3, TLS_AES_128_GCM_SHA256)", s.info());
        TlsHandshake.ServerHello h = s.tls().serverHello();
        assertTrue(h.truncated());
        assertEquals("TLS 1.3", h.version()); // supported_versions precedes the cut key share
        assertNull(h.keyShareGroup());
        assertNull(s.tls().quantumSafety());

        // cut before the extensions: the version is unknown, since TLS 1.3 is only announced there
        PacketSummary early = tls(Arrays.copyOf(hello, 5 + 4 + 2 + 32 + 1 + 2), 8443, 50000);
        assertEquals("Server Hello (TLS_AES_128_GCM_SHA256)", early.info());
        assertNull(early.tls().serverHello().version());
    }

}
