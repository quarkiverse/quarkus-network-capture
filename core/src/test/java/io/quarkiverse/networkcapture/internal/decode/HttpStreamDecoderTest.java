package io.quarkiverse.networkcapture.internal.decode;

import static io.quarkiverse.networkcapture.TestPackets.clientHello;
import static io.quarkiverse.networkcapture.TestPackets.concat;
import static io.quarkiverse.networkcapture.TestPackets.ethernet;
import static io.quarkiverse.networkcapture.TestPackets.ipv4;
import static io.quarkiverse.networkcapture.TestPackets.serverHello;
import static io.quarkiverse.networkcapture.TestPackets.tcp;
import static io.quarkiverse.networkcapture.TestPackets.tlsRecord;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import io.quarkiverse.networkcapture.LinkType;

class HttpStreamDecoderTest {

    private static final byte[] SERVER = { 10, 0, 0, 1 };
    private static final byte[] CLIENT = { 10, 0, 0, 2 };

    private final HttpStreamDecoder decoder = new HttpStreamDecoder();

    private PacketSummary fromServer(String payload, int flags) {
        return fromServer(payload.getBytes(StandardCharsets.UTF_8), flags);
    }

    private PacketSummary fromServer(byte[] payload, int flags) {
        return decoder.decode(LinkType.ETHERNET, concat(ethernet(0x0800), ipv4(6, SERVER, CLIENT, 20 + payload.length),
                tcp(8080, 50000, flags), payload));
    }

    private PacketSummary fromClient(String payload) {
        byte[] p = payload.getBytes(StandardCharsets.UTF_8);
        return decoder.decode(LinkType.ETHERNET, concat(ethernet(0x0800), ipv4(6, CLIENT, SERVER, 20 + p.length),
                tcp(50000, 8080, 0x18), p));
    }

    private PacketSummary tls(byte[] src, int sport, byte[] dst, int dport, byte[] payload, int flags) {
        return decoder.decode(LinkType.ETHERNET, concat(ethernet(0x0800), ipv4(6, src, dst, 20 + payload.length),
                tcp(sport, dport, flags), payload));
    }

    @Test
    void tlsConnection() {
        PacketSummary hello = tls(CLIENT, 50000, SERVER, 8443, clientHello("localhost", "h2"), 0x18);
        assertEquals("HTTPS", hello.protocol());
        assertEquals("Client Hello (SNI=localhost, ALPN=h2)", hello.info());

        PacketSummary reply = tls(SERVER, 8443, CLIENT, 50000, tlsRecord(0x16, new byte[] { 2, 0, 0, 4, 3, 3, 0, 0 }), 0x18);
        assertEquals("HTTPS", reply.protocol());
        assertEquals("Server Hello (localhost)", reply.info());
        assertNull(reply.tls().quantumSafety()); // cut hello

        // a segment starting in the middle of a record
        PacketSummary middle = tls(SERVER, 8443, CLIENT, 50000, new byte[] { 0x42, 0x42, 0x42 }, 0x18);
        assertEquals("HTTPS", middle.protocol());
        assertEquals("Continuation Data (localhost)", middle.info());

        // an empty segment stays TCP
        PacketSummary ack = tls(CLIENT, 50000, SERVER, 8443, new byte[0], 0x10);
        assertEquals("TCP", ack.protocol());

        // another connection is unaffected
        PacketSummary other = tls(CLIENT, 50001, SERVER, 8443, new byte[] { 0x42, 0x42, 0x42 }, 0x18);
        assertEquals("TCP", other.protocol());

        PacketSummary fin = tls(CLIENT, 50000, SERVER, 8443, tlsRecord(0x15, new byte[] { 1, 0 }), 0x11);
        assertEquals("HTTPS", fin.protocol());
        assertEquals("Alert (localhost)", fin.info());
        PacketSummary after = tls(CLIENT, 50000, SERVER, 8443, new byte[] { 0x42, 0x42, 0x42 }, 0x18);
        assertEquals("TCP", after.protocol());
    }

    @Test
    void serverSentEventsAsChunks() {
        PacketSummary head = fromServer("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n", 0x18);
        assertEquals("HTTP", head.protocol());
        assertNotNull(head.http());

        PacketSummary e1 = fromServer("f\r\ndata: hello 0\n\n\r\n", 0x18);
        assertEquals("HTTP", e1.protocol());
        assertEquals("Chunk of HTTP/1.1 200 OK: data: hello 0\\n\\n", e1.info());
        assertEquals("HTTP/1.1 200 OK", e1.httpBody().message());
        assertEquals(0, e1.httpBody().offset());
        assertEquals("data: hello 0\n\n", e1.httpBody().asText(100));
        assertTrue(e1.httpBody().chunked());
        assertFalse(e1.httpBody().last());

        // the other direction stays plain TCP
        assertEquals("TCP", fromClient("x").protocol());

        PacketSummary end = fromServer("f\r\ndata: hello 1\n\n\r\n0\r\n\r\n", 0x18);
        assertEquals("data: hello 1\n\n", end.httpBody().asText(100));
        assertTrue(end.httpBody().last());
        assertEquals("Last chunk of HTTP/1.1 200 OK: data: hello 1\\n\\n", end.info());
        assertEquals(15, end.httpBody().offset());

        // after the last chunk nothing is attributed to the body any more
        assertEquals("TCP", fromServer("garbage", 0x18).protocol());
    }

    @Test
    void responsesArePairedWithRequestsInOrder() {
        PacketSummary r1 = fromClient("GET /one HTTP/1.1\r\nHost: x\r\n\r\n");
        PacketSummary r2 = fromClient("GET /two HTTP/1.1\r\nHost: x\r\n\r\n");
        assertTrue(r1.exchange().isRequest());
        assertEquals("GET /one HTTP/1.1", r1.exchange().request());
        assertNotNull(r2.exchange());

        PacketSummary interim = fromServer("HTTP/1.1 100 Continue\r\n\r\n", 0x18);
        assertNull(interim.exchange(), "an interim response does not answer a request");

        PacketSummary a1 = fromServer("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n12345", 0x18);
        assertFalse(a1.exchange().isRequest());
        assertEquals(r1.exchange().id(), a1.exchange().id());
        assertEquals("GET /one HTTP/1.1", a1.exchange().request());

        PacketSummary a1rest = fromServer("67890", 0x18);
        assertEquals(r1.exchange().id(), a1rest.exchange().id(), "body parts carry the pairing too");

        PacketSummary a2 = fromServer("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 0x18);
        assertEquals(r2.exchange().id(), a2.exchange().id());

        assertNull(fromServer("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 0x18).exchange(),
                "a response without a pending request is left unpaired");
    }

    @Test
    void chunkSplitAcrossSegments() {
        fromServer("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", 0x18);
        PacketSummary first = fromServer("1a\r\nabcdefghij", 0x18);
        assertEquals("abcdefghij", first.httpBody().asText(100));
        PacketSummary second = fromServer("klmnopqrstuvwxyz\r\n", 0x18);
        assertEquals("klmnopqrstuvwxyz", second.httpBody().asText(100));
        // a size line split across segments
        assertEquals("TCP", fromServer("5", 0x18).protocol());
        PacketSummary third = fromServer("\r\nhello\r\n", 0x18);
        assertEquals("hello", third.httpBody().asText(100));
    }

    @Test
    void bodyAfterHeadersInTheSameSegmentAndContentLengthContinuation() {
        PacketSummary head = fromServer("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n12345", 0x18);
        assertEquals(5, head.http().body().length);
        PacketSummary rest = fromServer("67890", 0x18);
        assertEquals("HTTP", rest.protocol());
        assertEquals("Body of HTTP/1.1 200 OK [6-10 of 10]: 67890", rest.info());
        assertEquals(5, rest.httpBody().offset());
        assertEquals(10, rest.httpBody().total());
        assertFalse(rest.httpBody().chunked());
        assertTrue(rest.httpBody().last());
        assertEquals(0, rest.httpBody().remaining());
        assertEquals("TCP", fromServer("more", 0x18).protocol());
    }

    @Test
    void chunkedDataInTheHeaderSegmentIsAccountedFor() {
        fromServer("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n", 0x18);
        PacketSummary next = fromServer("3\r\ndef\r\n0\r\n\r\n", 0x18);
        assertEquals("def", next.httpBody().asText(100));
        assertTrue(next.httpBody().last());
    }

    @Test
    void connectionCloseForgetsTheBody() {
        fromServer("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", 0x18);
        fromServer("", 0x11); // FIN
        assertNull(fromServer("3\r\nabc\r\n", 0x18).httpBody());
    }

    @Test
    void quantumSafetyVerdictKnowsWhatTheClientOffered() {
        tls(CLIENT, 50000, SERVER, 8443, clientHello().serverName("api").groups(0x11EC, 0x1D).keyShares(0x11EC, 0x1D).build(), 0x18);
        PacketSummary reply = tls(SERVER, 8443, CLIENT, 50000,
                serverHello().versions(0x0304).cipherSuites(0x1301).keyShares(0x1D).build(), 0x18);
        assertEquals("Server Hello (TLS 1.3, TLS_AES_128_GCM_SHA256, key share x25519)"
                + "; not quantum safe: the client offered X25519MLKEM768 but the server chose x25519 (api)", reply.info());
        assertFalse(reply.tls().quantumSafety().safe());

        // the rest of the connection carries the verdict, so any of its packets can show it
        PacketSummary data = tls(SERVER, 8443, CLIENT, 50000, new byte[] { 0x17, 3, 3, 0, 1, 0x42 }, 0x18);
        assertEquals("Application Data (api)", data.info());
        assertEquals(reply.tls().quantumSafety(), data.tls().quantumSafety());
        assertNull(data.tls().serverHello());

        // a client that offered no post-quantum group
        tls(CLIENT, 50001, SERVER, 8443, clientHello().groups(0x1D, 0x17).keyShares(0x1D).build(), 0x18);
        PacketSummary classical = tls(SERVER, 8443, CLIENT, 50001,
                serverHello().versions(0x0304).cipherSuites(0x1301).keyShares(0x1D).build(), 0x18);
        assertEquals("not quantum safe: the client offered no post-quantum group and the server chose x25519",
                classical.tls().quantumSafety().reason());

        // a safe one
        tls(CLIENT, 50002, SERVER, 8443, clientHello().groups(0x11EC, 0x1D).keyShares(0x11EC).build(), 0x18);
        PacketSummary safe = tls(SERVER, 8443, CLIENT, 50002,
                serverHello().versions(0x0304).cipherSuites(0x1301).keyShares(0x11EC).build(), 0x18);
        assertTrue(safe.tls().quantumSafety().safe());
        assertEquals("quantum-safe key exchange", safe.tls().quantumSafety().reason());
    }

}
