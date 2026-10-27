package io.quarkiverse.networkcapture.runtime.dev;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.util.List;

import org.junit.jupiter.api.Test;

class RedactionTest {

    private static final List<String> HEADERS = List.of("authorization", "proxy-authorization", "cookie", "set-cookie",
            "x-api-key", "x-auth-token");
    private static final List<String> PARAMETERS = List.of("access_token", "code", "key");

    private final Redaction redaction = new Redaction(HEADERS, PARAMETERS);

    @Test
    void redactsCredentialHeadersAndKeepsTheRest() {
        Messages.PacketRow row = redaction.apply(request("/x",
                new Messages.Header("Authorization", "Bearer eyJhbGciOiJIUzI1NiJ9.e30.sig"),
                new Messages.Header("X-API-Key", "s3cr3t"),
                new Messages.Header("X-Auth-Token", "t0k3n"),
                new Messages.Header("Content-Type", "application/json")));
        assertEquals(List.of(
                new Messages.Header("Authorization", "Bearer [redacted]"),
                new Messages.Header("X-API-Key", "[redacted]"),
                new Messages.Header("X-Auth-Token", "[redacted]"),
                new Messages.Header("Content-Type", "application/json")), headers(row));
    }

    @Test
    void authorizationWithoutSchemeIsRedactedWhole() {
        Messages.PacketRow row = redaction.apply(request("/x", new Messages.Header("authorization", "token")));
        assertEquals(List.of(new Messages.Header("authorization", "[redacted]")), headers(row));
    }

    @Test
    void cookieNamesAndAttributesAreKept() {
        Messages.PacketRow row = redaction.apply(request("/x",
                new Messages.Header("Cookie", "JSESSIONID=abc123; theme=dark"),
                new Messages.Header("Set-Cookie", "SESSION=xyz; Path=/; HttpOnly")));
        assertEquals(List.of(
                new Messages.Header("Cookie", "JSESSIONID=[redacted]; theme=[redacted]"),
                new Messages.Header("Set-Cookie", "SESSION=[redacted]; Path=/; HttpOnly")), headers(row));
    }

    @Test
    void queryParametersAreRedactedWhereverTheUrlAppears() {
        Messages.PacketRow row = redaction.apply(request("/cb?code=abc&state=s1&access_token=t#top",
                new Messages.Header("Location", "https://app.example/home?key=k&page=2")));
        Messages.MessageDetails http = (Messages.MessageDetails) row.http();
        assertEquals("http://localhost/cb?code=[redacted]&state=s1&access_token=[redacted]#top", http.url());
        assertEquals("/cb?code=[redacted]&state=s1&access_token=[redacted]#top", http.target());
        assertEquals("GET /cb?code=[redacted]&state=s1&access_token=[redacted]#top HTTP/1.1", row.info());
        assertEquals("GET /cb?code=[redacted]&state=s1&access_token=[redacted]#top HTTP/1.1", row.exchange().request());
        assertEquals(List.of(new Messages.Header("Location", "https://app.example/home?key=[redacted]&page=2")),
                headers(row));
    }

    @Test
    void parametersInTheFragmentAreRedacted() {
        Messages.PacketRow row = redaction.apply(request("/x",
                new Messages.Header("Location", "https://app.example/cb#access_token=t&state=s1&key=k")));
        assertEquals(List.of(new Messages.Header("Location",
                "https://app.example/cb#access_token=[redacted]&state=s1&key=[redacted]")), headers(row));
    }

    @Test
    void parameterNamesMatchWholeNamesOnly() {
        assertEquals("/x?monkey=1&Key=[redacted]", redaction.url("/x?monkey=1&Key=2"));
    }

    @Test
    void bodyPartsCarryTheRedactedRequestLine() {
        Messages.BodyPartDetails part = new Messages.BodyPartDetails(true, "GET /x?access_token=t HTTP/1.1", true, 0, 10,
                false, 5, 5, "hello", false);
        Messages.PacketRow row = redaction.apply(new Messages.PacketRow(2, "0.000000", "lo", "127.0.0.1:2", "127.0.0.1:1",
                "HTTP", 70, "Chunk of GET /x?access_token=t HTTP/1.1: hello", part, null, null, false));
        assertEquals("GET /x?access_token=[redacted] HTTP/1.1", ((Messages.BodyPartDetails) row.http()).message());
        assertEquals("Chunk of GET /x?access_token=[redacted] HTTP/1.1: hello", row.info());
    }

    @Test
    void noneTurnsRedactionOff() {
        Messages.PacketRow original = request("/x?code=1", new Messages.Header("Authorization", "Basic dXNlcjpwYXNz"));
        assertSame(original, new Redaction(List.of("none"), List.of("none")).apply(original));
    }

    @Test
    void tlsDetailsPassThroughUntouched() {
        Messages.TlsDetails tls = new Messages.TlsDetails(null,
                new Messages.ServerHelloDetails("TLS 1.3", "TLS_AES_128_GCM_SHA256", "x25519", false, false),
                new Messages.QuantumSafety(false, "not quantum safe: the server chose x25519"));
        Messages.PacketRow original = new Messages.PacketRow(1, "0.000000", "lo", "127.0.0.1:8443", "127.0.0.1:2", "HTTPS", 120,
                "Server Hello (TLS 1.3, TLS_AES_128_GCM_SHA256, key share x25519); not quantum safe: the server chose x25519",
                null, tls, null, false);
        assertEquals(original, redaction.apply(original));
    }

    @Test
    void rowsWithoutHttpKeepTheirSummary() {
        Messages.PacketRow original = new Messages.PacketRow(1, "0.000000", "lo", "127.0.0.1:1", "127.0.0.1:2", "TCP", 60,
                "1 → 2 [SYN]", null, null, null, false);
        assertEquals(original, redaction.apply(original));
    }

    private static Messages.PacketRow request(String target, Messages.Header... headers) {
        String requestLine = "GET " + target + " HTTP/1.1";
        Messages.MessageDetails http = new Messages.MessageDetails(true, "GET", "http://localhost" + target, target,
                "HTTP/1.1", 0, null, List.of(headers), 0, 0, true, null, false);
        return new Messages.PacketRow(1, "0.000000", "lo", "127.0.0.1:1", "127.0.0.1:2", "HTTP", 100, requestLine, http, null,
                new Messages.ExchangeRef(1, requestLine, true, null), false);
    }

    private static List<Messages.Header> headers(Messages.PacketRow row) {
        return ((Messages.MessageDetails) row.http()).headers();
    }
}
