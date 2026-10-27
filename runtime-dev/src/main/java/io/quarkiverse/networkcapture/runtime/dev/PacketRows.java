package io.quarkiverse.networkcapture.runtime.dev;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import io.quarkiverse.networkcapture.CapturedPacket;
import io.quarkiverse.networkcapture.Packet;
import io.quarkiverse.networkcapture.PacketListener;
import io.quarkiverse.networkcapture.internal.decode.HttpBodyPart;
import io.quarkiverse.networkcapture.internal.decode.HttpExchange;
import io.quarkiverse.networkcapture.internal.decode.HttpMessage;
import io.quarkiverse.networkcapture.internal.decode.HttpRequestFilter;
import io.quarkiverse.networkcapture.internal.decode.HttpStreamDecoder;
import io.quarkiverse.networkcapture.internal.decode.PacketSummary;
import io.quarkiverse.networkcapture.internal.decode.TlsHandshake;


/**
 * The rows of the live packet list, decoded once per capture as packets are written and kept in a bounded buffer,
 * so that a page can pick up what it missed while it was not connected, and a page opened later still sees the
 * recent packets. Decoding runs on the capture's writer thread; reads come from the Dev UI.
 */
final class PacketRows implements PacketListener {

    static final int CAPACITY = 2000;
    // Longest body text sent to the browser per message.
    static final int BODY_TEXT_LIMIT = 16 * 1024;

    private final Instant startedAt;
    private final HttpStreamDecoder decoder = new HttpStreamDecoder();
    private final HttpRequestFilter devUiExchanges = new HttpRequestFilter(DevUiConnections::isDevUiPath);
    private final Map<Long, Long> requestNumbers = new LinkedHashMap<>(16, 0.75f, false) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<Long, Long> eldest) {
            return size() > 4096;
        }
    };
    private final ArrayDeque<Messages.PacketRow> rows = new ArrayDeque<>();
    private long next = 1;
    private long evicted;

    PacketRows(Instant startedAt) {
        this.startedAt = startedAt;
    }

    @Override
    public void onPacket(CapturedPacket captured) {
        Packet packet = captured.packet();
        PacketSummary summary = decoder.decode(captured.linkType(), packet.data());
        boolean devUi = summary.sourcePort() >= 0
                && DevUiConnections.isDevUiConnection(summary.sourcePort(), summary.destinationPort())
                || devUiExchanges.excludes(summary);
        Messages.HttpDetails http = summary.http() != null ? http(summary.http())
                : summary.httpBody() != null ? bodyPart(summary.httpBody()) : null;
        Messages.TlsDetails tls = summary.tls() == null ? null : tls(summary.tls());
        long startNanos = startedAt.getEpochSecond() * 1_000_000_000L + startedAt.getNano();
        synchronized (this) {
            long no = next++;
            Messages.ExchangeRef exchange = null;
            if (summary.exchange() != null) {
                HttpExchange x = summary.exchange();
                if (x.isRequest()) {
                    requestNumbers.put(x.id(), no);
                }
                exchange = new Messages.ExchangeRef(x.id(), x.request(), x.isRequest(),
                        x.isRequest() ? null : requestNumbers.get(x.id()));
            }
            rows.addLast(new Messages.PacketRow(no, String.format("%.6f", (packet.timestampNanos() - startNanos) / 1e9),
                    captured.networkInterface().name(), summary.source(), summary.destination(), summary.protocol(),
                    packet.originalLength(), summary.info(), http, tls, exchange, devUi));
            if (rows.size() > CAPACITY) {
                rows.removeFirst();
                evicted++;
            }
        }
    }

    /**
     * The rows after packet number {@code after}, oldest first, at most {@code max}.
     *
     * @param hideDevUi whether to leave out the Dev UI's own traffic
     */
    synchronized Messages.PacketBatch since(long after, boolean hideDevUi, int max, boolean running) {
        List<Messages.PacketRow> result = new ArrayList<>();
        for (Messages.PacketRow row : rows) {
            if (row.no() <= after || hideDevUi && row.devUi()) {
                continue;
            }
            result.add(row);
            if (result.size() == max) {
                break;
            }
        }
        return new Messages.PacketBatch(running, evicted, result);
    }

    private static Messages.MessageDetails http(HttpMessage m) {
        List<Messages.Header> headers = new ArrayList<>();
        for (HttpMessage.Header header : m.headers()) {
            headers.add(new Messages.Header(header.name(), header.value()));
        }
        String text = m.bodyAsText(BODY_TEXT_LIMIT);
        return new Messages.MessageDetails(m.isRequest(), m.method(), m.url(), m.target(), m.version(), m.status(), m.reason(),
                headers, m.body().length, m.contentLength(), m.bodyComplete(), text, truncated(text, m.body().length));
    }

    private static Messages.BodyPartDetails bodyPart(HttpBodyPart part) {
        String text = part.asText(BODY_TEXT_LIMIT);
        return new Messages.BodyPartDetails(true, part.message(), part.chunked(), part.offset(), part.total(), part.last(),
                part.remaining(), part.data().length, text, truncated(text, part.data().length));
    }

    private static Messages.TlsDetails tls(TlsHandshake handshake) {
        TlsHandshake.ClientHello c = handshake.clientHello();
        TlsHandshake.ServerHello s = handshake.serverHello();
        TlsHandshake.QuantumSafety q = handshake.quantumSafety();
        return new Messages.TlsDetails(
                c == null ? null : new Messages.ClientHelloDetails(c.serverName(), c.protocols(), c.versions(), c.cipherSuites(),
                        c.groups(), c.keyShares(), c.signatureAlgorithms(), c.postQuantumGroups(), c.truncated()),
                s == null ? null : new Messages.ServerHelloDetails(s.version(), s.cipherSuite(), s.keyShareGroup(),
                        s.retryRequest(), s.truncated()),
                q == null ? null : new Messages.QuantumSafety(q.safe(), q.reason()));
    }

    private static boolean truncated(String text, int bodyLength) {
        return text != null && text.length() == BODY_TEXT_LIMIT && bodyLength > BODY_TEXT_LIMIT;
    }
}
