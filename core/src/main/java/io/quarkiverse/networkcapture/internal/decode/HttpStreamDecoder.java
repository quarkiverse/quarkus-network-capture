package io.quarkiverse.networkcapture.internal.decode;

import java.io.ByteArrayOutputStream;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.Map;
import io.quarkiverse.networkcapture.LinkType;

/**
 * {@link PacketSummary#decode} with memory: once a message has announced a chunked body or a {@code Content-Length}
 * that did not fit in its segment, the following segments in the same direction of the same connection are decoded
 * as parts of that body instead of plain TCP. Chunk framing is removed, chunks may span segments. State is dropped
 * when the body ends, when the connection closes, or when too many connections are tracked. Not thread safe; use one
 * instance per consumer.
 * <p>
 * TLS connections are remembered from their Client Hello, so that the segments that follow, which cannot be
 * recognised on their own because they are encrypted or start in the middle of a record, are reported as the same
 * protocol with the server name the client asked for. The Server Hello's verdict on the key exchange is worded with
 * what the client offered, and is carried by every later segment of the connection.
 * <p>
 * Requests and responses are also paired into {@link HttpExchange}s: a response, and the body parts that follow it,
 * refer to the oldest request on the connection that is still unanswered.
 * <p>
 * References: <a href="https://www.rfc-editor.org/rfc/rfc9112#section-7.1">RFC 9112 section 7.1</a> (chunked
 * transfer coding: hex size line with optional extensions, data, CRLF, terminated by a zero sized chunk and optional
 * trailer section) and <a href="https://www.rfc-editor.org/rfc/rfc9112#section-6">section 6</a> (message body length).
 */
public final class HttpStreamDecoder {

    private static final int MAX_CONNECTIONS = 1024;
    private static final int MAX_PENDING = 64 * 1024;
    private static final int MAX_UNANSWERED = 64;

    // Body state of one direction of one connection.
    private static final class Body {
        final String message; // start line of the message the body belongs to
        HttpExchange exchange; // the pairing of the message, when it is a response
        final boolean chunked;
        final long total; // content length, or -1 when chunked
        long delivered; // decoded body bytes handed out so far
        long remaining; // content-length bytes still expected, or in chunked mode the data bytes of the current chunk
        int trailingCrlf; // CRLF bytes still to skip after a chunk's data
        boolean finished;
        byte[] pending = new byte[0]; // bytes of an incomplete chunk size line

        Body(String message, boolean chunked, long total, long remaining) {
            this.message = message;
            this.chunked = chunked;
            this.total = total;
            this.remaining = remaining;
        }
    }

    // The three maps below are bounded LRU caches: with accessOrder (the third constructor argument, the first two
    // being HashMap's defaults) a LinkedHashMap moves an entry to the tail on every get or put, and removeEldestEntry
    // is consulted after each insertion, so once there are more than MAX_CONNECTIONS entries the one that has not
    // seen a packet for the longest is dropped. Insertion order would instead forget long lived connections, such as
    // a pool member or an SSE stream, that are still busy. A dropped entry only means the segment shows as plain TCP.
    private final Map<String, Body> bodies = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Body> eldest) {
            return size() > MAX_CONNECTIONS;
        }
    };

    // Unanswered requests per connection, keyed by the endpoints in a direction independent order.
    private final Map<String, Deque<HttpExchange>> unanswered = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Deque<HttpExchange>> eldest) {
            return size() > MAX_CONNECTIONS;
        }
    };
    private long nextExchange = 1;

    // What is known about one TLS connection: from its Client Hello, then from its Server Hello.
    private static final class Tls {
        final String protocol;
        final TlsHandshake.ClientHello clientHello;
        TlsHandshake.QuantumSafety verdict;

        Tls(String protocol, TlsHandshake.ClientHello clientHello) {
            this.protocol = protocol;
            this.clientHello = clientHello;
        }

        String serverName() {
            return clientHello == null ? null : clientHello.serverName();
        }
    }

    private final Map<String, Tls> tls = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Tls> eldest) {
            return size() > MAX_CONNECTIONS;
        }
    };

    public PacketSummary decode(LinkType linkType, byte[] data) {
        PacketSummary summary = PacketSummary.decode(linkType, data);
        boolean tcp = summary.protocol().equals("TCP");
        boolean encrypted = summary.protocol().equals("TLS") || summary.protocol().equals("HTTPS");
        if (!tcp && !encrypted && !summary.protocol().equals("HTTP")) {
            return summary;
        }
        TransportSegment segment = TransportSegment.of(linkType, data);
        if (segment == null || !segment.tcp()) {
            return summary;
        }
        String key = summary.source() + ">" + summary.destination();
        String connection = summary.source().compareTo(summary.destination()) < 0
                ? summary.source() + "|" + summary.destination()
                : summary.destination() + "|" + summary.source();
        if (summary.tls() != null && summary.tls().clientHello() != null) {
            tls.put(connection, new Tls(summary.protocol(), summary.tls().clientHello()));
        }
        Tls known = tls.get(connection);
        if (known != null && segment.payloadLength() > 0) {
            String suffix = known.serverName() == null ? "" : " (" + known.serverName() + ")";
            TlsHandshake.ServerHello serverHello = summary.tls() == null ? null : summary.tls().serverHello();
            if (serverHello != null) {
                TlsHandshake.QuantumSafety verdict = TlsHandshake.QuantumSafety.of(serverHello, known.clientHello);
                known.verdict = verdict;
                summary = new PacketSummary(summary.source(), summary.destination(), known.protocol,
                        TlsRecords.withVerdict(summary.info(), summary.tls().quantumSafety(), verdict) + suffix,
                        summary.sourcePort(), summary.destinationPort(), null, null, null,
                        new TlsHandshake(null, serverHello, verdict));
            } else {
                String info = encrypted && summary.tls() == null ? summary.info() : tcp ? "Continuation Data" : null;
                if (info != null) {
                    summary = new PacketSummary(summary.source(), summary.destination(), known.protocol, info + suffix,
                            summary.sourcePort(), summary.destinationPort(), null, null, null,
                            known.verdict == null ? null : new TlsHandshake(null, null, known.verdict));
                }
            }
        }
        if (encrypted || known != null) {
            if (segment.closes()) {
                tls.remove(connection);
            }
            return summary;
        }
        if (summary.http() != null) {
            HttpExchange exchange = pair(connection, summary.http());
            Body body = remember(key, summary.http());
            if (body != null) {
                body.exchange = exchange;
            }
            if (segment.closes()) {
                unanswered.remove(connection);
            }
            return exchange == null ? summary : summary.withExchange(exchange);
        }
        Body body = bodies.get(key);
        PacketSummary result = summary;
        if (body != null && segment.payloadLength() > 0) {
            HttpBodyPart part = body.chunked
                    ? chunks(body, data, segment.payloadOffset(), segment.payloadLength())
                    : plain(body, data, segment.payloadOffset(), segment.payloadLength());
            if (part != null) {
                String text = part.asText(60);
                String info = (part.chunked() ? (part.last() ? "Last chunk of " : "Chunk of ") : "Body of ") + part.message()
                        + (part.chunked() ? "" : " [" + (part.offset() + 1) + "-" + (part.offset() + part.data().length) + " of " + part.total() + "]")
                        + ": " + (text == null ? part.data().length + " bytes" : text.replace("\r", "\\r").replace("\n", "\\n"));
                result = new PacketSummary(summary.source(), summary.destination(), "HTTP", info, summary.sourcePort(),
                        summary.destinationPort(), null, part, body.exchange, null);
            }
            if (body.finished) {
                bodies.remove(key);
            }
        }
        if (segment.closes()) {
            bodies.remove(key);
            unanswered.remove(connection);
        }
        return result;
    }

    // Records a request as unanswered, or pairs a response with the oldest unanswered request.
    private HttpExchange pair(String connection, HttpMessage message) {
        if (message.isRequest()) {
            Deque<HttpExchange> queue = unanswered.computeIfAbsent(connection, k -> new ArrayDeque<>());
            if (queue.size() >= MAX_UNANSWERED) {
                queue.pollFirst();
            }
            HttpExchange exchange = new HttpExchange(nextExchange++, message.startLine(), true);
            queue.addLast(exchange);
            return exchange;
        }
        if (message.status() >= 100 && message.status() < 200 && message.status() != 101) {
            return null; // interim response, the final one is still to come
        }
        Deque<HttpExchange> queue = unanswered.get(connection);
        HttpExchange request = queue == null ? null : queue.pollFirst();
        return request == null ? null : new HttpExchange(request.id(), request.request(), false);
    }

    private Body remember(String key, HttpMessage message) {
        String startLine = message.startLine();
        String transferEncoding = message.header("Transfer-Encoding");
        if (transferEncoding != null && transferEncoding.toLowerCase().contains("chunked")) {
            Body body = new Body(startLine, true, -1, 0);
            // the bytes after the headers already belong to the body
            if (message.body().length > 0) {
                chunks(body, message.body(), 0, message.body().length);
            }
            if (!body.finished) {
                bodies.put(key, body);
                return body;
            }
        } else if (message.contentLength() > message.body().length) {
            Body body = new Body(startLine, false, message.contentLength(), message.contentLength() - message.body().length);
            body.delivered = message.body().length;
            bodies.put(key, body);
            return body;
        }
        bodies.remove(key);
        return null;
    }

    private static HttpBodyPart plain(Body body, byte[] d, int o, int len) {
        int take = (int) Math.min(len, body.remaining);
        body.remaining -= take;
        body.finished = body.remaining == 0;
        HttpBodyPart part = new HttpBodyPart(body.message, Arrays.copyOfRange(d, o, o + take), false, body.delivered, body.total,
                body.finished);
        body.delivered += take;
        return part;
    }

    // Decodes the chunks in d[o, o+len), continuing from the body's state; null when nothing decodable yet.
    private static HttpBodyPart chunks(Body body, byte[] d, int o, int len) {
        byte[] in;
        if (body.pending.length > 0) {
            in = new byte[body.pending.length + len];
            System.arraycopy(body.pending, 0, in, 0, body.pending.length);
            System.arraycopy(d, o, in, body.pending.length, len);
            body.pending = new byte[0];
        } else {
            in = Arrays.copyOfRange(d, o, o + len);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int p = 0;
        while (p < in.length && !body.finished) {
            if (body.trailingCrlf > 0) {
                int skip = Math.min(body.trailingCrlf, in.length - p);
                body.trailingCrlf -= skip;
                p += skip;
            } else if (body.remaining > 0) {
                int take = (int) Math.min(body.remaining, in.length - p);
                out.write(in, p, take);
                p += take;
                body.remaining -= take;
                if (body.remaining == 0) {
                    body.trailingCrlf = 2;
                }
            } else {
                int lineEnd = indexOfCrlf(in, p);
                if (lineEnd < 0) {
                    if (in.length - p <= MAX_PENDING) {
                        body.pending = Arrays.copyOfRange(in, p, in.length);
                    }
                    break;
                }
                String line = new String(in, p, lineEnd - p, java.nio.charset.StandardCharsets.US_ASCII);
                int semicolon = line.indexOf(';');
                long size;
                try {
                    size = Long.parseLong((semicolon >= 0 ? line.substring(0, semicolon) : line).trim(), 16);
                } catch (NumberFormatException e) {
                    body.finished = true; // not a chunk after all, stop decoding this direction
                    break;
                }
                p = lineEnd + 2;
                if (size == 0) {
                    body.finished = true; // trailer fields, if any, are ignored
                } else {
                    body.remaining = size;
                }
            }
        }
        if (out.size() == 0 && !body.finished) {
            return null;
        }
        HttpBodyPart part = new HttpBodyPart(body.message, out.toByteArray(), true, body.delivered, -1, body.finished);
        body.delivered += out.size();
        return part;
    }

    private static int indexOfCrlf(byte[] d, int from) {
        for (int i = from; i < d.length - 1; i++) {
            if (d[i] == '\r' && d[i + 1] == '\n') {
                return i;
            }
        }
        return -1;
    }
}
