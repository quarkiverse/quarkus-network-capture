package io.quarkiverse.networkcapture.runtime.dev;

import java.util.List;
import java.util.Map;

/**
 * What the Dev UI page receives over JSON-RPC. The records are serialised by component name, so these names are the
 * property names the page reads.
 */
public final class Messages {

    private Messages() {
    }

    /**
     * @param interfaces the interfaces a capture opens by default, empty for every interface that is up
     */
    public record Settings(String platform, String directory, String elevation, String setupHint, boolean applicationOnly,
            boolean excludeDevUi, List<String> interfaces) {
    }

    /**
     * A network interface the page offers to capture on.
     *
     * @param addresses the interface's IP addresses, to tell interfaces apart
     */
    public record InterfaceInfo(String name, int index, boolean loopback, boolean up, List<String> addresses) {
    }

    // Outcome of a start request: started, permission-required or error.
    public record StartResult(String status, String message, String elevation, String setupHint) {

        static StartResult started() {
            return new StartResult("started", null, null, null);
        }

        static StartResult error(String message) {
            return new StartResult("error", message, null, null);
        }
    }

    public record InterfaceStatus(String name, long packets, long bytes, long filtered, String error) {
    }

    /**
     * @param file absolute path of the capture file, or null when no capture was started yet
     * @param skipped interfaces that could not be opened, with the reason
     */
    public record CaptureStatus(boolean running, String file, String fileName, String startedAt, long packets, long bytes,
            long filtered, long dropped, String filterError, Map<String, String> skipped, List<InterfaceStatus> interfaces) {

        static final CaptureStatus NONE = new CaptureStatus(false, null, null, null, 0, 0, 0, 0, null, Map.of(), List.of());
    }

    public record CaptureFile(String name, long size, String modified) {
    }

    /**
     * One batch of the live packet stream.
     *
     * @param dropped rows that left the server's buffer before any page received them
     */
    public record PacketBatch(boolean running, long dropped, List<PacketRow> packets) {
    }

    /**
     * @param http details of an HTTP/1.x message or body part, or null
     * @param exchange the request/response pairing, or null
     * @param devUi whether the packet belongs to the Dev UI's own traffic
     */
    public record PacketRow(long no, String time, String interfaceName, String source, String destination, String protocol,
            int length, String info, HttpDetails http, ExchangeRef exchange, boolean devUi) {
    }

    public sealed interface HttpDetails permits MessageDetails, BodyPartDetails {
    }

    // An HTTP/1.x request or response whose headers are in this packet.
    public record MessageDetails(boolean request, String method, String url, String target, String version, int status,
            String reason, List<Header> headers, int bodyBytes, long contentLength, boolean bodyComplete, String bodyText,
            boolean bodyTextTruncated) implements HttpDetails {
    }

    // A later part of an HTTP/1.x body; bodyPart is always true and tells the page the two shapes apart.
    public record BodyPartDetails(boolean bodyPart, String message, boolean chunked, long offset, long total, boolean last,
            long remaining, int bodyBytes, String bodyText, boolean bodyTextTruncated) implements HttpDetails {
    }

    public record Header(String name, String value) {
    }

    /**
     * @param requestNo packet number of the request, on a response or body part; null when the request was not seen
     */
    public record ExchangeRef(long id, String request, boolean isRequest, Long requestNo) {
    }
}
