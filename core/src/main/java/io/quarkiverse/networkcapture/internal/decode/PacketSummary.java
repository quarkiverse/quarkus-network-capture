package io.quarkiverse.networkcapture.internal.decode;

import java.util.ArrayList;
import java.util.List;
import io.quarkiverse.networkcapture.LinkType;

/**
 * A one line, Wireshark style description of a packet: the columns of Wireshark's packet list.
 * <p>
 * References for the headers decoded here: {@link NetworkLayer} and {@link IpPacket} for the link and network
 * layers; <a href="https://www.rfc-editor.org/rfc/rfc826">RFC 826</a> (ARP);
 * {@link TransportSegment} for TCP and UDP;
 * <a href="https://www.rfc-editor.org/rfc/rfc792">RFC 792</a> (ICMP);
 * <a href="https://www.rfc-editor.org/rfc/rfc4443">RFC 4443</a> (ICMPv6);
 * {@link HttpMessage} for HTTP/1.x and {@link Http2Frames} for HTTP/2, both recognised at the start of a TCP
 * segment's payload; {@link TlsRecords} for TLS, whose records and hellos are shown but whose content cannot be. TLS is
 * reported as {@code HTTPS} when the Client Hello offers HTTP through ALPN, or offers nothing and the connection
 * uses a well known HTTPS port, and as {@code TLS} otherwise.
 *
 * @param source source address, with port for TCP and UDP
 * @param destination destination address, with port for TCP and UDP
 * @param protocol highest protocol recognised, e.g. {@code HTTP}, {@code TCP}, {@code UDP}, {@code ARP}
 * @param info protocol specific details
 * @param sourcePort TCP or UDP source port, or -1
 * @param destinationPort TCP or UDP destination port, or -1
 * @param http the parsed HTTP/1.x message when the packet starts one, otherwise null
 * @param httpBody a later part of an HTTP/1.x body, only produced by {@link HttpStreamDecoder}, otherwise null
 * @param exchange the request/response pairing, only produced by {@link HttpStreamDecoder}, otherwise null
 * @param tls the TLS handshake details when the packet starts a Client Hello or Server Hello, and the key exchange
 *        verdict on any later packet of a TLS connection, only produced by {@link HttpStreamDecoder}; otherwise null
 */
public record PacketSummary(String source, String destination, String protocol, String info, int sourcePort,
        int destinationPort, HttpMessage http, HttpBodyPart httpBody, HttpExchange exchange, TlsHandshake tls) {

    public PacketSummary(String source, String destination, String protocol, String info, int sourcePort,
            int destinationPort) {
        this(source, destination, protocol, info, sourcePort, destinationPort, null, null, null, null);
    }

    PacketSummary withExchange(HttpExchange exchange) {
        return new PacketSummary(source, destination, protocol, info, sourcePort, destinationPort, http, httpBody, exchange,
                null);
    }

    // Whether a TLS connection on these ports should be assumed to carry HTTP when its Client Hello does not say
    public static boolean httpsPort(int sourcePort, int destinationPort) {
        return sourcePort == 443 || sourcePort == 8443 || destinationPort == 443 || destinationPort == 8443;
    }

    public static PacketSummary decode(LinkType linkType, byte[] data) {
        try {
            NetworkLayer network = NetworkLayer.of(linkType, data);
            if (network == null) {
                return malformed();
            }
            IpPacket ip = IpPacket.of(network, data);
            if (ip != null) {
                return ip(ip, data);
            }
            return switch (network.etherType()) {
                case NetworkLayer.ARP -> arp(data, network.offset());
                case NetworkLayer.IPV4, NetworkLayer.IPV6 -> malformed();
                default -> linkType == LinkType.ETHERNET
                        ? new PacketSummary(mac(data, 6), mac(data, 0), "Ethernet",
                                "type 0x" + Integer.toHexString(network.etherType()), -1, -1)
                        : new PacketSummary("", "", linkType.name(), "unknown protocol", -1, -1);
            };
        } catch (IndexOutOfBoundsException e) {
            return malformed();
        }
    }

    private static PacketSummary malformed() {
        return new PacketSummary("", "", "Malformed", "truncated packet", -1, -1);
    }

    private static PacketSummary arp(byte[] d, int o) {
        int op = NetworkLayer.u16(d, o + 6);
        String sender = IpPacket.ipv4(d, o + 14);
        String target = IpPacket.ipv4(d, o + 24);
        String info = op == 1 ? "Who has " + target + "? Tell " + sender : op == 2 ? sender + " is at " + mac(d, o + 8) : "opcode " + op;
        return new PacketSummary(sender, target, "ARP", info, -1, -1);
    }

    private static PacketSummary ip(IpPacket ip, byte[] d) {
        String src = ip.source();
        String dst = ip.destination();
        int payload = ip.payloadOffset();
        return switch (ip.protocol()) {
            case IpPacket.TCP, IpPacket.UDP -> {
                TransportSegment segment = TransportSegment.of(ip, d);
                yield segment == null ? malformed() : segment.tcp() ? tcp(segment, d, src, dst) : udp(segment, src, dst);
            }
            case IpPacket.ICMP -> new PacketSummary(src, dst, "ICMP", "type " + (d[payload] & 0xFF) + " code " + (d[payload + 1] & 0xFF), -1, -1);
            case IpPacket.ICMPV6 -> new PacketSummary(src, dst, "ICMPv6", "type " + (d[payload] & 0xFF) + " code " + (d[payload + 1] & 0xFF), -1, -1);
            default -> new PacketSummary(src, dst, "IPv" + ip.version(), "protocol " + ip.protocol(), -1, -1);
        };
    }

    private static PacketSummary tcp(TransportSegment s, byte[] d, String src, String dst) {
        String source = src + ":" + s.sourcePort();
        String destination = dst + ":" + s.destinationPort();
        String startLine = HttpMessage.startLine(d, s.payloadOffset(), s.payloadLength());
        if (startLine != null) {
            // the message is null when the header section does not fit in this segment
            return new PacketSummary(source, destination, "HTTP", startLine, s.sourcePort(), s.destinationPort(),
                    HttpMessage.parse(d, s.payloadOffset(), s.payloadLength()), null, null, null);
        }
        String http2 = Http2Frames.describe(d, s.payloadOffset(), s.payloadLength());
        if (http2 != null) {
            return new PacketSummary(source, destination, "HTTP2", http2, s.sourcePort(), s.destinationPort());
        }
        TlsRecords.Summary tls = TlsRecords.describe(d, s.payloadOffset(), s.payloadLength());
        if (tls != null) {
            TlsHandshake.ClientHello hello = tls.handshake() == null ? null : tls.handshake().clientHello();
            boolean https = hello != null && !hello.protocols().isEmpty() ? hello.http()
                    : httpsPort(s.sourcePort(), s.destinationPort());
            return new PacketSummary(source, destination, https ? "HTTPS" : "TLS", tls.info(), s.sourcePort(), s.destinationPort(),
                    null, null, null, tls.handshake());
        }
        List<String> names = new ArrayList<>();
        if ((s.flags() & TransportSegment.SYN) != 0) names.add("SYN");
        if ((s.flags() & TransportSegment.ACK) != 0) names.add("ACK");
        if ((s.flags() & TransportSegment.PSH) != 0) names.add("PSH");
        if ((s.flags() & TransportSegment.FIN) != 0) names.add("FIN");
        if ((s.flags() & TransportSegment.RST) != 0) names.add("RST");
        String info = s.sourcePort() + " → " + s.destinationPort() + " [" + String.join(", ", names) + "] Seq=" + s.sequence()
                + " Len=" + s.payloadLength();
        return new PacketSummary(source, destination, "TCP", info, s.sourcePort(), s.destinationPort());
    }

    private static PacketSummary udp(TransportSegment s, String src, String dst) {
        return new PacketSummary(src + ":" + s.sourcePort(), dst + ":" + s.destinationPort(), "UDP",
                s.sourcePort() + " → " + s.destinationPort() + " Len=" + s.payloadLength(), s.sourcePort(), s.destinationPort());
    }

    private static String mac(byte[] d, int o) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) {
                sb.append(':');
            }
            sb.append(String.format("%02x", d[o + i] & 0xFF));
        }
        return sb.toString();
    }
}
