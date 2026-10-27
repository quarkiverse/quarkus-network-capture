package io.quarkiverse.networkcapture.internal.decode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Recognises TLS in a TCP payload: the record headers, which are never encrypted, and the two messages that are
 * always in the clear, the Client Hello and the Server Hello. From them come the server name and ALPN protocols,
 * the versions, cipher suites and key exchange groups offered and chosen, and so the verdict on whether the key
 * exchange is post-quantum. Nothing after the Server Hello can be seen; such segments are reported as application
 * data.
 * <p>
 * References: <a href="https://www.rfc-editor.org/rfc/rfc8446">RFC 8446</a>, section 5.1 (record layer: content
 * type, legacy version, length), section 4.1.2 (Client Hello), section 4.1.3 (Server Hello and Hello Retry Request),
 * section 4.2.1 (supported_versions), 4.2.3 (signature_algorithms), 4.2.7 (supported_groups) and 4.2.8 (key_share);
 * <a href="https://www.rfc-editor.org/rfc/rfc6066">RFC 6066</a>, section 3 (Server Name Indication);
 * <a href="https://www.rfc-editor.org/rfc/rfc7301">RFC 7301</a> (Application-Layer Protocol Negotiation).
 */
final class TlsRecords {

    private TlsRecords() {
    }

    private static final int CHANGE_CIPHER_SPEC = 0x14;
    private static final int ALERT = 0x15;
    private static final int HANDSHAKE = 0x16;
    private static final int APPLICATION_DATA = 0x17;
    private static final int CLIENT_HELLO = 1;
    private static final int SERVER_HELLO = 2;
    private static final int SERVER_NAME = 0;
    private static final int SUPPORTED_GROUPS = 10;
    private static final int SIGNATURE_ALGORITHMS = 13;
    private static final int ALPN = 16;
    private static final int SUPPORTED_VERSIONS = 43;
    private static final int KEY_SHARE = 51;
    private static final int TLS_1_3 = 0x0304;

    // SHA-256 of "HelloRetryRequest": the random of a Server Hello that is really a Hello Retry Request
    private static final byte[] HELLO_RETRY_REQUEST = { (byte) 0xCF, 0x21, (byte) 0xAD, 0x74, (byte) 0xE5, (byte) 0x9A, 0x61,
            0x11, (byte) 0xBE, 0x1D, (byte) 0x8C, 0x02, 0x1E, 0x65, (byte) 0xB8, (byte) 0x91, (byte) 0xC2, (byte) 0xA2, 0x11,
            0x16, 0x7A, (byte) 0xBB, (byte) 0x8C, 0x5E, 0x07, (byte) 0x9E, 0x09, (byte) 0xE2, (byte) 0xC8, (byte) 0xA8, 0x33,
            (byte) 0x9C };

    /**
     * The records in {@code d[o, o+len)}, e.g. {@code Server Hello (TLS 1.3, TLS_AES_128_GCM_SHA256, key share
     * x25519), Change Cipher Spec; not quantum safe: the server chose x25519}, or null when the payload does not
     * start with a record header; the last record may be cut by the segment. The handshake, when non-null, is the
     * Client Hello or Server Hello the payload starts with.
     */
    record Summary(String info, TlsHandshake handshake) {
    }

    static Summary describe(byte[] d, int o, int len) {
        int end = o + len;
        List<String> records = new ArrayList<>();
        TlsHandshake handshake = null;
        int p = o;
        while (end - p >= 5) {
            int type = d[p] & 0xFF;
            if (type < CHANGE_CIPHER_SPEC || type > APPLICATION_DATA || d[p + 1] != 3 || d[p + 2] < 0 || d[p + 2] > 4) {
                return null;
            }
            int length = NetworkLayer.u16(d, p + 3);
            int body = p + 5;
            String name = switch (type) {
                case CHANGE_CIPHER_SPEC -> "Change Cipher Spec";
                case ALERT -> "Alert";
                case APPLICATION_DATA -> "Application Data";
                default -> handshake(d, body, Math.min(body + length, end));
            };
            if (records.isEmpty() && type == HANDSHAKE && body + 4 < end) {
                int available = Math.min(body + length, end);
                boolean truncated = body + length > end;
                if (d[body] == CLIENT_HELLO) {
                    TlsHandshake.ClientHello hello = clientHello(d, body + 4, available, truncated);
                    handshake = new TlsHandshake(hello, null, null);
                    name += clientHelloDetails(hello);
                } else if (d[body] == SERVER_HELLO) {
                    TlsHandshake.ServerHello hello = serverHello(d, body + 4, available, truncated);
                    handshake = new TlsHandshake(null, hello, TlsHandshake.QuantumSafety.of(hello, null));
                    name = (hello.retryRequest() ? "Hello Retry Request" : name) + serverHelloDetails(hello);
                }
            }
            records.add(name);
            p = body + length;
        }
        if (records.isEmpty()) {
            return null;
        }
        String info = String.join(", ", records);
        if (handshake != null && handshake.quantumSafety() != null) {
            info += "; " + handshake.quantumSafety().reason();
        }
        return new Summary(info, handshake);
    }

    // The one-line summary of the Server Hello with the client's verdict, when known, in place of the stateless one
    static String withVerdict(String info, TlsHandshake.QuantumSafety stateless, TlsHandshake.QuantumSafety verdict) {
        String base = stateless == null ? info : info.substring(0, info.length() - 2 - stateless.reason().length());
        return verdict == null ? base : base + "; " + verdict.reason();
    }

    private static String handshake(byte[] d, int o, int end) {
        if (o >= end) {
            return "Handshake";
        }
        return switch (d[o] & 0xFF) {
            case CLIENT_HELLO -> "Client Hello";
            case SERVER_HELLO -> "Server Hello";
            case 4 -> "New Session Ticket";
            case 11 -> "Certificate";
            case 12 -> "Server Key Exchange";
            case 14 -> "Server Hello Done";
            case 16 -> "Client Key Exchange";
            default -> "Handshake";
        };
    }

    private static String clientHelloDetails(TlsHandshake.ClientHello hello) {
        List<String> details = new ArrayList<>();
        if (hello.serverName() != null) {
            details.add("SNI=" + hello.serverName());
        }
        if (!hello.protocols().isEmpty()) {
            details.add("ALPN=" + String.join(", ", hello.protocols()));
        }
        if (!hello.keyShares().isEmpty()) {
            details.add("key shares=" + String.join(", ", hello.keyShares()));
        }
        return details.isEmpty() ? "" : " (" + String.join(", ", details) + ")";
    }

    private static String serverHelloDetails(TlsHandshake.ServerHello hello) {
        List<String> details = new ArrayList<>();
        if (hello.version() != null) {
            details.add(hello.version());
        }
        if (hello.cipherSuite() != null) {
            details.add(hello.cipherSuite());
        }
        if (hello.keyShareGroup() != null) {
            details.add((hello.retryRequest() ? "asks for key share " : "key share ") + hello.keyShareGroup());
        }
        return details.isEmpty() ? "" : " (" + String.join(", ", details) + ")";
    }

    // Parses the Client Hello body in d[o, end); the fields are read in order up to the extensions, and what is
    // missing from a truncated hello is left unset.
    private static TlsHandshake.ClientHello clientHello(byte[] d, int o, int end, boolean truncated) {
        String serverName = null;
        List<String> protocols = new ArrayList<>();
        List<String> versions = new ArrayList<>();
        List<String> cipherSuites = new ArrayList<>();
        List<String> groups = new ArrayList<>();
        List<String> keyShares = new ArrayList<>();
        List<String> signatureAlgorithms = new ArrayList<>();
        try {
            int legacyVersion = NetworkLayer.u16(d, o);
            int p = o + 2 + 32; // version, random
            p += 1 + (d[p] & 0xFF); // session id
            int suites = NetworkLayer.u16(d, p);
            for (int q = p + 2; q < p + 2 + suites && q + 2 <= end; q += 2) {
                cipherSuites.add(TlsNames.cipherSuite(NetworkLayer.u16(d, q)));
            }
            p += 2 + suites;
            p += 1 + (d[p] & 0xFF); // compression methods
            int extensionsEnd = Math.min(p + 2 + NetworkLayer.u16(d, p), end);
            p += 2;
            while (p + 4 <= extensionsEnd) {
                int type = NetworkLayer.u16(d, p);
                int length = NetworkLayer.u16(d, p + 2);
                int data = p + 4;
                if (data + length > extensionsEnd) {
                    truncated = true;
                    break;
                }
                switch (type) {
                    case SERVER_NAME -> {
                        if (length >= 5 && d[data + 2] == 0) {
                            int nameLength = NetworkLayer.u16(d, data + 3);
                            serverName = new String(d, data + 5, Math.min(nameLength, length - 5), StandardCharsets.US_ASCII);
                        }
                    }
                    case ALPN -> {
                        int q = data + 2;
                        while (q < data + length) {
                            int nameLength = d[q] & 0xFF;
                            protocols.add(new String(d, q + 1, Math.min(nameLength, data + length - q - 1), StandardCharsets.US_ASCII));
                            q += 1 + nameLength;
                        }
                    }
                    case SUPPORTED_VERSIONS -> {
                        for (int q = data + 1; q + 2 <= data + 1 + (d[data] & 0xFF) && q + 2 <= data + length; q += 2) {
                            versions.add(TlsNames.version(NetworkLayer.u16(d, q)));
                        }
                    }
                    case SUPPORTED_GROUPS -> u16List(d, data, length, groups, TlsNames::group);
                    case SIGNATURE_ALGORITHMS -> u16List(d, data, length, signatureAlgorithms, TlsNames::signatureScheme);
                    case KEY_SHARE -> {
                        int q = data + 2;
                        int listEnd = Math.min(data + 2 + NetworkLayer.u16(d, data), data + length);
                        while (q + 4 <= listEnd) {
                            keyShares.add(TlsNames.group(NetworkLayer.u16(d, q)));
                            q += 4 + NetworkLayer.u16(d, q + 2);
                        }
                    }
                    default -> {
                    }
                }
                p = data + length;
            }
            if (versions.isEmpty()) {
                versions.add(TlsNames.version(legacyVersion));
            }
        } catch (IndexOutOfBoundsException e) {
            truncated = true; // keep what was read
        }
        return new TlsHandshake.ClientHello(serverName, protocols, versions, cipherSuites, groups, keyShares,
                signatureAlgorithms, truncated);
    }

    // Parses the Server Hello body in d[o, end); the version is only known once the extensions were read in full,
    // because TLS 1.3 announces itself there and puts TLS 1.2 in the legacy field.
    private static TlsHandshake.ServerHello serverHello(byte[] d, int o, int end, boolean truncated) {
        String version = null;
        String cipherSuite = null;
        String keyShareGroup = null;
        boolean retryRequest = false;
        try {
            int legacyVersion = NetworkLayer.u16(d, o);
            retryRequest = Arrays.equals(d, o + 2, o + 2 + 32, HELLO_RETRY_REQUEST, 0, 32);
            int p = o + 2 + 32; // version, random
            p += 1 + (d[p] & 0xFF); // session id
            cipherSuite = TlsNames.cipherSuite(NetworkLayer.u16(d, p));
            p += 2 + 1; // cipher suite, compression method
            if (p == end && !truncated) {
                return new TlsHandshake.ServerHello(TlsNames.version(legacyVersion), cipherSuite, null, retryRequest, false);
            }
            int extensionsEnd = Math.min(p + 2 + NetworkLayer.u16(d, p), end);
            p += 2;
            while (p + 4 <= extensionsEnd) {
                int type = NetworkLayer.u16(d, p);
                int length = NetworkLayer.u16(d, p + 2);
                int data = p + 4;
                if (data + length > extensionsEnd) {
                    truncated = true;
                    break;
                }
                if (type == SUPPORTED_VERSIONS && length >= 2) {
                    version = TlsNames.version(NetworkLayer.u16(d, data));
                } else if (type == KEY_SHARE && length >= 2) {
                    keyShareGroup = TlsNames.group(NetworkLayer.u16(d, data));
                }
                p = data + length;
            }
            if (version == null && !truncated) {
                version = TlsNames.version(legacyVersion);
            }
        } catch (IndexOutOfBoundsException e) {
            truncated = true; // keep what was read
        }
        return new TlsHandshake.ServerHello(version, cipherSuite, keyShareGroup, retryRequest, truncated);
    }

    // Reads a u16-length-prefixed list of u16 code points into names
    private static void u16List(byte[] d, int data, int length, List<String> into, java.util.function.IntFunction<String> name) {
        int listEnd = Math.min(data + 2 + NetworkLayer.u16(d, data), data + length);
        for (int q = data + 2; q + 2 <= listEnd; q += 2) {
            into.add(name.apply(NetworkLayer.u16(d, q)));
        }
    }
}
