package io.quarkiverse.networkcapture;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

// Builders for synthetic packets.
public final class TestPackets {

    private TestPackets() {
    }

    public static byte[] ethernet(int type) {
        byte[] h = new byte[14];
        h[12] = (byte) (type >> 8);
        h[13] = (byte) type;
        return h;
    }

    public static byte[] ipv4(int proto, byte[] src, byte[] dst, int payloadLength) {
        byte[] h = new byte[20];
        h[0] = 0x45;
        int total = 20 + payloadLength;
        h[2] = (byte) (total >> 8);
        h[3] = (byte) total;
        h[9] = (byte) proto;
        System.arraycopy(src, 0, h, 12, 4);
        System.arraycopy(dst, 0, h, 16, 4);
        return h;
    }

    public static byte[] ipv6(int nextHeader, byte[] src, byte[] dst, int payloadLength) {
        byte[] h = new byte[40];
        h[0] = 0x60;
        h[4] = (byte) (payloadLength >> 8);
        h[5] = (byte) payloadLength;
        h[6] = (byte) nextHeader;
        System.arraycopy(src, 0, h, 8, 16);
        System.arraycopy(dst, 0, h, 24, 16);
        return h;
    }

    public static byte[] tcp(int sport, int dport, int flags) {
        byte[] h = new byte[20];
        h[0] = (byte) (sport >> 8);
        h[1] = (byte) sport;
        h[2] = (byte) (dport >> 8);
        h[3] = (byte) dport;
        h[7] = 7; // sequence number
        h[12] = 0x50; // data offset 5 words
        h[13] = (byte) flags;
        return h;
    }

    public static byte[] udp(int sport, int dport, int length) {
        byte[] h = new byte[length];
        h[0] = (byte) (sport >> 8);
        h[1] = (byte) sport;
        h[2] = (byte) (dport >> 8);
        h[3] = (byte) dport;
        h[5] = (byte) length;
        return h;
    }

    public static byte[] loopbackTcp(int sport, int dport) {
        byte[] lo = { 127, 0, 0, 1 };
        return concat(ethernet(0x0800), ipv4(6, lo, lo, 20), tcp(sport, dport, 0x18));
    }

    // An Ethernet packet as a session would hand it to a filter, captured on the loopback interface.
    public static CapturedPacket captured(byte[] data) {
        return CapturedPacket.builder()
                .networkInterface(CaptureInterface.builder().name("lo").index(1).loopback(true).build())
                .linkType(LinkType.ETHERNET)
                .packet(Packet.builder().timestampNanos(0).data(data).build())
                .build();
    }

    /**
     * A TLS record carrying a Client Hello with the given server name (null for none) and ALPN protocols (none for
     * no ALPN extension); only the fields the decoder reads are meaningful.
     */
    public static byte[] clientHello(String serverName, String... alpn) {
        return clientHello().serverName(serverName).alpn(alpn).build();
    }

    public static TlsHello clientHello() {
        return new TlsHello(true);
    }

    public static TlsHello serverHello() {
        return new TlsHello(false);
    }

    // Builds the record of a Client Hello or Server Hello; code points are IANA values, e.g. 0x1301 for a cipher suite.
    public static final class TlsHello {

        // SHA-256 of "HelloRetryRequest", the random of a TLS 1.3 Hello Retry Request (RFC 8446 section 4.1.3)
        private static final byte[] HELLO_RETRY_REQUEST = { (byte) 0xCF, 0x21, (byte) 0xAD, 0x74, (byte) 0xE5, (byte) 0x9A,
                0x61, 0x11, (byte) 0xBE, 0x1D, (byte) 0x8C, 0x02, 0x1E, 0x65, (byte) 0xB8, (byte) 0x91, (byte) 0xC2,
                (byte) 0xA2, 0x11, 0x16, 0x7A, (byte) 0xBB, (byte) 0x8C, 0x5E, 0x07, (byte) 0x9E, 0x09, (byte) 0xE2,
                (byte) 0xC8, (byte) 0xA8, 0x33, (byte) 0x9C };

        private final boolean client;
        private String serverName;
        private String[] alpn = new String[0];
        private int[] versions = new int[0]; // supported_versions, absent when empty
        private int[] cipherSuites = { 0x1301 };
        private int[] groups = new int[0];
        private int[] keyShares = new int[0];
        private int[] signatureAlgorithms = new int[0];
        private boolean retryRequest;

        private TlsHello(boolean client) {
            this.client = client;
        }

        public TlsHello serverName(String serverName) {
            this.serverName = serverName;
            return this;
        }

        public TlsHello alpn(String... alpn) {
            this.alpn = alpn;
            return this;
        }

        // The supported_versions extension: offered versions on a Client Hello, the selected one on a Server Hello
        public TlsHello versions(int... versions) {
            this.versions = versions;
            return this;
        }

        // Offered cipher suites on a Client Hello, the single selected one on a Server Hello
        public TlsHello cipherSuites(int... cipherSuites) {
            this.cipherSuites = cipherSuites;
            return this;
        }

        public TlsHello groups(int... groups) {
            this.groups = groups;
            return this;
        }

        // Key share entries on a Client Hello, the single selected one on a Server Hello
        public TlsHello keyShares(int... keyShares) {
            this.keyShares = keyShares;
            return this;
        }

        public TlsHello signatureAlgorithms(int... signatureAlgorithms) {
            this.signatureAlgorithms = signatureAlgorithms;
            return this;
        }

        // Makes a Server Hello a Hello Retry Request, whose key share names only the group the server wants
        public TlsHello retryRequest() {
            this.retryRequest = true;
            return this;
        }

        public byte[] build() {
            ByteArrayOutputStream ext = new ByteArrayOutputStream();
            if (serverName != null) {
                byte[] name = serverName.getBytes(StandardCharsets.US_ASCII);
                ByteArrayOutputStream data = new ByteArrayOutputStream();
                u16(data, name.length + 3);
                data.write(0); // host_name
                u16(data, name.length);
                data.writeBytes(name);
                extension(ext, 0, data.toByteArray());
            }
            if (groups.length > 0) {
                extension(ext, 10, u16List(groups));
            }
            if (signatureAlgorithms.length > 0) {
                extension(ext, 13, u16List(signatureAlgorithms));
            }
            if (alpn.length > 0) {
                ByteArrayOutputStream list = new ByteArrayOutputStream();
                for (String protocol : alpn) {
                    byte[] b = protocol.getBytes(StandardCharsets.US_ASCII);
                    list.write(b.length);
                    list.writeBytes(b);
                }
                ByteArrayOutputStream data = new ByteArrayOutputStream();
                u16(data, list.size());
                data.writeBytes(list.toByteArray());
                extension(ext, 16, data.toByteArray());
            }
            if (versions.length > 0) {
                if (client) {
                    ByteArrayOutputStream data = new ByteArrayOutputStream();
                    data.write(versions.length * 2);
                    for (int v : versions) {
                        u16(data, v);
                    }
                    extension(ext, 43, data.toByteArray());
                } else {
                    ByteArrayOutputStream data = new ByteArrayOutputStream();
                    u16(data, versions[0]);
                    extension(ext, 43, data.toByteArray());
                }
            }
            if (keyShares.length > 0) {
                ByteArrayOutputStream entries = new ByteArrayOutputStream();
                for (int group : keyShares) {
                    u16(entries, group);
                    if (!retryRequest) {
                        u16(entries, 4);
                        entries.writeBytes(new byte[] { 1, 2, 3, 4 }); // key exchange bytes, not read
                    }
                }
                ByteArrayOutputStream data = new ByteArrayOutputStream();
                if (client) {
                    u16(data, entries.size());
                }
                data.writeBytes(entries.toByteArray());
                extension(ext, 51, data.toByteArray());
            }
            ByteArrayOutputStream body = new ByteArrayOutputStream();
            body.writeBytes(new byte[] { 3, 3 }); // legacy version
            body.writeBytes(retryRequest ? HELLO_RETRY_REQUEST : new byte[32]); // random
            body.write(0); // session id length
            if (client) {
                body.writeBytes(u16List(cipherSuites));
                body.writeBytes(new byte[] { 1, 0 }); // one compression method
            } else {
                u16(body, cipherSuites[0]);
                body.write(0); // compression method
            }
            if (ext.size() > 0 || client) {
                u16(body, ext.size());
                body.writeBytes(ext.toByteArray());
            }
            ByteArrayOutputStream hello = new ByteArrayOutputStream();
            hello.write(client ? 1 : 2); // handshake type
            hello.write(0);
            u16(hello, body.size());
            hello.writeBytes(body.toByteArray());
            return tlsRecord(0x16, hello.toByteArray());
        }

        private static void extension(ByteArrayOutputStream ext, int type, byte[] data) {
            u16(ext, type);
            u16(ext, data.length);
            ext.writeBytes(data);
        }

        // A list of u16 values with its u16 length prefix
        private static byte[] u16List(int[] values) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            u16(out, values.length * 2);
            for (int v : values) {
                u16(out, v);
            }
            return out.toByteArray();
        }
    }

    public static byte[] tlsRecord(int contentType, byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(contentType);
        out.writeBytes(new byte[] { 3, 3 });
        u16(out, body.length);
        out.writeBytes(body);
        return out.toByteArray();
    }

    private static void u16(ByteArrayOutputStream out, int v) {
        out.write(v >> 8);
        out.write(v);
    }

    public static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }
}
