package io.quarkiverse.networkcapture.runtime.dev;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import io.quarkiverse.networkcapture.CaptureInterface;
import io.quarkiverse.networkcapture.CapturedPacket;
import io.quarkiverse.networkcapture.LinkType;
import io.quarkiverse.networkcapture.Packet;

class PacketRowsTest {

    // A TLS 1.3 Server Hello choosing TLS_AES_128_GCM_SHA256 with an X25519MLKEM768 key share
    private static final byte[] SERVER_HELLO = {
            0x16, 0x03, 0x03, 0x00, 0x3a, // record: handshake, 58 bytes
            0x02, 0x00, 0x00, 0x36, // server hello, 54 bytes
            0x03, 0x03, // legacy version
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // random
            0x00, // session id
            0x13, 0x01, // cipher suite
            0x00, // compression
            0x00, 0x0e, // extensions, 14 bytes
            0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, // supported_versions: TLS 1.3
            0x00, 0x33, 0x00, 0x04, 0x11, (byte) 0xec, 0x00, 0x00 // key_share: X25519MLKEM768, empty key
    };

    @Test
    void tlsHandshakeDetailsReachTheRow() {
        PacketRows rows = new PacketRows(Instant.EPOCH);
        rows.onPacket(captured(segment(8443, 50000, SERVER_HELLO)));
        rows.onPacket(captured(segment(50000, 8443, new byte[0])));
        List<Messages.PacketRow> result = rows.since(0, false, 10, true).packets();
        assertEquals(2, result.size());

        Messages.TlsDetails tls = result.get(0).tls();
        assertNull(tls.clientHello());
        assertEquals("TLS 1.3", tls.serverHello().version());
        assertEquals("TLS_AES_128_GCM_SHA256", tls.serverHello().cipherSuite());
        assertEquals("X25519MLKEM768", tls.serverHello().keyShareGroup());
        assertFalse(tls.serverHello().retryRequest());
        assertTrue(tls.quantumSafety().safe());
        assertEquals("quantum-safe key exchange", tls.quantumSafety().reason());
        assertTrue(result.get(0).info().endsWith("; quantum-safe key exchange"), result.get(0).info());

        assertNull(result.get(1).tls());
    }

    private static CapturedPacket captured(byte[] data) {
        return CapturedPacket.builder()
                .networkInterface(CaptureInterface.builder().name("lo").index(1).loopback(true).build())
                .linkType(LinkType.ETHERNET)
                .packet(Packet.builder().timestampNanos(0).data(data).build())
                .build();
    }

    // An Ethernet/IPv4/TCP segment on loopback with the given payload
    private static byte[] segment(int sourcePort, int destinationPort, byte[] payload) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[12]);
        out.write(0x08);
        out.write(0x00);
        byte[] ip = new byte[20];
        ip[0] = 0x45;
        int total = 40 + payload.length;
        ip[2] = (byte) (total >> 8);
        ip[3] = (byte) total;
        ip[9] = 6;
        ip[12] = 127;
        ip[15] = 1;
        ip[16] = 127;
        ip[19] = 1;
        out.writeBytes(ip);
        byte[] tcp = new byte[20];
        tcp[0] = (byte) (sourcePort >> 8);
        tcp[1] = (byte) sourcePort;
        tcp[2] = (byte) (destinationPort >> 8);
        tcp[3] = (byte) destinationPort;
        tcp[12] = 0x50;
        tcp[13] = (byte) (payload.length == 0 ? 0x10 : 0x18);
        out.writeBytes(tcp);
        out.writeBytes(payload);
        return out.toByteArray();
    }
}
