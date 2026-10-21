package io.quarkiverse.networkcapture.runtime.dev;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.InetAddress;

import org.junit.jupiter.api.Test;

class AddressTextTest {

    @Test
    void ipv4IsUnchanged() throws Exception {
        assertEquals("192.0.2.1", NetworkCaptureJsonRpcService.text(InetAddress.getByName("192.0.2.1")));
    }

    @Test
    void ipv6IsShortened() throws Exception {
        assertEquals("::1", NetworkCaptureJsonRpcService.text(InetAddress.getByName("::1")));
        assertEquals("::", NetworkCaptureJsonRpcService.text(InetAddress.getByName("::")));
        assertEquals("fe80::1:2", NetworkCaptureJsonRpcService.text(InetAddress.getByName("fe80:0:0:0:0:0:1:2")));
        assertEquals("2001:db8::1", NetworkCaptureJsonRpcService.text(InetAddress.getByName("2001:db8:0:0:0:0:0:1")));
    }

    @Test
    void longestRunOfZerosIsShortenedAndTheFirstOnATie() throws Exception {
        assertEquals("2001:0:0:1::1", NetworkCaptureJsonRpcService.text(InetAddress.getByName("2001:0:0:1:0:0:0:1")));
        assertEquals("2001:db8::1:0:0:1", NetworkCaptureJsonRpcService.text(InetAddress.getByName("2001:db8:0:0:1:0:0:1")));
    }

    @Test
    void singleZeroGroupIsKept() throws Exception {
        assertEquals("2001:db8:0:1:1:1:1:1", NetworkCaptureJsonRpcService.text(InetAddress.getByName("2001:db8:0:1:1:1:1:1")));
    }
}
