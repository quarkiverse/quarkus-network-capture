package io.quarkiverse.networkcapture.internal.decode;

import java.util.Map;
import java.util.Set;

/**
 * Names for the code points of a TLS handshake, from the IANA TLS parameters registry
 * (<a href="https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml">tls-parameters</a>). Only the
 * values current implementations send are listed; anything else is shown as hex, so the lists stay honest about
 * what was on the wire.
 */
final class TlsNames {

    private TlsNames() {
    }

    private static final Map<Integer, String> VERSIONS = Map.of(
            0x0300, "SSL 3.0",
            0x0301, "TLS 1.0",
            0x0302, "TLS 1.1",
            0x0303, "TLS 1.2",
            0x0304, "TLS 1.3");

    // Supported groups (RFC 8446 section 4.2.7, RFC 7919, draft-ietf-tls-ecdhe-mlkem, draft-ietf-tls-mlkem)
    private static final Map<Integer, String> GROUPS = Map.ofEntries(
            Map.entry(0x0017, "secp256r1"),
            Map.entry(0x0018, "secp384r1"),
            Map.entry(0x0019, "secp521r1"),
            Map.entry(0x001D, "x25519"),
            Map.entry(0x001E, "x448"),
            Map.entry(0x0100, "ffdhe2048"),
            Map.entry(0x0101, "ffdhe3072"),
            Map.entry(0x0102, "ffdhe4096"),
            Map.entry(0x0103, "ffdhe6144"),
            Map.entry(0x0104, "ffdhe8192"),
            Map.entry(0x0200, "MLKEM512"),
            Map.entry(0x0201, "MLKEM768"),
            Map.entry(0x0202, "MLKEM1024"),
            Map.entry(0x11EB, "SecP256r1MLKEM768"),
            Map.entry(0x11EC, "X25519MLKEM768"),
            Map.entry(0x11ED, "SecP384r1MLKEM1024"));

    private static final Set<String> POST_QUANTUM = Set.of("MLKEM512", "MLKEM768", "MLKEM1024", "SecP256r1MLKEM768",
            "X25519MLKEM768", "SecP384r1MLKEM1024");

    // The TLS 1.3 suites and the TLS 1.2 suites with forward secrecy and an AEAD cipher
    private static final Map<Integer, String> CIPHER_SUITES = Map.ofEntries(
            Map.entry(0x1301, "TLS_AES_128_GCM_SHA256"),
            Map.entry(0x1302, "TLS_AES_256_GCM_SHA384"),
            Map.entry(0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
            Map.entry(0x1304, "TLS_AES_128_CCM_SHA256"),
            Map.entry(0x1305, "TLS_AES_128_CCM_8_SHA256"),
            Map.entry(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
            Map.entry(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
            Map.entry(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
            Map.entry(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
            Map.entry(0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
            Map.entry(0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
            Map.entry(0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
            Map.entry(0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
            Map.entry(0x00FF, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"));

    // Signature schemes (RFC 8446 section 4.2.3, draft-ietf-tls-mldsa)
    private static final Map<Integer, String> SIGNATURE_SCHEMES = Map.ofEntries(
            Map.entry(0x0201, "rsa_pkcs1_sha1"),
            Map.entry(0x0203, "ecdsa_sha1"),
            Map.entry(0x0401, "rsa_pkcs1_sha256"),
            Map.entry(0x0403, "ecdsa_secp256r1_sha256"),
            Map.entry(0x0501, "rsa_pkcs1_sha384"),
            Map.entry(0x0503, "ecdsa_secp384r1_sha384"),
            Map.entry(0x0601, "rsa_pkcs1_sha512"),
            Map.entry(0x0603, "ecdsa_secp521r1_sha512"),
            Map.entry(0x0804, "rsa_pss_rsae_sha256"),
            Map.entry(0x0805, "rsa_pss_rsae_sha384"),
            Map.entry(0x0806, "rsa_pss_rsae_sha512"),
            Map.entry(0x0807, "ed25519"),
            Map.entry(0x0808, "ed448"),
            Map.entry(0x0809, "rsa_pss_pss_sha256"),
            Map.entry(0x080A, "rsa_pss_pss_sha384"),
            Map.entry(0x080B, "rsa_pss_pss_sha512"),
            Map.entry(0x0904, "mldsa44"),
            Map.entry(0x0905, "mldsa65"),
            Map.entry(0x0906, "mldsa87"));

    static String version(int code) {
        return name(VERSIONS, code);
    }

    static String group(int code) {
        return name(GROUPS, code);
    }

    static String cipherSuite(int code) {
        return name(CIPHER_SUITES, code);
    }

    static String signatureScheme(int code) {
        return name(SIGNATURE_SCHEMES, code);
    }

    // Whether a group name, as returned by group(), is an ML-KEM key exchange, pure or hybrid
    static boolean postQuantum(String group) {
        return POST_QUANTUM.contains(group);
    }

    private static String name(Map<Integer, String> names, int code) {
        String name = names.get(code);
        return name != null ? name : String.format("0x%04x", code);
    }
}
