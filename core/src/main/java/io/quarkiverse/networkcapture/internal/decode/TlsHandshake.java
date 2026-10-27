package io.quarkiverse.networkcapture.internal.decode;

import java.util.ArrayList;
import java.util.List;

/**
 * What a TLS handshake packet reveals: the Client Hello or Server Hello it starts with, and the verdict on the key
 * exchange. Later packets of the same connection carry the verdict alone. All names are the IANA registry names,
 * code points without a known name are printed as hex.
 *
 * @param clientHello the parsed Client Hello when the packet starts with one, otherwise null
 * @param serverHello the parsed Server Hello when the packet starts with one, otherwise null
 * @param quantumSafety the verdict on the connection's key exchange, null until the Server Hello decides it
 */
public record TlsHandshake(ClientHello clientHello, ServerHello serverHello, QuantumSafety quantumSafety) {

    /**
     * The Client Hello: what the client offers.
     *
     * @param serverName the Server Name Indication, or null
     * @param protocols the ALPN protocols offered, empty when the extension is absent
     * @param versions the TLS versions offered, highest first as the client lists them
     * @param cipherSuites the cipher suites offered, in preference order
     * @param groups the key exchange groups the client supports (the supported_groups extension)
     * @param keyShares the groups the client sent key shares for, which the server can pick without a round trip
     * @param signatureAlgorithms the signature algorithms the client accepts
     * @param truncated whether the hello was cut by the segment, so lists may be incomplete
     */
    public record ClientHello(String serverName, List<String> protocols, List<String> versions, List<String> cipherSuites,
            List<String> groups, List<String> keyShares, List<String> signatureAlgorithms, boolean truncated) {

        // Whether the client said it will speak HTTP; false when it said nothing
        boolean http() {
            return protocols.contains("h2") || protocols.contains("http/1.1");
        }

        /**
         * The post-quantum groups the client offered, in the order it listed them; empty when it offered none.
         */
        public List<String> postQuantumGroups() {
            List<String> result = new ArrayList<>();
            for (String group : groups.isEmpty() ? keyShares : groups) {
                if (TlsNames.postQuantum(group) && !result.contains(group)) {
                    result.add(group);
                }
            }
            return result;
        }

        public boolean offersPostQuantum() {
            return !postQuantumGroups().isEmpty();
        }
    }

    /**
     * The Server Hello: what the server chose. A TLS 1.3 Hello Retry Request has the same shape, and names in its
     * key share the group it wants the client to send a share for.
     *
     * @param version the negotiated version; null when the hello was cut before the extensions, since TLS 1.3 is
     *        only announced there
     * @param cipherSuite the chosen cipher suite, or null when cut
     * @param keyShareGroup the group of the server's key share, which is the key exchange of the connection; null
     *        in TLS 1.2, in a resumed session without key share, or when cut
     * @param retryRequest whether this is a Hello Retry Request rather than the final Server Hello
     * @param truncated whether the hello was cut by the segment
     */
    public record ServerHello(String version, String cipherSuite, String keyShareGroup, boolean retryRequest,
            boolean truncated) {
    }

    /**
     * Whether the connection's key exchange resists a quantum computer: it does when the server chose a post-quantum
     * (ML-KEM, pure or hybrid) key share group in TLS 1.3. Authentication is not considered, certificates are
     * classical everywhere.
     *
     * @param reason one sentence, e.g. {@code not quantum safe: the client offered X25519MLKEM768 but the server
     *        chose x25519}, meant to be shown as is
     */
    public record QuantumSafety(boolean safe, String reason) {

        static final QuantumSafety SAFE = new QuantumSafety(true, "quantum-safe key exchange");

        /**
         * The verdict a Server Hello gives, or null when it gives none: a Hello Retry Request, a cut hello, or a
         * TLS 1.3 hello without key share. The Client Hello, when known, makes the reason say whose fault it is.
         */
        static QuantumSafety of(ServerHello server, ClientHello client) {
            if (server.truncated() || server.retryRequest()) {
                return null;
            }
            if (!"TLS 1.3".equals(server.version())) {
                return new QuantumSafety(false, "not quantum safe: " + server.version() + " has no post-quantum key exchange");
            }
            if (server.keyShareGroup() == null) {
                return null;
            }
            if (TlsNames.postQuantum(server.keyShareGroup())) {
                return SAFE;
            }
            String chose = "the server chose " + server.keyShareGroup();
            if (client == null) {
                return new QuantumSafety(false, "not quantum safe: " + chose);
            }
            List<String> offered = client.postQuantumGroups();
            return new QuantumSafety(false, offered.isEmpty()
                    ? "not quantum safe: the client offered no post-quantum group and " + chose
                    : "not quantum safe: the client offered " + String.join(", ", offered) + " but " + chose);
        }
    }
}
