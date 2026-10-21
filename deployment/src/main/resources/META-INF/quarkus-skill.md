### What it does

- Captures the application's own network traffic in dev mode to pcapng files that open in Wireshark: everything the
  process sends and receives, including JDBC, HTTP clients and messaging, not only what passes through Vert.x.
- Pure Java on JDK 25 (Foreign Function & Memory API); no libpcap, no native library; Linux and macOS only.
- Production builds are unaffected: the extension contributes no code outside dev mode.

### Using it

- Add `io.quarkiverse.networkcapture:quarkus-network-capture` and run dev mode. The **Network Capture** card in the Dev UI has the **Capture** page;
  files land in `target/pcap/` (`quarkus.network-capture.directory`).
- By default a capture covers every interface that is up and keeps the application's packets wherever they travel
  (loopback, a container bridge, the LAN). The page has an interface picker, and
  `quarkus.network-capture.interfaces` sets the default.
- Capturing needs a privilege the application normally lacks. The page offers to start a short-lived helper process
  through `sudo`, `pkexec` or the macOS administrator dialog; it asks for the password once and exits. The
  application itself never runs with elevated rights. `quarkus.network-capture.elevation` picks the mechanism; the page shows
  the one-time command (such as `setcap cap_net_raw+ep` on the JDK) that removes the prompt for good.
- A capture survives live reloads, is finished cleanly when dev mode exits, and the file can be opened in Wireshark
  while it is still being written.

### Dev MCP tools (prefix `quarkus-network-capture_`)

- `start(applicationOnly, excludeDevUi, interfaces)` → exercise the application → `packets(after, onlyHttp, max)` →
  `stop()`. Packets carrying HTTP/1.x come with method, URL, status, headers and decoded body, and each response
  links to its request, so a capture answers "what exactly did the application send and receive".
- `start` never runs the privileged helper. A result of `permission-required` means the application lacks the
  capture privilege: ask the user to press **Start capture** on the Network Capture page of the Dev UI (which can
  prompt for their password), or to run the one-time command in `setupHint`, then call `status` or `start` again.
  Do NOT try to obtain the privilege yourself, for instance by running `sudo`.
- `packets` replaces credentials with `[redacted]`: the values of credential headers (`Authorization`, `Cookie`,
  `Set-Cookie`, ...), keeping the authorization scheme and the cookie names, and the values of credential query
  parameters (`access_token`, `code`, `api_key`, ...) in URLs. Do NOT ask the user to turn this off to debug
  authentication; the scheme, the cookie names and the response status are usually enough.
- `packets` pages with `after`: pass the last packet number received. It never returns the Dev UI's or Dev MCP's
  own traffic.
- `interfaces` lists the machine's interfaces with their addresses. Pass names to `start` only when you know which
  interface carries the traffic; an empty list (the default) captures on all of them, which is almost always right.
- `status`, `settings`, `interfaces` and `listFiles` are read-only. `deleteFile` is disabled until the user enables it.

### Common pitfalls

- Do NOT look for packets of a request made in the last second right away: packets are held briefly so the
  application-only filter can learn about new sockets; `packets` returns them a moment later.
- Do NOT expect HTTP/2 or TLS bodies to be decoded; HTTP/2 shows frame types, TLS shows only the record types plus
  the server name and ALPN from the Client Hello. `HTTPS` means TLS whose Client Hello offered HTTP, or TLS on port
  443 or 8443 without ALPN; other TLS shows as `TLS`.
- Do NOT run the application itself as root to avoid the prompt; grant the capability to the JDK instead.
