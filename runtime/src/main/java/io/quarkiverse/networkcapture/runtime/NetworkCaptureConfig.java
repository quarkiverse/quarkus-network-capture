package io.quarkiverse.networkcapture.runtime;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import io.quarkus.runtime.annotations.ConfigPhase;
import io.quarkus.runtime.annotations.ConfigRoot;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

@ConfigMapping(prefix = "quarkus.network-capture")
@ConfigRoot(phase = ConfigPhase.RUN_TIME)
public interface NetworkCaptureConfig {

    /**
     * Directory where capture files are written. Relative paths are resolved against the working directory.
     */
    @WithDefault("target/pcap")
    String directory();

    /**
     * Maximum number of bytes captured per packet.
     */
    @WithDefault("262144")
    int snapLen();

    /**
     * Default for the "only this application's traffic" option: keep only TCP and UDP packets whose source or
     * destination port belongs to a socket of this process.
     */
    @WithDefault("true")
    boolean applicationOnly();

    /**
     * Default for the "exclude Dev UI traffic" option: leave the Dev UI's own traffic out of the capture file, that
     * is its websocket connections and its HTTP requests and responses. Application requests on a connection the
     * browser also used for the Dev UI are kept.
     */
    @WithDefault("true")
    boolean excludeDevUi();

    /**
     * Whether to put captured interfaces into promiscuous mode.
     */
    @WithDefault("false")
    boolean promiscuous();

    /**
     * How the helper process that opens the capture acquires root when the application itself lacks the
     * privilege: {@code auto}, {@code sudo}, {@code pkexec} (Linux desktop prompt) or {@code osascript}
     * (macOS prompt). {@code auto} picks {@code osascript} on macOS and {@code pkexec} or {@code sudo} on Linux.
     */
    @WithDefault("auto")
    String elevation();

    /**
     * How long to wait for the privileged helper, which includes the time the user takes to enter a password.
     */
    @WithDefault("2m")
    Duration helperTimeout();

    /**
     * The interfaces a capture opens by default, by OS name, e.g. {@code lo} or {@code eth0}. When not set, a capture
     * opens every interface that is up. The Dev UI page preselects these and lets you pick others for each capture.
     */
    Optional<List<String>> interfaces();

    /**
     * HTTP headers whose values the {@code packets} Dev MCP tool replaces with {@code [redacted]}, so that credentials
     * the application sends or receives do not end up in an AI agent's conversation. Names are case-insensitive. The
     * scheme of an {@code Authorization} or {@code Proxy-Authorization} value is kept, and so are the names and
     * attributes of cookies. {@code none} turns header redaction off. The Dev UI page and the capture files are not
     * affected.
     */
    @WithDefault("authorization,proxy-authorization,cookie,set-cookie,x-api-key,x-auth-token")
    List<String> redactHeaders();

    /**
     * Query parameters whose values the {@code packets} Dev MCP tool replaces with {@code [redacted]}, wherever a URL
     * appears: the request line, the packet summary, and headers such as {@code Location} and {@code Referer}. The same
     * names are redacted in a URL's fragment, where the OAuth implicit flow returns the access token. Names
     * are case-insensitive. {@code none} turns query parameter redaction off.
     */
    @WithDefault("access_token,refresh_token,id_token,token,code,api_key,apikey,key,password,secret,client_secret,signature,sig")
    List<String> redactQueryParameters();
}
