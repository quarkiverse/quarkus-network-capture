package io.quarkiverse.networkcapture.deployment;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusDevModeTest;
import io.quarkus.value.registry.ValueRegistry;
import io.quarkus.value.registry.ValueRegistry.RuntimeKey;

/**
 * The capture tools an AI agent needs are available over the Dev MCP endpoint without the user enabling them.
 */
public class NetworkCaptureDevMcpTest {

    @RegisterExtension
    static final QuarkusDevModeTest test = new QuarkusDevModeTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class)
                    .add(new StringAsset("quarkus.http.port=0\nquarkus.dev-mcp.enabled=true\n"), "application.properties"));

    private URI endpoint;

    @BeforeEach
    void endpoint(ValueRegistry registry) {
        URI base = registry.get(RuntimeKey.<URI> key("quarkus.http.local-base-uri"));
        endpoint = URI.create(base.toString().replaceAll("/$", "") + "/q/dev-mcp");
    }

    @Test
    void captureToolsAreEnabledByDefault() throws Exception {
        String tools = call("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}");
        for (String tool : new String[] { "settings", "interfaces", "start", "stop", "status", "packets", "listFiles" }) {
            assertTrue(tools.contains("\"quarkus-network-capture_" + tool + "\""), tool + " missing from " + tools);
        }
        assertFalse(tools.contains("\"quarkus-network-capture_deleteFile\""), "deleting files must be opt-in");
    }

    @Test
    void agentCannotRunThePrivilegedHelper() throws Exception {
        String tools = call("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}");
        assertFalse(tools.contains("startFromDevUi"), "the page's start must not be a tool: " + tools);
        assertFalse(tools.contains("\"elevate\""), "no tool may take an elevate argument: " + tools);
    }

    @Test
    void statusToolCanBeCalled() throws Exception {
        String status = call("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"quarkus-network-capture_status\",\"arguments\":{}}}");
        // MCP returns the tool's result as JSON text inside a content block
        assertTrue(status.contains("\\\"running\\\" : false"), status);
        assertTrue(status.contains("\"isError\" : false"), status);
    }

    @Test
    void startToolNeverPrompts() throws Exception {
        // Without the capture privilege the tool must report it rather than run the helper, which would prompt or,
        // with cached sudo credentials, run as root unasked; with the privilege it simply starts.
        String result = call("{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{"
                + "\"name\":\"quarkus-network-capture_start\",\"arguments\":{\"applicationOnly\":true,\"excludeDevUi\":true}}}");
        assertTrue(result.contains("permission-required") || result.contains("\\\"started\\\""), result);
        call("{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\","
                + "\"params\":{\"name\":\"quarkus-network-capture_stop\",\"arguments\":{}}}");
    }

    private String call(String body) throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(endpoint)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        assertTrue(response.statusCode() < 300, response.statusCode() + " " + response.body());
        return response.body();
    }
}
