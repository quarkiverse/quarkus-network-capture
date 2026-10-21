package io.quarkiverse.networkcapture.deployment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.devui.tests.DevUIJsonRPCTest;
import io.quarkus.test.QuarkusDevModeTest;
import io.quarkus.value.registry.ValueRegistry;
import io.quarkus.value.registry.ValueRegistry.RuntimeKey;
import tools.jackson.databind.JsonNode;

/**
 * With a default configured, the page's empty selection still means every interface that is up, as the page says,
 * while an agent that leaves the interfaces out gets the default. The default names an interface that does not exist,
 * so which one was used shows in the result without needing the capture privilege.
 */
public class NetworkCaptureInterfacesTest extends DevUIJsonRPCTest {

    @RegisterExtension
    static final QuarkusDevModeTest test = new QuarkusDevModeTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class)
                    .add(new StringAsset("quarkus.http.port=0\nquarkus.dev-mcp.enabled=true\n"
                            + "quarkus.network-capture.interfaces=bogus0\n"), "application.properties"));

    private URI mcp;

    public NetworkCaptureInterfacesTest() {
        super("quarkus-network-capture");
    }

    @BeforeEach
    void mcp(ValueRegistry registry) {
        URI base = registry.get(RuntimeKey.<URI> key("quarkus.http.local-base-uri"));
        mcp = URI.create(base.toString().replaceAll("/$", "") + "/q/dev-mcp");
    }

    @Test
    public void settingsCarryTheDefault() throws Exception {
        JsonNode interfaces = executeJsonRPCMethod("settings").get("interfaces");
        assertEquals(1, interfaces.size(), interfaces.toString());
        assertEquals("bogus0", interfaces.get(0).asString());
    }

    @Test
    public void emptySelectionMeansEveryInterfaceThatIsUp() throws Exception {
        JsonNode result = executeJsonRPCMethod("startFromDevUi", Map.of("elevate", false, "applicationOnly", true,
                "excludeDevUi", true, "interfaces", List.of()));
        String status = result.get("status").asString();
        assertTrue(status.equals("permission-required") || status.equals("started"), result.toString());
        if (status.equals("started")) {
            executeJsonRPCMethod("stop");
        }
    }

    @Test
    public void agentLeavingInterfacesOutGetsTheDefault() throws Exception {
        String result = call("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{"
                + "\"name\":\"quarkus-network-capture_start\",\"arguments\":{\"applicationOnly\":true,"
                + "\"excludeDevUi\":true}}}");
        assertTrue(result.contains("No such network interface: bogus0"), result);
        assertFalse(executeJsonRPCMethod("status").get("running").asBoolean());
    }

    private String call(String body) throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(mcp)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        assertTrue(response.statusCode() < 300, response.statusCode() + " " + response.body());
        return response.body();
    }
}
