package io.quarkiverse.networkcapture.deployment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.devui.tests.DevUIJsonRPCTest;
import io.quarkus.test.QuarkusDevModeTest;
import tools.jackson.databind.JsonNode;

/**
 * Exercises the Dev UI backend through the same JSON-RPC channel the page uses. Capturing itself needs privileges
 * the test cannot assume, so starting is only checked up to the permission decision.
 */
public class NetworkCaptureDevUiTest extends DevUIJsonRPCTest {

    @RegisterExtension
    static final QuarkusDevModeTest test = new QuarkusDevModeTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class)
                    // a random port, so the test does not collide with an application running in dev mode
                    .add(new StringAsset("quarkus.http.port=0\n"), "application.properties"));

    public NetworkCaptureDevUiTest() {
        super("quarkus-network-capture");
    }

    @Test
    public void packetsBeforeAnyCapture() throws Exception {
        JsonNode batch = executeJsonRPCMethod("packets", Map.of("after", 0, "onlyHttp", true, "max", 10));
        assertFalse(batch.get("running").asBoolean());
        assertTrue(batch.get("packets").isEmpty());
    }

    @Test
    public void settings() throws Exception {
        JsonNode settings = executeJsonRPCMethod("settings");
        assertNotNull(settings.get("platform"));
        assertTrue(settings.get("directory").asString().endsWith("pcap"));
        assertNotNull(settings.get("elevation"));
        assertTrue(settings.get("applicationOnly").asBoolean());
        assertTrue(settings.get("excludeDevUi").asBoolean());
        assertTrue(settings.get("interfaces").isEmpty());
    }

    @Test
    public void interfacesIncludeLoopback() throws Exception {
        JsonNode interfaces = executeJsonRPCMethod("interfaces");
        JsonNode loopback = null;
        for (JsonNode i : interfaces) {
            if (i.get("loopback").asBoolean()) {
                loopback = i;
            }
        }
        assertNotNull(loopback, interfaces.toString());
        assertTrue(loopback.get("up").asBoolean());
        assertFalse(loopback.get("addresses").isEmpty(), loopback.toString());
    }

    @Test
    public void unknownInterfaceIsRefused() throws Exception {
        JsonNode result = executeJsonRPCMethod("startFromDevUi", Map.of("elevate", false, "applicationOnly", true,
                "excludeDevUi", true, "interfaces", List.of("no-such-interface0")));
        assertEquals("error", result.get("status").asString(), result.toString());
        assertTrue(result.get("message").asString().contains("no-such-interface0"), result.toString());
        assertFalse(executeJsonRPCMethod("status").get("running").asBoolean());
    }

    @Test
    public void statusAndStartWithoutPrivileges() throws Exception {
        JsonNode status = executeJsonRPCMethod("status");
        assertFalse(status.get("running").asBoolean());
        assertEquals("", executeJsonRPCMethod("statusLabel").asString());

        JsonNode result = executeJsonRPCMethod("startFromDevUi", Map.of("elevate", false, "applicationOnly", true,
                "excludeDevUi", true, "interfaces", List.of()));
        String outcome = result.get("status").asString();
        assertTrue(outcome.equals("permission-required") || outcome.equals("started"), result.toString());
        if (outcome.equals("started")) {
            assertTrue(executeJsonRPCMethod("status").get("running").asBoolean());
            assertFalse(executeJsonRPCMethod("stop").get("running").asBoolean());
        } else {
            assertNotNull(result.get("setupHint"));
            assertNotNull(result.get("elevation"));
        }
        assertTrue(executeJsonRPCMethod("listFiles").isArray());
    }
}
