package com.oashield.openapi.integration;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

import com.oashield.openapi.integration.util.ModSecurityContainerManager;
import com.oashield.openapi.integration.util.RuleGenerationUtil;

/** Run with -DrunModSecurityIntegration=true and Docker available. */
@EnabledIfSystemProperty(named = "runModSecurityIntegration", matches = "true")
class ArraySelectorIntegrationTest {
    @TempDir
    Path output;

    @Test
    void generatedArraySelectorsLoadAndValidateElements() throws Exception {
        RuleGenerationUtil.generateRules("src/test/resources/specs/array-selector-regression.yaml",
                output.toString(), true, "modsecurity3");
        ModSecurityContainerManager waf = new ModSecurityContainerManager(output.resolve("rules").toString());
        try {
            String base = waf.start();
            HttpClient client = HttpClient.newHttpClient();
            assertEquals(200, post(client, base, "{\"names\":[\"one\",\"two\"]}"));
            assertEquals(403, post(client, base, "{\"names\":[\"one\",\"INVALID\"]}"));
            assertEquals(403, post(client, base, "{\"names\":[\"one\",\"two\",\"three\",\"four\"]}"));
        } finally {
            waf.stop();
        }
    }

    private int post(HttpClient client, String base, String body) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(base + "/items"))
                .timeout(Duration.ofSeconds(15))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
    }
}
