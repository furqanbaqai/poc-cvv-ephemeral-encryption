package com.openfintechlab.jwe;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openfintechlab.jwe.model.RevealRequest;
import com.openfintechlab.jwe.util.JsonUtil;
import com.sib.cvv.Main;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class RevealTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void buildRevealRequestReturnsPublicKeyOnlyByDefault() throws Exception {
        RevealRequest request = Reveal.buildRevealRequest(false);

        assertRequestBasics(request);
        assertNotNull(request.getEphemeralPublicKey());
        assertEquals("RSA", request.getEphemeralPublicKey().getKty());
        assertEquals("enc", request.getEphemeralPublicKey().getUse());
        assertEquals("RSA-OAEP-256", request.getEphemeralPublicKey().getAlg());
        assertTrue(request.getEphemeralPublicKey().getN().matches("[A-Za-z0-9_-]+"));
        assertEquals("AQAB", request.getEphemeralPublicKey().getE());
        assertEquals(null, request.getEphemeralPublicKey().getPrivateKey());

        String json = JsonUtil.toMinifiedJson(request);
        JsonNode root = OBJECT_MAPPER.readTree(json);

        assertFalse(root.get("ephemeralPublicKey").has("privateKey"));
    }

    @Test
    void buildRevealRequestIncludesPemPrivateKeyOnlyInDebugMode() throws Exception {
        RevealRequest request = Reveal.buildRevealRequest(true);
        String privateKey = request.getEphemeralPublicKey().getPrivateKey();

        assertRequestBasics(request);
        assertNotNull(privateKey);
        assertTrue(privateKey.startsWith("-----BEGIN PRIVATE KEY-----\n"));
        assertTrue(privateKey.endsWith("\n-----END PRIVATE KEY-----"));
        assertDoesNotThrow(() -> KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(decodePem(privateKey))));

        String json = JsonUtil.toMinifiedJson(request);
        JsonNode root = OBJECT_MAPPER.readTree(json);

        assertTrue(root.get("ephemeralPublicKey").has("privateKey"));
        assertTrue(root.get("ephemeralPublicKey").get("privateKey").asText().contains("BEGIN PRIVATE KEY"));
    }

    @Test
    void buildRevealRequestUsesProvidedCardRefAndChannelWithoutPrivateKey() throws Exception {
        RevealRequest request = Reveal.buildRevealRequest(false, "card_12345", "web");
        String json = JsonUtil.toMinifiedJson(request);
        JsonNode root = OBJECT_MAPPER.readTree(json);

        assertRequestBasics(request, "card_12345", "web");
        assertEquals("card_12345", root.get("cardRef").asText());
        assertEquals("web", root.get("channel").asText());
        assertEquals("RSA", root.get("ephemeralPublicKey").get("kty").asText());
        assertEquals("enc", root.get("ephemeralPublicKey").get("use").asText());
        assertEquals("RSA-OAEP-256", root.get("ephemeralPublicKey").get("alg").asText());
        assertTrue(root.get("ephemeralPublicKey").get("n").asText().matches("[A-Za-z0-9_-]+"));
        assertEquals("AQAB", root.get("ephemeralPublicKey").get("e").asText());
        assertFalse(root.get("ephemeralPublicKey").has("privateKey"));
    }

    @Test
    void buildRevealRequestUsesProvidedCardRefAndChannelWithPrivateKeyInDebugMode() throws Exception {
        RevealRequest request = Reveal.buildRevealRequest(true, "card_67890", "atm");
        String privateKey = request.getEphemeralPublicKey().getPrivateKey();
        String json = JsonUtil.toMinifiedJson(request);
        JsonNode root = OBJECT_MAPPER.readTree(json);

        assertRequestBasics(request, "card_67890", "atm");
        assertEquals("card_67890", root.get("cardRef").asText());
        assertEquals("atm", root.get("channel").asText());
        assertNotNull(privateKey);
        assertTrue(privateKey.startsWith("-----BEGIN PRIVATE KEY-----\n"));
        assertTrue(privateKey.endsWith("\n-----END PRIVATE KEY-----"));
        assertTrue(root.get("ephemeralPublicKey").has("privateKey"));
        assertDoesNotThrow(() -> KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(decodePem(privateKey))));
    }

    @Test
    void mainRevealCommandPrintsMinifiedJsonToStdout() throws Exception {
        CliResult result = runMain("reveal");
        JsonNode root = OBJECT_MAPPER.readTree(result.stdout().trim());

        assertEquals("", result.stderr());
        assertEquals("4012 8888 8888 1881", root.get("cardRef").asText());
        assertEquals("mobile", root.get("channel").asText());
        assertTrue(root.get("requestId").asText().matches("[0-9a-f]{32}"));
        assertEquals("RSA", root.get("ephemeralPublicKey").get("kty").asText());
        assertEquals("enc", root.get("ephemeralPublicKey").get("use").asText());
        assertEquals("RSA-OAEP-256", root.get("ephemeralPublicKey").get("alg").asText());
        assertTrue(root.get("ephemeralPublicKey").get("n").asText().matches("[A-Za-z0-9_-]+"));
        assertEquals("AQAB", root.get("ephemeralPublicKey").get("e").asText());
        assertFalse(root.get("ephemeralPublicKey").has("privateKey"));
        assertFalse(result.stdout().contains(System.lineSeparator() + System.lineSeparator()));
    }

    @Test
    void mainRevealDebugCommandPrintsPrivateKeyInJson() throws Exception {
        CliResult result = runMain("reveal", "debug");
        JsonNode root = OBJECT_MAPPER.readTree(result.stdout().trim());
        String privateKey = root.get("ephemeralPublicKey").get("privateKey").asText();

        assertEquals("", result.stderr());
        assertTrue(privateKey.startsWith("-----BEGIN PRIVATE KEY-----\n"));
        assertTrue(privateKey.endsWith("\n-----END PRIVATE KEY-----"));
        assertDoesNotThrow(() -> KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(decodePem(privateKey))));
    }

    @Test
    void generateRequestIdReturnsThirtyTwoLowercaseHexCharacters() {
        assertTrue(Reveal.generateRequestId().matches("[0-9a-f]{32}"));
    }

    private static void assertRequestBasics(RevealRequest request) {
        assertRequestBasics(request, "4012 8888 8888 1881", "mobile");
    }

    private static void assertRequestBasics(RevealRequest request, String expectedCardRef, String expectedChannel) {
        assertNotNull(request);
        assertTrue(request.getRequestId().matches("[0-9a-f]{32}"));
        assertEquals(expectedCardRef, request.getCardRef());
        assertEquals(expectedChannel, request.getChannel());
    }

    private static byte[] decodePem(String pem) {
        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }

    private static CliResult runMain(String... args) {
        PrintStream originalOut = System.out;
        PrintStream originalErr = System.err;
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();

        try {
            System.setOut(new PrintStream(stdout, true, StandardCharsets.UTF_8));
            System.setErr(new PrintStream(stderr, true, StandardCharsets.UTF_8));
            Main.main(args);
            return new CliResult(stdout.toString(StandardCharsets.UTF_8), stderr.toString(StandardCharsets.UTF_8));
        } finally {
            System.setOut(originalOut);
            System.setErr(originalErr);
        }
    }

    private record CliResult(String stdout, String stderr) {
    }
}
