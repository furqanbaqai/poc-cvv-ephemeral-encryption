package com.openfintechlab.jwe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openfintechlab.jwe.model.RevealRequest;
import com.openfintechlab.jwe.util.JsonUtil;
import com.openfintechlab.jwe.util.KeyGeneratorUtil;
import com.sib.cvv.Main;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.Test;

class JWEDecryptTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void decryptReturnsOriginalPayloadJson() throws Exception {
        RevealRequest revealRequest = Reveal.buildRevealRequest(true, "4012 8888 8888 1881", "mobile");
        String jwe = encryptForRevealRequest(revealRequest);

        String payloadJson = new JWEDecrypt(jwe, revealRequest.getEphemeralPublicKey().getPrivateKey()).decrypt();
        JsonNode payload = OBJECT_MAPPER.readTree(payloadJson);

        assertExpectedPayload(payload, "4012 8888 8888 1881");
    }

    @Test
    void mainJweDecryptCommandPrintsPayloadToStdout() throws Exception {
        RevealRequest revealRequest = Reveal.buildRevealRequest(true, "card_12345", "mobile");
        String jwe = encryptForRevealRequest(revealRequest);

        CliResult result = runMain("jwe-decrypt", jwe, revealRequest.getEphemeralPublicKey().getPrivateKey());
        JsonNode payload = OBJECT_MAPPER.readTree(result.stdout().trim());

        assertEquals("", result.stderr());
        assertExpectedPayload(payload, "card_12345");
    }

    @Test
    void mainJweDecryptCommandAcceptsPrivateKeyJsonArgument() throws Exception {
        RevealRequest revealRequest = Reveal.buildRevealRequest(true, "4012 8888 8888 1881", "mobile");
        String jwe = encryptForRevealRequest(revealRequest);
        String privateKeyJson = "{\"privateKey\":\""
                + JsonUtil.escapeJson(revealRequest.getEphemeralPublicKey().getPrivateKey())
                + "\"}";

        CliResult result = runMain("jwe-decrypt", jwe, privateKeyJson);
        JsonNode payload = OBJECT_MAPPER.readTree(result.stdout().trim());

        assertEquals("", result.stderr());
        assertExpectedPayload(payload, "4012 8888 8888 1881");
    }

    @Test
    void decryptRejectsTamperedToken() throws Exception {
        RevealRequest revealRequest = Reveal.buildRevealRequest(true, "4012 8888 8888 1881", "mobile");
        String jwe = encryptForRevealRequest(revealRequest);
        String tamperedJwe = tamperAuthenticationTag(jwe);

        GeneralSecurityException exception = assertThrows(GeneralSecurityException.class,
                () -> new JWEDecrypt(tamperedJwe, revealRequest.getEphemeralPublicKey().getPrivateKey()).decrypt());

        assertEquals("Authentication tag verification failed - token may be tampered", exception.getMessage());
    }

    private static String tamperAuthenticationTag(String jwe) {
        String[] parts = jwe.split("\\.", -1);
        byte[] tag = KeyGeneratorUtil.base64urlDecode(parts[4]);
        tag[0] = (byte) (tag[0] ^ 0x01);
        parts[4] = KeyGeneratorUtil.base64urlEncode(tag);
        return String.join(".", parts);
    }

    private static String encryptForRevealRequest(RevealRequest revealRequest) throws Exception {
        return new JWEEncrypt(
                revealRequest.getCardRef(),
                revealRequest.getCardRef(),
                "12",
                "29",
                "123",
                1775901000L,
                1775901030L,
                "reveal-8f3a1c",
                revealRequest.getEphemeralPublicKey().getKty(),
                revealRequest.getEphemeralPublicKey().getUse(),
                revealRequest.getEphemeralPublicKey().getAlg(),
                revealRequest.getEphemeralPublicKey().getN(),
                revealRequest.getEphemeralPublicKey().getE())
                .encrypt();
    }

    private static void assertExpectedPayload(JsonNode payload, String expectedCardRef) {
        assertEquals(expectedCardRef, payload.get("cardRef").asText());
        assertEquals(expectedCardRef, payload.get("pan").asText());
        assertEquals("12", payload.get("expiryMonth").asText());
        assertEquals("29", payload.get("expiryYear").asText());
        assertEquals("123", payload.get("cvv").asText());
        assertEquals(1775901000L, payload.get("iat").asLong());
        assertEquals(1775901030L, payload.get("exp").asLong());
        assertEquals("reveal-8f3a1c", payload.get("jti").asText());
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
