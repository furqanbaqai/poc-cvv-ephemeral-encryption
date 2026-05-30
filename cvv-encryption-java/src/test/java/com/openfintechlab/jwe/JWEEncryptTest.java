package com.openfintechlab.jwe;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.openfintechlab.jwe.model.RevealRequest;
import com.openfintechlab.jwe.util.JsonUtil;
import com.openfintechlab.jwe.util.KeyGeneratorUtil;
import com.sib.cvv.Main;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class JWEEncryptTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void encryptReturnsCompactJweWithExpectedHeaderAndPayload() throws Exception {
        RevealRequest revealRequest = Reveal.buildRevealRequest(true, "4012 8888 8888 1881", "mobile");
        JWEEncrypt encryptor = new JWEEncrypt(
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
                revealRequest.getEphemeralPublicKey().getE());

        String jwe = encryptor.encrypt();
        DecryptedJwe decryptedJwe = decryptJwe(jwe, revealRequest.getEphemeralPublicKey().getPrivateKey());

        assertExpectedHeader(decryptedJwe.header());
        assertExpectedPayload(decryptedJwe.payload(), "4012 8888 8888 1881");
    }

    @Test
    void mainJweEncryptCommandPrintsCompactJweToStdout() throws Exception {
        RevealRequest revealRequest = Reveal.buildRevealRequest(true, "card_12345", "mobile");
        String revealJson = JsonUtil.toMinifiedJson(revealRequest);
        CliResult result = runMain("jwe-encrypt", revealJson);
        String jwe = result.stdout().trim();
        DecryptedJwe decryptedJwe = decryptJwe(jwe, revealRequest.getEphemeralPublicKey().getPrivateKey());

        assertEquals("", result.stderr());
        assertEquals(5, jwe.split("\\.").length);
        assertFalse(jwe.contains(System.lineSeparator() + System.lineSeparator()));
        assertExpectedHeader(decryptedJwe.header());
        assertExpectedPayload(decryptedJwe.payload(), "card_12345");
    }

    @Test
    void mainJweEncryptCommandAcceptsPowerShellStrippedJsonArgument() throws Exception {
        RevealRequest revealRequest = Reveal.buildRevealRequest(true, "4012 8888 8888 1881", "mobile");
        String strippedJson = "{requestId:testrequest,cardRef:4012 8888 8888 1881,channel:mobile,ephemeralPublicKey:{"
                + "kty:" + revealRequest.getEphemeralPublicKey().getKty()
                + ",use:" + revealRequest.getEphemeralPublicKey().getUse()
                + ",alg:" + revealRequest.getEphemeralPublicKey().getAlg()
                + ",n:" + revealRequest.getEphemeralPublicKey().getN()
                + ",e:" + revealRequest.getEphemeralPublicKey().getE()
                + "}}";
        CliResult result = runMain("jwe-encrypt", strippedJson);
        String jwe = result.stdout().trim();
        DecryptedJwe decryptedJwe = decryptJwe(jwe, revealRequest.getEphemeralPublicKey().getPrivateKey());

        assertEquals("", result.stderr());
        assertEquals(5, jwe.split("\\.").length);
        assertExpectedHeader(decryptedJwe.header());
        assertExpectedPayload(decryptedJwe.payload(), "4012 8888 8888 1881");
    }

    private static void assertExpectedHeader(JsonNode header) {
        assertEquals("RSA-OAEP-256", header.get("alg").asText());
        assertEquals("A256GCM", header.get("enc").asText());
        assertEquals("JWE", header.get("typ").asText());
        assertEquals("json", header.get("cty").asText());
        assertEquals("ephemeral-key", header.get("kid").asText());
        assertEquals(1775901000L, header.get("iat").asLong());
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

    private static DecryptedJwe decryptJwe(String jwe, String privateKeyPem) throws Exception {
        String[] parts = jwe.split("\\.");
        assertEquals(5, parts.length);
        for (String part : parts) {
            assertTrue(part.matches("[A-Za-z0-9_-]+"));
        }

        JsonNode header = OBJECT_MAPPER.readTree(new String(KeyGeneratorUtil.base64urlDecode(parts[0]), StandardCharsets.UTF_8));
        byte[] encryptedKey = KeyGeneratorUtil.base64urlDecode(parts[1]);
        byte[] iv = KeyGeneratorUtil.base64urlDecode(parts[2]);
        byte[] ciphertext = KeyGeneratorUtil.base64urlDecode(parts[3]);
        byte[] tag = KeyGeneratorUtil.base64urlDecode(parts[4]);
        byte[] cek = decryptCek(encryptedKey, privateKeyPem);
        byte[] plaintext = decryptContent(cek, iv, ciphertext, tag);

        return new DecryptedJwe(header, OBJECT_MAPPER.readTree(new String(plaintext, StandardCharsets.UTF_8)));
    }

    private static byte[] decryptCek(byte[] encryptedKey, String privateKeyPem) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, toPrivateKey(privateKeyPem), oaepParameterSpec);
        return cipher.doFinal(encryptedKey);
    }

    private static byte[] decryptContent(byte[] cek, byte[] iv, byte[] ciphertext, byte[] tag) throws Exception {
        byte[] encryptedContent = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, encryptedContent, 0, ciphertext.length);
        System.arraycopy(tag, 0, encryptedContent, ciphertext.length, tag.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cek, "AES"), new GCMParameterSpec(128, iv));
        cipher.updateAAD(new byte[0]);
        return cipher.doFinal(encryptedContent);
    }

    private static PrivateKey toPrivateKey(String pem) throws Exception {
        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePrivate(
                new PKCS8EncodedKeySpec(Base64.getDecoder().decode(base64)));
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

    private record DecryptedJwe(JsonNode header, JsonNode payload) {
    }

    private record CliResult(String stdout, String stderr) {
    }
}
