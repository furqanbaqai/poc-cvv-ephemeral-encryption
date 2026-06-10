package com.openfintechlab.cms;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CMSDecryptTest {
    @Test
    void decryptFromCmsBase64ReturnsOriginalText() throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        String plainText = "test cvv text";
        String cipherText = CMSEncrypt.encryptToCmsBase64(plainText, toPublicKeyPem(keyPair));

        String decryptedText = CMSDecrypt.decryptFromCmsBase64(cipherText, toPrivateKeyPem(keyPair));

        assertEquals(plainText, decryptedText);
    }

    @Test
    void decryptFromNestedJoseReturnsOriginalText() throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        String plainText = "test cvv text";
        String token = CMSEncrypt.encryptToNestedJose(plainText, toPublicKeyPem(keyPair), toPrivateKeyPem(keyPair));

        String decryptedText = CMSDecrypt.decryptFromNestedJose(token, toPrivateKeyPem(keyPair), toPublicKeyPem(keyPair));

        assertEquals(plainText, decryptedText);
    }

    @Test
    void decryptFromCmsBase64StillHandlesPlainCompactJwe() throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        String plainText = "plain compact jwe";
        String token = CMSEncrypt.encryptToCompactJwe(plainText, toPublicKeyPem(keyPair));

        String decryptedText = CMSDecrypt.decryptFromCmsBase64(token, toPrivateKeyPem(keyPair));

        assertEquals(plainText, decryptedText);
    }

    @Test
    void decryptFromNestedJoseRejectsInvalidSignature() throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        String token = CMSEncrypt.encryptToNestedJose("test cvv text", toPublicKeyPem(keyPair), toPrivateKeyPem(keyPair));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                CMSDecrypt.decryptFromNestedJose(tamperSignature(token), toPrivateKeyPem(keyPair), toPublicKeyPem(keyPair)));

        assertTrue(exception.getMessage().contains("JWS signature verification failed"));
    }

    @Test
    void decryptFromNestedJoseRejectsInvalidContentType() throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        String token = CMSEncrypt.encryptToNestedJose("test cvv text", toPublicKeyPem(keyPair), toPrivateKeyPem(keyPair));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                CMSDecrypt.decryptFromNestedJose(replaceJwsHeader(token, "PS256", "JWT"), toPrivateKeyPem(keyPair), toPublicKeyPem(keyPair)));

        assertTrue(exception.getMessage().contains("cty=JWE"));
    }

    @Test
    void decryptFromNestedJoseRejectsUnsupportedAlgorithm() throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        String token = CMSEncrypt.encryptToNestedJose("test cvv text", toPublicKeyPem(keyPair), toPrivateKeyPem(keyPair));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () ->
                CMSDecrypt.decryptFromNestedJose(replaceJwsHeader(token, "RS256", "JWE"), toPrivateKeyPem(keyPair), toPublicKeyPem(keyPair)));

        assertTrue(exception.getMessage().contains("Unsupported JWS algorithm"));
    }

    private static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static String toPublicKeyPem(KeyPair keyPair) {
        String publicKey = Base64.getMimeEncoder(64, System.lineSeparator().getBytes(StandardCharsets.US_ASCII))
                .encodeToString(keyPair.getPublic().getEncoded());
        return "-----BEGIN PUBLIC KEY-----" + System.lineSeparator()
                + publicKey + System.lineSeparator()
                + "-----END PUBLIC KEY-----";
    }

    private static String toPrivateKeyPem(KeyPair keyPair) {
        String privateKey = Base64.getMimeEncoder(64, System.lineSeparator().getBytes(StandardCharsets.US_ASCII))
                .encodeToString(keyPair.getPrivate().getEncoded());
        return "-----BEGIN PRIVATE KEY-----" + System.lineSeparator()
                + privateKey + System.lineSeparator()
                + "-----END PRIVATE KEY-----";
    }

    private static String tamperSignature(String token) {
        String[] parts = token.split("\\.", -1);
        char replacement = parts[2].charAt(0) == 'A' ? 'B' : 'A';
        parts[2] = replacement + parts[2].substring(1);
        return parts[0] + "." + parts[1] + "." + parts[2];
    }

    private static String replaceJwsHeader(String token, String alg, String cty) {
        String[] parts = token.split("\\.", -1);
        String header = "{\"alg\":\"" + alg + "\",\"typ\":\"JOSE\",\"cty\":\"" + cty + "\",\"kid\":\"keyid\"}";
        parts[0] = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8));
        return parts[0] + "." + parts[1] + "." + parts[2];
    }
}
