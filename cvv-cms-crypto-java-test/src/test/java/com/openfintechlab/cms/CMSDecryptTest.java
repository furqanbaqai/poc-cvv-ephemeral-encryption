package com.openfintechlab.cms;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CMSDecryptTest {
    @Test
    void decryptFromCmsBase64ReturnsOriginalText() throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        String plainText = "test cvv text";
        String cipherText = CMSEncrypt.encryptToCmsBase64(plainText, toPublicKeyPem(keyPair));

        String decryptedText = CMSDecrypt.decryptFromCmsBase64(cipherText, toPrivateKeyPem(keyPair));

        assertEquals(plainText, decryptedText);
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
}
