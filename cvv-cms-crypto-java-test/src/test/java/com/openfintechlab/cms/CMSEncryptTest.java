package com.openfintechlab.cms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class CMSEncryptTest {
    @Test
    void encryptToCmsBase64ReturnsDecryptableNativeEnvelope() throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        String publicKeyPem = toPublicKeyPem(keyPair);
        String plainText = "test cvv text";

        String encryptedBase64 = CMSEncrypt.encryptToCmsBase64(plainText, publicKeyPem);

        assertNotEquals(plainText, encryptedBase64);
        assertEquals(plainText, decryptEnvelope(encryptedBase64, keyPair));
    }

    @Test
    void encryptToNestedJoseReturnsJwsContainingJwe() throws Exception {
        KeyPair keyPair = generateRsaKeyPair();

        String token = CMSEncrypt.encryptToNestedJose(
                "test cvv text",
                toPublicKeyPem(keyPair),
                toPrivateKeyPem(keyPair));

        String[] jwsParts = token.split("\\.", -1);
        assertEquals(3, jwsParts.length);

        String innerJwe = new String(Base64.getUrlDecoder().decode(jwsParts[1]), StandardCharsets.UTF_8);
        assertEquals(5, innerJwe.split("\\.", -1).length);
        assertEquals("test cvv text", CMSDecrypt.decryptFromNestedJose(
                token,
                toPrivateKeyPem(keyPair),
                toPublicKeyPem(keyPair)));
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

    private static String decryptEnvelope(String encryptedBase64, KeyPair keyPair) throws Exception {
        DataInputStream input = new DataInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(encryptedBase64)));
        byte[] magic = new byte[7];
        input.readFully(magic);
        input.readByte();

        byte[] encryptedContentKey = new byte[input.readInt()];
        input.readFully(encryptedContentKey);
        byte[] iv = new byte[input.readInt()];
        input.readFully(iv);
        byte[] encryptedContent = new byte[input.readInt()];
        input.readFully(encryptedContent);

        Cipher keyCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT);
        keyCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate(), oaepParameterSpec);
        byte[] contentKey = keyCipher.doFinal(encryptedContentKey);

        Cipher contentCipher = Cipher.getInstance("AES/GCM/NoPadding");
        contentCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(contentKey, "AES"), new GCMParameterSpec(128, iv));
        return new String(contentCipher.doFinal(encryptedContent), StandardCharsets.UTF_8);
    }
}
