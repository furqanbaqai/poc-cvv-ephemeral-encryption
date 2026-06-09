package com.sib.cvv.cms;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

import com.openfintechlab.cms.CMSEncrypt;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MainTest {
    @Test
    void cmsEncryptPrintsCmsEnvelope() throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        String publicKey = toPublicKeyPem(keyPair);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ByteArrayOutputStream error = new ByteArrayOutputStream();

        int exitCode = Main.run(new String[] {"cms-encrypt", "test cvv text", publicKey},
                new PrintStream(output), new PrintStream(error));

        assertEquals(0, exitCode);
        assertEquals("", error.toString());
        assertTrue(output.toString().trim().length() > 0);
    }

    @Test
    void cmsDecryptPrintsPlainText() throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        String plainText = "test cvv text";
        String cipherText = CMSEncrypt.encryptToCmsBase64(plainText, toPublicKeyPem(keyPair));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ByteArrayOutputStream error = new ByteArrayOutputStream();

        int exitCode = Main.run(new String[] {"cms-decrypt", cipherText, toPrivateKeyPem(keyPair)},
                new PrintStream(output), new PrintStream(error));

        assertEquals(0, exitCode);
        assertEquals("", error.toString());
        assertEquals(plainText + System.lineSeparator(), output.toString());
    }

    @Test
    void runPrintsUsageForUnknownCommand() {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        ByteArrayOutputStream error = new ByteArrayOutputStream();

        int exitCode = Main.run(new String[] {"unknown"},
                new PrintStream(output), new PrintStream(error));

        assertEquals(1, exitCode);
        assertEquals("", output.toString());
        assertTrue(error.toString().contains("cms-encrypt <text> <public-key-pem>"));
        assertTrue(error.toString().contains("cms-decrypt <cipher-text> <private-key-pem>"));
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
