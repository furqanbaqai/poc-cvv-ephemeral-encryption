package com.openfintechlab.cms;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
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

public final class CMSDecrypt {
    private static final byte[] ENVELOPE_MAGIC = new byte[] {'O', 'F', 'T', 'L', 'C', 'M', 'S'};
    private static final byte ENVELOPE_VERSION = 1;
    private static final int GCM_TAG_SIZE_BITS = 128;

    private CMSDecrypt() {
    }

    public static String decryptFromCmsBase64(String cipherText, String privateKeyPem) throws Exception {
        PrivateKey privateKey = parsePrivateKey(privateKeyPem);
        EncryptedEnvelope envelope = decodeEnvelope(Base64.getDecoder().decode(cipherText));
        byte[] contentKey = decryptContentKey(envelope.encryptedContentKey, privateKey);
        byte[] plainText = decryptContent(envelope.encryptedContent, contentKey, envelope.iv);

        return new String(plainText, StandardCharsets.UTF_8);
    }

    private static PrivateKey parsePrivateKey(String privateKeyPem) throws Exception {
        String keyBody = privateKeyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("\\n", "")
                .replaceAll("\\s", "");

        byte[] encodedKey = Base64.getDecoder().decode(keyBody);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
    }

    private static EncryptedEnvelope decodeEnvelope(byte[] encodedEnvelope) throws Exception {
        DataInputStream input = new DataInputStream(new ByteArrayInputStream(encodedEnvelope));

        byte[] magic = new byte[ENVELOPE_MAGIC.length];
        input.readFully(magic);
        for (int index = 0; index < ENVELOPE_MAGIC.length; index++) {
            if (magic[index] != ENVELOPE_MAGIC[index]) {
                throw new IllegalArgumentException("Invalid encrypted envelope format.");
            }
        }

        byte version = input.readByte();
        if (version != ENVELOPE_VERSION) {
            throw new IllegalArgumentException("Unsupported encrypted envelope version: " + version);
        }

        byte[] encryptedContentKey = readLengthPrefixedBytes(input);
        byte[] iv = readLengthPrefixedBytes(input);
        byte[] encryptedContent = readLengthPrefixedBytes(input);

        return new EncryptedEnvelope(encryptedContentKey, iv, encryptedContent);
    }

    private static byte[] readLengthPrefixedBytes(DataInputStream input) throws Exception {
        int length = input.readInt();
        if (length <= 0) {
            throw new IllegalArgumentException("Invalid encrypted envelope field length.");
        }

        byte[] value = new byte[length];
        input.readFully(value);
        return value;
    }

    private static byte[] decryptContentKey(byte[] encryptedContentKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParameterSpec);
        return cipher.doFinal(encryptedContentKey);
    }

    private static byte[] decryptContent(byte[] encryptedContent, byte[] contentKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(contentKey, "AES"), new GCMParameterSpec(GCM_TAG_SIZE_BITS, iv));
        return cipher.doFinal(encryptedContent);
    }

    private static final class EncryptedEnvelope {
        private final byte[] encryptedContentKey;
        private final byte[] iv;
        private final byte[] encryptedContent;

        private EncryptedEnvelope(byte[] encryptedContentKey, byte[] iv, byte[] encryptedContent) {
            this.encryptedContentKey = encryptedContentKey;
            this.iv = iv;
            this.encryptedContent = encryptedContent;
        }
    }
}
