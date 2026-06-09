package com.openfintechlab.cms;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public final class CMSEncrypt {
    private static final byte[] ENVELOPE_MAGIC = new byte[] {'O', 'F', 'T', 'L', 'C', 'M', 'S'};
    private static final byte ENVELOPE_VERSION = 1;
    private static final int AES_KEY_SIZE_BITS = 256;
    private static final int GCM_IV_SIZE_BYTES = 12;
    private static final int GCM_TAG_SIZE_BITS = 128;

    private CMSEncrypt() {
    }

    public static String encryptToCmsBase64(String text, String publicKeyPem) throws Exception {
        PublicKey publicKey = parsePublicKey(publicKeyPem);
        SecretKey contentKey = generateContentKey();
        byte[] iv = generateIv();
        byte[] encryptedContentKey = encryptContentKey(contentKey, publicKey);
        byte[] encryptedContent = encryptContent(text, contentKey, iv);

        return Base64.getEncoder().encodeToString(encodeEnvelope(encryptedContentKey, iv, encryptedContent));
    }

    private static PublicKey parsePublicKey(String publicKeyPem) throws Exception {
        String keyBody = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("\\n", "")
                .replaceAll("\\s", "");

        byte[] encodedKey = Base64.getDecoder().decode(keyBody);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encodedKey));
    }

    private static SecretKey generateContentKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(AES_KEY_SIZE_BITS);
        return keyGenerator.generateKey();
    }

    private static byte[] generateIv() {
        byte[] iv = new byte[GCM_IV_SIZE_BYTES];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private static byte[] encryptContentKey(SecretKey contentKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParameterSpec);
        return cipher.doFinal(contentKey.getEncoded());
    }

    private static byte[] encryptContent(String text, SecretKey contentKey, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, contentKey, new GCMParameterSpec(GCM_TAG_SIZE_BITS, iv));
        return cipher.doFinal(text.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] encodeEnvelope(byte[] encryptedContentKey, byte[] iv, byte[] encryptedContent)
            throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        DataOutputStream dataOutput = new DataOutputStream(output);

        dataOutput.write(ENVELOPE_MAGIC);
        dataOutput.writeByte(ENVELOPE_VERSION);
        dataOutput.writeInt(encryptedContentKey.length);
        dataOutput.write(encryptedContentKey);
        dataOutput.writeInt(iv.length);
        dataOutput.write(iv);
        dataOutput.writeInt(encryptedContent.length);
        dataOutput.write(encryptedContent);
        dataOutput.flush();

        return output.toByteArray();
    }
}
