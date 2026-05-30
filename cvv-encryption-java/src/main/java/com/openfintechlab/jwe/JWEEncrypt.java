package com.openfintechlab.jwe;

import com.openfintechlab.jwe.util.JsonUtil;
import com.openfintechlab.jwe.util.KeyGeneratorUtil;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/**
 * Helper service for encrypting card payload data into JWE compact serialization.
 *
 * <p>Example usage:</p>
 *
 * <pre>{@code
 * JWEEncrypt encryptor = new JWEEncrypt(
 *     "4012 8888 8888 1881",
 *     "4012 8888 8888 1881",
 *     "12",
 *     "29",
 *     "123",
 *     1775901000L,
 *     1775901030L,
 *     "reveal-8f3a1c",
 *     "RSA",
 *     "enc",
 *     "RSA-OAEP-256",
 *     "...base64url modulus...",
 *     "AQAB"
 * );
 * String jwe = encryptor.encrypt();
 * }</pre>
 *
 * <p>The class does not perform console I/O. Command-line parsing and output are
 * owned by {@code com.sib.cvv.Main}.</p>
 */
public class JWEEncrypt {
    private static final String HEADER_JSON = "{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\","
            + "\"typ\":\"JWE\",\"cty\":\"json\",\"kid\":\"ephemeral-key\",\"iat\":1775901000}";
    private static final int CEK_BYTES = 32;
    private static final int IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_TAG_BYTES = 16;

    private final String cardRef;
    private final String pan;
    private final String expiryMonth;
    private final String expiryYear;
    private final String cvv;
    private final long issuedAt;
    private final long expiresAt;
    private final String jwtId;
    private final String keyType;
    private final String keyUse;
    private final String keyAlgorithm;
    private final String modulus;
    private final String exponent;

    /**
     * Creates a JWE encryptor with payload fields and RSA public JWK fields.
     *
     * @param cardRef card reference for the payload
     * @param pan PAN value for the payload
     * @param expiryMonth expiry month
     * @param expiryYear expiry year
     * @param cvv card verification value
     * @param issuedAt issued-at timestamp
     * @param expiresAt expiration timestamp
     * @param jwtId payload JWT ID
     * @param keyType JWK key type, expected {@code RSA}
     * @param keyUse JWK key use, expected {@code enc}
     * @param keyAlgorithm JWK algorithm, expected {@code RSA-OAEP-256}
     * @param modulus RSA modulus as base64url text
     * @param exponent RSA exponent as base64url text
     */
    public JWEEncrypt(
            String cardRef,
            String pan,
            String expiryMonth,
            String expiryYear,
            String cvv,
            long issuedAt,
            long expiresAt,
            String jwtId,
            String keyType,
            String keyUse,
            String keyAlgorithm,
            String modulus,
            String exponent) {
        this.cardRef = requireText(cardRef, "cardRef");
        this.pan = requireText(pan, "pan");
        this.expiryMonth = requireText(expiryMonth, "expiryMonth");
        this.expiryYear = requireText(expiryYear, "expiryYear");
        this.cvv = requireText(cvv, "cvv");
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.jwtId = requireText(jwtId, "jti");
        this.keyType = requireText(keyType, "kty");
        this.keyUse = requireText(keyUse, "use");
        this.keyAlgorithm = requireText(keyAlgorithm, "alg");
        this.modulus = requireText(modulus, "n");
        this.exponent = requireText(exponent, "e");
    }

    /**
     * Encrypts the configured payload into JWE compact serialization.
     *
     * @return compact JWE token
     * @throws GeneralSecurityException when key import or encryption fails
     */
    public String encrypt() throws GeneralSecurityException {
        validatePublicKeyMetadata();

        byte[] cek = new byte[CEK_BYTES];
        byte[] iv = new byte[IV_BYTES];
        byte[] encryptedKey = null;
        byte[] encryptedContent = null;

        try {
            SecureRandom secureRandom = KeyGeneratorUtil.createSecureRandom();
            secureRandom.nextBytes(cek);
            secureRandom.nextBytes(iv);

            encryptedKey = encryptContentEncryptionKey(cek, toRsaPublicKey());
            encryptedContent = encryptPayload(cek, iv);

            int ciphertextLength = encryptedContent.length - GCM_TAG_BYTES;
            byte[] ciphertext = Arrays.copyOfRange(encryptedContent, 0, ciphertextLength);
            byte[] tag = Arrays.copyOfRange(encryptedContent, ciphertextLength, encryptedContent.length);

            try {
                return String.join(".",
                        KeyGeneratorUtil.base64urlEncode(HEADER_JSON.getBytes(StandardCharsets.UTF_8)),
                        KeyGeneratorUtil.base64urlEncode(encryptedKey),
                        KeyGeneratorUtil.base64urlEncode(iv),
                        KeyGeneratorUtil.base64urlEncode(ciphertext),
                        KeyGeneratorUtil.base64urlEncode(tag));
            } finally {
                Arrays.fill(ciphertext, (byte) 0);
                Arrays.fill(tag, (byte) 0);
            }
        } finally {
            Arrays.fill(cek, (byte) 0);
            Arrays.fill(iv, (byte) 0);
            clear(encryptedKey);
            clear(encryptedContent);
        }
    }

    private void validatePublicKeyMetadata() throws GeneralSecurityException {
        if (!"RSA".equals(keyType)) {
            throw new GeneralSecurityException("Invalid public key type: expected RSA");
        }

        if (!"enc".equals(keyUse)) {
            throw new GeneralSecurityException("Invalid public key use: expected enc");
        }

        if (!"RSA-OAEP-256".equals(keyAlgorithm)) {
            throw new GeneralSecurityException("Invalid public key algorithm: expected RSA-OAEP-256");
        }

        if (expiresAt <= issuedAt) {
            throw new GeneralSecurityException("Invalid payload timestamps: exp must be greater than iat");
        }
    }

    private RSAPublicKey toRsaPublicKey() throws GeneralSecurityException {
        BigInteger n = new BigInteger(1, KeyGeneratorUtil.base64urlDecode(modulus));
        BigInteger e = new BigInteger(1, KeyGeneratorUtil.base64urlDecode(exponent));

        if (n.bitLength() < KeyGeneratorUtil.MIN_RSA_KEY_SIZE_BITS) {
            throw new GeneralSecurityException("RSA modulus must be at least 2048 bits");
        }

        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e));
    }

    private byte[] encryptContentEncryptionKey(byte[] cek, RSAPublicKey publicKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaepParameterSpec = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParameterSpec);
        return cipher.doFinal(cek);
    }

    private byte[] encryptPayload(byte[] cek, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeySpec key = new SecretKeySpec(cek, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
        cipher.updateAAD(new byte[0]);
        return cipher.doFinal(buildPayloadJson().getBytes(StandardCharsets.UTF_8));
    }

    private String buildPayloadJson() {
        return "{"
                + JsonUtil.jsonField("cardRef", cardRef) + ","
                + JsonUtil.jsonField("pan", pan) + ","
                + JsonUtil.jsonField("expiryMonth", expiryMonth) + ","
                + JsonUtil.jsonField("expiryYear", expiryYear) + ","
                + JsonUtil.jsonField("cvv", cvv) + ","
                + "\"iat\":" + issuedAt + ","
                + "\"exp\":" + expiresAt + ","
                + JsonUtil.jsonField("jti", jwtId)
                + "}";
    }

    private static String requireText(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing required field: " + fieldName);
        }
        return value;
    }

    private static void clear(byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
        }
    }
}
