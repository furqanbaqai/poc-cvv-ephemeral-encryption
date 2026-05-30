package com.openfintechlab.jwe.util;

import com.openfintechlab.jwe.model.EphemeralPublicKey;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;

/**
 * Utility methods for ephemeral RSA key generation and key encoding.
 */
public final class KeyGeneratorUtil {
    public static final int MIN_RSA_KEY_SIZE_BITS = 2048;

    private KeyGeneratorUtil() {
    }

    /**
     * Generates a new 2048-bit RSA key pair for a reveal request.
     *
     * @return generated RSA key pair
     * @throws GeneralSecurityException when RSA key generation fails
     */
    public static KeyPair generateEphemeralRsaKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(MIN_RSA_KEY_SIZE_BITS, createSecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        if (!(keyPair.getPublic() instanceof RSAPublicKey publicKey)
                || publicKey.getModulus().bitLength() < MIN_RSA_KEY_SIZE_BITS) {
            throw new GeneralSecurityException("Generated RSA key size is below 2048 bits");
        }

        return keyPair;
    }

    /**
     * Converts an RSA public key to the public JWK fields used by this project.
     *
     * @param publicKey RSA public key
     * @return public-key model containing JWK fields
     */
    public static String toJwkPublicKey(RSAPublicKey publicKey) {
        return JsonUtil.toMinifiedJson(toEphemeralPublicKey(publicKey));
    }

    /**
     * Converts an RSA public key to a model containing public JWK fields.
     *
     * @param publicKey RSA public key
     * @return public-key model containing JWK fields
     */
    public static EphemeralPublicKey toEphemeralPublicKey(RSAPublicKey publicKey) {
        return EphemeralPublicKey.builder()
                .kty("RSA")
                .use("enc")
                .alg("RSA-OAEP-256")
                .n(base64urlEncode(unsignedBigIntegerBytes(publicKey.getModulus())))
                .e(base64urlEncode(unsignedBigIntegerBytes(publicKey.getPublicExponent())))
                .build();
    }

    /**
     * Converts an RSA private key to PKCS#8 PEM text.
     *
     * @param privateKey RSA private key
     * @return PEM-encoded PKCS#8 private key
     */
    public static String toPemPrivateKey(RSAPrivateKey privateKey) {
        return toPemPrivateKey((PrivateKey) privateKey);
    }

    /**
     * Converts a private key to PKCS#8 PEM text.
     *
     * @param privateKey private key with PKCS#8 encoding
     * @return PEM-encoded PKCS#8 private key
     */
    public static String toPemPrivateKey(PrivateKey privateKey) {
        byte[] encoded = privateKey.getEncoded();

        try {
            String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded);
            return "-----BEGIN PRIVATE KEY-----\n"
                    + base64
                    + "\n-----END PRIVATE KEY-----";
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /**
     * Encodes bytes using base64url without padding.
     *
     * @param data source bytes
     * @return base64url text without padding
     */
    public static String base64urlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    /**
     * Decodes base64url text without requiring padding.
     *
     * @param value base64url text
     * @return decoded bytes
     */
    public static byte[] base64urlDecode(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    /**
     * Creates a secure random instance for request IDs and key generation.
     *
     * @return secure random instance
     */
    public static SecureRandom createSecureRandom() {
        try {
            return SecureRandom.getInstanceStrong();
        } catch (GeneralSecurityException ignored) {
            return new SecureRandom();
        }
    }

    private static byte[] unsignedBigIntegerBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();

        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }

        return bytes;
    }
}
