package com.openfintechlab.jwe;

import com.openfintechlab.jwe.model.EphemeralPublicKey;
import com.openfintechlab.jwe.model.RevealRequest;
import com.openfintechlab.jwe.util.KeyGeneratorUtil;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Helper service for generating JWE reveal request payloads.
 */
public class Reveal {
    private static final String CARD_REF = "4012 8888 8888 1881";
    private static final String CHANNEL = "mobile";
    private static final int REQUEST_ID_BYTES = 16;
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /**
     * Builds a reveal request with an ephemeral RSA public key.
     *
     * @param debug when true, includes PKCS#8 PEM private key in the output
     * @return reveal request model
     * @throws Exception when key generation or request serialization preparation fails
     */
    public static RevealRequest buildRevealRequest(boolean debug) throws Exception {
        KeyPair keyPair = KeyGeneratorUtil.generateEphemeralRsaKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        EphemeralPublicKey ephemeralPublicKey = KeyGeneratorUtil.toEphemeralPublicKey(publicKey);

        if (debug) {
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            ephemeralPublicKey.setPrivateKey(KeyGeneratorUtil.toPemPrivateKey(privateKey));
        }

        return RevealRequest.builder()
                .requestId(generateRequestId())
                .cardRef(CARD_REF)
                .channel(CHANNEL)
                .ephemeralPublicKey(ephemeralPublicKey)
                .build();
    }

    /**
     * Generates a cryptographically secure 32-character hexadecimal request ID.
     *
     * @return request ID
     */
    public static String generateRequestId() {
        SecureRandom secureRandom = KeyGeneratorUtil.createSecureRandom();
        byte[] randomBytes = new byte[REQUEST_ID_BYTES];

        try {
            secureRandom.nextBytes(randomBytes);
            char[] hexChars = new char[REQUEST_ID_BYTES * 2];

            for (int i = 0; i < randomBytes.length; i++) {
                int value = randomBytes[i] & 0xff;
                hexChars[i * 2] = HEX[value >>> 4];
                hexChars[i * 2 + 1] = HEX[value & 0x0f];
            }

            return new String(hexChars);
        } finally {
            java.util.Arrays.fill(randomBytes, (byte) 0);
        }
    }
}
