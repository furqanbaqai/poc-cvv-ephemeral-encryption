package com.openfintechlab.jwe;

import com.openfintechlab.jwe.model.EphemeralPublicKey;
import com.openfintechlab.jwe.model.RevealRequest;
import com.openfintechlab.jwe.util.JsonUtil;
import com.openfintechlab.jwe.util.KeyGeneratorUtil;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * CLI entry point for generating JWE reveal request payloads.
 */
public class Reveal {
    private static final String COMMAND_REVEAL = "reveal";
    private static final String OPTION_DEBUG = "debug";
    private static final String CARD_REF = "4012 8888 8888 1881";
    private static final String CHANNEL = "mobile";
    private static final int REQUEST_ID_BYTES = 16;
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /**
     * CLI entry point.
     *
     * @param args command-line arguments
     */
    public static void main(String[] args) {
        try {
            if (!isValidArguments(args)) {
                printUsage();
                System.exit(1);
            }

            boolean debug = args.length == 2;
            RevealRequest revealRequest = buildRevealRequest(debug);
            System.out.println(JsonUtil.toMinifiedJson(revealRequest));
        } catch (Exception exception) {
            System.err.println("Error: " + exception.getMessage());
            System.exit(1);
        }
    }

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

    private static boolean isValidArguments(String[] args) {
        if (args.length < 1 || args.length > 2) {
            return false;
        }

        if (!COMMAND_REVEAL.equals(args[0])) {
            return false;
        }

        return args.length != 2 || OPTION_DEBUG.equals(args[1]);
    }

    private static void printUsage() {
        System.err.println("Usage: java -jar cvv-encryption-java.jar <COMMAND> [OPTIONS]");
        System.err.println();
        System.err.println("Commands:");
        System.err.println("  reveal [debug]    Generate ephemeral RSA key pair and output request JSON");
        System.err.println("                    Include 'debug' to emit private key PEM");
        System.err.println();
        System.err.println("Examples:");
        System.err.println("  java -jar cvv-encryption-java.jar reveal");
        System.err.println("  java -jar cvv-encryption-java.jar reveal debug");
    }
}
