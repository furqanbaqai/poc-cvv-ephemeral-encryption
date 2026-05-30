package com.sib.cvv;

import com.openfintechlab.jwe.JWEEncrypt;
import com.openfintechlab.jwe.Reveal;
import com.openfintechlab.jwe.model.RevealRequest;
import com.openfintechlab.jwe.util.JsonUtil;
import java.util.LinkedHashMap;
import java.util.Map;

public class Main {
    private static final String COMMAND_REVEAL = "reveal";
    private static final String COMMAND_JWE_ENCRYPT = "jwe-encrypt";
    private static final String OPTION_DEBUG = "debug";
    private static final String EXPIRY_MONTH = "12";
    private static final String EXPIRY_YEAR = "29";
    private static final String CVV = "123";
    private static final long PAYLOAD_IAT = 1775901000L;
    private static final long PAYLOAD_EXP = 1775901030L;
    private static final String PAYLOAD_JTI = "reveal-8f3a1c";

    public static void main(String[] args) {
        try {
            if (isRevealCommand(args)) {
                boolean debug = args.length == 2;
                RevealRequest revealRequest = Reveal.buildRevealRequest(debug);
                System.out.println(JsonUtil.toMinifiedJson(revealRequest));
                return;
            }

            if (isJweEncryptCommand(args)) {
                RevealInput revealInput = parseRevealInput(args[1]);
                JWEEncrypt encryptor = new JWEEncrypt(
                        revealInput.cardRef(),
                        revealInput.cardRef(),
                        EXPIRY_MONTH,
                        EXPIRY_YEAR,
                        CVV,
                        PAYLOAD_IAT,
                        PAYLOAD_EXP,
                        PAYLOAD_JTI,
                        revealInput.publicKey().get("kty"),
                        revealInput.publicKey().get("use"),
                        revealInput.publicKey().get("alg"),
                        revealInput.publicKey().get("n"),
                        revealInput.publicKey().get("e"));
                System.out.println(encryptor.encrypt());
                return;
            }

            if (!isValidArguments(args)) {
                printUsage();
                System.exit(1);
            }
        } catch (Exception exception) {
            System.err.println("Error: " + exception.getMessage());
            System.exit(1);
        }
    }

    private static boolean isValidArguments(String[] args) {
        return isRevealCommand(args) || isJweEncryptCommand(args);
    }

    private static boolean isRevealCommand(String[] args) {
        return (args.length == 1 && COMMAND_REVEAL.equals(args[0]))
                || (args.length == 2 && COMMAND_REVEAL.equals(args[0]) && OPTION_DEBUG.equals(args[1]));
    }

    private static boolean isJweEncryptCommand(String[] args) {
        return args.length == 2 && COMMAND_JWE_ENCRYPT.equals(args[0]) && !args[1].isBlank();
    }

    private static void printUsage() {
        System.err.println("Usage: java -jar cvv-encryption-java.jar <COMMAND> [OPTIONS]");
        System.err.println();
        System.err.println("Commands:");
        System.err.println("  reveal [debug]    Generate ephemeral RSA key pair and output request JSON");
        System.err.println("                    Include 'debug' to emit private key PEM");
        System.err.println("  jwe-encrypt <JSON-PAYLOAD>");
        System.err.println("                    Encrypt card data using reveal request public key");
        System.err.println();
        System.err.println("Examples:");
        System.err.println("  java -jar cvv-encryption-java.jar reveal");
        System.err.println("  java -jar cvv-encryption-java.jar reveal debug");
        System.err.println("  java -jar cvv-encryption-java.jar jwe-encrypt '{\"requestId\":\"...\",\"cardRef\":\"...\",\"channel\":\"mobile\",\"ephemeralPublicKey\":{\"kty\":\"RSA\",\"use\":\"enc\",\"alg\":\"RSA-OAEP-256\",\"n\":\"...\",\"e\":\"AQAB\"}}'");
    }

    private static RevealInput parseRevealInput(String jsonPayload) {
        JsonObjectParser parser = new JsonObjectParser(jsonPayload);
        Map<String, String> root = parser.parseObject();
        String cardRef = required(root, "cardRef");
        String publicKeyJson = required(root, "ephemeralPublicKey");
        Map<String, String> publicKey = new JsonObjectParser(publicKeyJson).parseObject();

        for (String field : new String[] {"kty", "use", "alg", "n", "e"}) {
            required(publicKey, field);
        }

        return new RevealInput(cardRef, publicKey);
    }

    private static String required(Map<String, String> values, String fieldName) {
        String value = values.get(fieldName);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing required JSON field: " + fieldName);
        }
        return value;
    }

    private record RevealInput(String cardRef, Map<String, String> publicKey) {
    }

    private static final class JsonObjectParser {
        private final String input;
        private int index;

        private JsonObjectParser(String input) {
            this.input = input == null ? "" : input.trim();
        }

        private Map<String, String> parseObject() {
            Map<String, String> values = new LinkedHashMap<>();
            consumeWhitespace();
            expect('{');
            consumeWhitespace();

            if (peek('}')) {
                index++;
                return values;
            }

            while (true) {
                consumeWhitespace();
                String key = parseKey();
                consumeWhitespace();
                expect(':');
                consumeWhitespace();
                String value = parseValue();
                values.put(key, value);
                consumeWhitespace();

                if (peek(',')) {
                    index++;
                    continue;
                }

                expect('}');
                consumeWhitespace();
                if (index != input.length()) {
                    throw new IllegalArgumentException("Invalid JSON payload");
                }
                return values;
            }
        }

        private String parseValue() {
            if (peek('"')) {
                return parseString();
            }

            if (peek('{')) {
                return parseNestedObject();
            }

            return parseBareValue();
        }

        private String parseKey() {
            if (peek('"')) {
                return parseString();
            }

            return parseBareKey();
        }

        private String parseBareKey() {
            int start = index;

            while (index < input.length()) {
                char character = input.charAt(index);
                if (character == ':' || Character.isWhitespace(character)) {
                    break;
                }
                index++;
            }

            String key = input.substring(start, index).trim();
            if (!key.matches("[A-Za-z_$][A-Za-z0-9_$]*")) {
                throw new IllegalArgumentException("Invalid JSON payload");
            }

            return key;
        }

        private String parseBareValue() {
            int start = index;

            while (index < input.length()) {
                char character = input.charAt(index);
                if (character == ',' || character == '}') {
                    break;
                }
                index++;
            }

            String value = input.substring(start, index).trim();
            if (value.isEmpty()) {
                throw new IllegalArgumentException("Invalid JSON payload");
            }

            return value;
        }

        private String parseNestedObject() {
            int start = index;
            int depth = 0;
            boolean inString = false;
            boolean escaped = false;

            while (index < input.length()) {
                char character = input.charAt(index);

                if (inString) {
                    if (escaped) {
                        escaped = false;
                    } else if (character == '\\') {
                        escaped = true;
                    } else if (character == '"') {
                        inString = false;
                    }
                } else if (character == '"') {
                    inString = true;
                } else if (character == '{') {
                    depth++;
                } else if (character == '}') {
                    depth--;
                    if (depth == 0) {
                        index++;
                        return input.substring(start, index);
                    }
                }
                index++;
            }

            throw new IllegalArgumentException("Invalid JSON payload");
        }

        private String parseString() {
            expect('"');
            StringBuilder value = new StringBuilder();

            while (index < input.length()) {
                char character = input.charAt(index++);

                if (character == '"') {
                    return value.toString();
                }

                if (character == '\\') {
                    value.append(parseEscapedCharacter());
                } else {
                    value.append(character);
                }
            }

            throw new IllegalArgumentException("Invalid JSON payload");
        }

        private char parseEscapedCharacter() {
            if (index >= input.length()) {
                throw new IllegalArgumentException("Invalid JSON payload");
            }

            char escaped = input.charAt(index++);
            return switch (escaped) {
                case '"', '\\', '/' -> escaped;
                case 'b' -> '\b';
                case 'f' -> '\f';
                case 'n' -> '\n';
                case 'r' -> '\r';
                case 't' -> '\t';
                case 'u' -> parseUnicodeEscape();
                default -> throw new IllegalArgumentException("Invalid JSON payload");
            };
        }

        private char parseUnicodeEscape() {
            if (index + 4 > input.length()) {
                throw new IllegalArgumentException("Invalid JSON payload");
            }

            String hex = input.substring(index, index + 4);
            index += 4;
            try {
                return (char) Integer.parseInt(hex, 16);
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException("Invalid JSON payload", exception);
            }
        }

        private void consumeWhitespace() {
            while (index < input.length() && Character.isWhitespace(input.charAt(index))) {
                index++;
            }
        }

        private boolean peek(char expected) {
            return index < input.length() && input.charAt(index) == expected;
        }

        private void expect(char expected) {
            if (!peek(expected)) {
                throw new IllegalArgumentException("Invalid JSON payload");
            }
            index++;
        }
    }
}
