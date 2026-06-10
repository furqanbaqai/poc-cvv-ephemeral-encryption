package com.openfintechlab.cms;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

final class JoseSupport {
    private static final String JWE_ALG = "RSA-OAEP-256";
    private static final String JWE_ENC = "A256GCM";
    private static final String JOSE_TYP = "JOSE";
    private static final String JWS_ALG = "PS256";
    private static final String JWS_CTY = "JWE";
    private static final String DEFAULT_KID = "keyid";
    private static final int AES_KEY_SIZE_BITS = 256;
    private static final int GCM_IV_SIZE_BYTES = 12;
    private static final int GCM_TAG_SIZE_BYTES = 16;
    private static final int GCM_TAG_SIZE_BITS = GCM_TAG_SIZE_BYTES * 8;
    private static final int TOKEN_TTL_MINUTES = 5;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private JoseSupport() {
    }

    static boolean isCompactJwe(String token) {
        return token != null && token.split("\\.", -1).length == 5;
    }

    static boolean isCompactJws(String token) {
        return token != null && token.split("\\.", -1).length == 3;
    }

    static String encryptToCompactJwe(String plainText, PublicKey publicKey) throws Exception {
        Instant issuedAt = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expiresAt = issuedAt.plus(TOKEN_TTL_MINUTES, ChronoUnit.MINUTES);
        return encryptToCompactJwe(plainText, publicKey, issuedAt, expiresAt);
    }

    static String encryptToCompactJwe(String plainText, PublicKey publicKey, Instant issuedAt, Instant expiresAt)
            throws Exception {
        Map<String, String> header = new LinkedHashMap<String, String>();
        header.put("alg", JWE_ALG);
        header.put("enc", JWE_ENC);
        header.put("typ", JOSE_TYP);
        header.put("iat", issuedAt.toString());
        header.put("exp", expiresAt.toString());

        String encodedHeader = base64UrlEncode(toJson(header).getBytes(StandardCharsets.UTF_8));
        SecretKey contentKey = generateContentKey();
        byte[] iv = generateIv();
        byte[] encryptedKey = encryptContentKey(contentKey, publicKey);
        byte[] cipherAndTag = encryptContent(
                plainText.getBytes(StandardCharsets.UTF_8),
                contentKey.getEncoded(),
                iv,
                encodedHeader.getBytes(StandardCharsets.US_ASCII));

        int cipherTextLength = cipherAndTag.length - GCM_TAG_SIZE_BYTES;
        byte[] cipherText = new byte[cipherTextLength];
        byte[] tag = new byte[GCM_TAG_SIZE_BYTES];
        System.arraycopy(cipherAndTag, 0, cipherText, 0, cipherTextLength);
        System.arraycopy(cipherAndTag, cipherTextLength, tag, 0, GCM_TAG_SIZE_BYTES);

        return encodedHeader + "."
                + base64UrlEncode(encryptedKey) + "."
                + base64UrlEncode(iv) + "."
                + base64UrlEncode(cipherText) + "."
                + base64UrlEncode(tag);
    }

    static String signCompactJwe(String compactJwe, PrivateKey privateKey) throws Exception {
        Map<String, String> header = new LinkedHashMap<String, String>();
        header.put("alg", JWS_ALG);
        header.put("typ", JOSE_TYP);
        header.put("cty", JWS_CTY);
        header.put("kid", DEFAULT_KID);

        String encodedHeader = base64UrlEncode(toJson(header).getBytes(StandardCharsets.UTF_8));
        String encodedPayload = base64UrlEncode(compactJwe.getBytes(StandardCharsets.UTF_8));
        String signingInput = encodedHeader + "." + encodedPayload;
        byte[] signature = signPs256(signingInput.getBytes(StandardCharsets.US_ASCII), privateKey);
        return signingInput + "." + base64UrlEncode(signature);
    }

    static String extractVerifiedJwe(String compactJws, PublicKey publicKey) throws Exception {
        String[] parts = splitToken(compactJws, 3);
        Map<String, String> header = parseJsonObject(base64UrlDecodeToString(parts[0]));
        if (!JWS_ALG.equals(header.get("alg"))) {
            throw new IllegalArgumentException("Unsupported JWS algorithm: " + header.get("alg"));
        }
        if (!JWS_CTY.equals(header.get("cty"))) {
            throw new IllegalArgumentException("Invalid JWS content type. Expected cty=JWE.");
        }

        String signingInput = parts[0] + "." + parts[1];
        if (!verifyPs256(signingInput.getBytes(StandardCharsets.US_ASCII), base64UrlDecode(parts[2]), publicKey)) {
            throw new IllegalArgumentException("JWS signature verification failed.");
        }

        String innerJwe = base64UrlDecodeToString(parts[1]);
        if (!isCompactJwe(innerJwe)) {
            throw new IllegalArgumentException("Invalid compact token format. Expected inner JWE with 5 parts.");
        }
        return innerJwe;
    }

    static String decryptCompactJwe(String compactJwe, PrivateKey privateKey) throws Exception {
        return decryptCompactJwe(compactJwe, privateKey, false);
    }

    static String decryptCompactJwe(String compactJwe, PrivateKey privateKey, boolean ignoreExpiry) throws Exception {
        String[] parts = splitToken(compactJwe, 5);
        Map<String, String> header = parseJsonObject(base64UrlDecodeToString(parts[0]));
        if (!JWE_ALG.equals(header.get("alg"))) {
            throw new IllegalArgumentException("Unsupported JWE algorithm: " + header.get("alg"));
        }
        if (!JWE_ENC.equals(header.get("enc"))) {
            throw new IllegalArgumentException("Unsupported JWE encryption method: " + header.get("enc"));
        }
        if (!ignoreExpiry) {
            validateTimestamps(header.get("iat"), header.get("exp"));
        }

        byte[] contentKey = decryptContentKey(base64UrlDecode(parts[1]), privateKey);
        byte[] iv = base64UrlDecode(parts[2]);
        byte[] cipherText = base64UrlDecode(parts[3]);
        byte[] tag = base64UrlDecode(parts[4]);
        byte[] cipherAndTag = ByteBuffer.allocate(cipherText.length + tag.length)
                .put(cipherText)
                .put(tag)
                .array();
        byte[] plainText = decryptContent(
                cipherAndTag,
                contentKey,
                iv,
                parts[0].getBytes(StandardCharsets.US_ASCII));
        return new String(plainText, StandardCharsets.UTF_8);
    }

    private static SecretKey generateContentKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(AES_KEY_SIZE_BITS);
        return keyGenerator.generateKey();
    }

    private static byte[] generateIv() {
        byte[] iv = new byte[GCM_IV_SIZE_BYTES];
        SECURE_RANDOM.nextBytes(iv);
        return iv;
    }

    private static byte[] encryptContentKey(SecretKey contentKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepSpec());
        return cipher.doFinal(contentKey.getEncoded());
    }

    private static byte[] decryptContentKey(byte[] encryptedContentKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepSpec());
        return cipher.doFinal(encryptedContentKey);
    }

    private static byte[] encryptContent(byte[] plainText, byte[] contentKey, byte[] iv, byte[] aad) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(contentKey, "AES"), new GCMParameterSpec(GCM_TAG_SIZE_BITS, iv));
        cipher.updateAAD(aad);
        return cipher.doFinal(plainText);
    }

    private static byte[] decryptContent(byte[] cipherAndTag, byte[] contentKey, byte[] iv, byte[] aad) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(contentKey, "AES"), new GCMParameterSpec(GCM_TAG_SIZE_BITS, iv));
        cipher.updateAAD(aad);
        return cipher.doFinal(cipherAndTag);
    }

    private static OAEPParameterSpec oaepSpec() {
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
    }

    private static byte[] signPs256(byte[] signingInput, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("RSASSA-PSS");
        signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        signature.initSign(privateKey);
        signature.update(signingInput);
        return signature.sign();
    }

    private static boolean verifyPs256(byte[] signingInput, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("RSASSA-PSS");
        signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        signature.initVerify(publicKey);
        signature.update(signingInput);
        return signature.verify(signatureBytes);
    }

    private static void validateTimestamps(String issuedAt, String expiresAt) {
        if (issuedAt != null && issuedAt.length() > 0) {
            Instant issueTime = Instant.parse(issuedAt);
            if (issueTime.isAfter(Instant.now())) {
                throw new IllegalArgumentException("Token issued in the future at " + issuedAt);
            }
        }

        if (expiresAt == null || expiresAt.length() == 0) {
            return;
        }

        Instant expiry = Instant.parse(expiresAt);
        if (!Instant.now().isBefore(expiry)) {
            throw new IllegalArgumentException("Token expired at " + expiresAt);
        }
    }

    private static String[] splitToken(String token, int expectedParts) {
        String[] parts = token.split("\\.", -1);
        if (parts.length != expectedParts) {
            throw new IllegalArgumentException(
                    "Invalid compact token format. Expected " + expectedParts + " parts but found " + parts.length + ".");
        }
        for (String part : parts) {
            if (part.length() == 0) {
                throw new IllegalArgumentException("Invalid compact token format. Token parts must not be empty.");
            }
        }
        return parts;
    }

    private static String base64UrlEncode(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private static byte[] base64UrlDecode(String value) {
        return Base64.getUrlDecoder().decode(value);
    }

    private static String base64UrlDecodeToString(String value) {
        return new String(base64UrlDecode(value), StandardCharsets.UTF_8);
    }

    private static String toJson(Map<String, String> values) {
        StringBuilder json = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : values.entrySet()) {
            if (!first) {
                json.append(',');
            }
            json.append('"').append(escapeJson(entry.getKey())).append('"')
                    .append(':')
                    .append('"').append(escapeJson(entry.getValue())).append('"');
            first = false;
        }
        json.append('}');
        return json.toString();
    }

    private static Map<String, String> parseJsonObject(String json) {
        Map<String, String> values = new LinkedHashMap<String, String>();
        int index = skipWhitespace(json, 0);
        if (index >= json.length() || json.charAt(index) != '{') {
            throw new IllegalArgumentException("Invalid JOSE header JSON.");
        }
        index++;

        while (true) {
            index = skipWhitespace(json, index);
            if (index < json.length() && json.charAt(index) == '}') {
                return values;
            }
            ParsedString key = parseJsonString(json, index);
            index = skipWhitespace(json, key.nextIndex);
            if (index >= json.length() || json.charAt(index) != ':') {
                throw new IllegalArgumentException("Invalid JOSE header JSON.");
            }
            index = skipWhitespace(json, index + 1);
            ParsedString value = parseJsonString(json, index);
            values.put(key.value, value.value);
            index = skipWhitespace(json, value.nextIndex);
            if (index < json.length() && json.charAt(index) == ',') {
                index++;
                continue;
            }
            if (index < json.length() && json.charAt(index) == '}') {
                return values;
            }
            throw new IllegalArgumentException("Invalid JOSE header JSON.");
        }
    }

    private static ParsedString parseJsonString(String json, int index) {
        if (index >= json.length() || json.charAt(index) != '"') {
            throw new IllegalArgumentException("Invalid JOSE header JSON.");
        }
        StringBuilder value = new StringBuilder();
        index++;
        while (index < json.length()) {
            char current = json.charAt(index);
            if (current == '"') {
                return new ParsedString(value.toString(), index + 1);
            }
            if (current == '\\') {
                if (index + 1 >= json.length()) {
                    throw new IllegalArgumentException("Invalid JOSE header JSON.");
                }
                char escaped = json.charAt(index + 1);
                if (escaped == '"' || escaped == '\\' || escaped == '/') {
                    value.append(escaped);
                    index += 2;
                    continue;
                }
                if (escaped == 'b') {
                    value.append('\b');
                } else if (escaped == 'f') {
                    value.append('\f');
                } else if (escaped == 'n') {
                    value.append('\n');
                } else if (escaped == 'r') {
                    value.append('\r');
                } else if (escaped == 't') {
                    value.append('\t');
                } else {
                    throw new IllegalArgumentException("Invalid JOSE header JSON escape.");
                }
                index += 2;
                continue;
            }
            value.append(current);
            index++;
        }
        throw new IllegalArgumentException("Invalid JOSE header JSON.");
    }

    private static int skipWhitespace(String value, int index) {
        while (index < value.length() && Character.isWhitespace(value.charAt(index))) {
            index++;
        }
        return index;
    }

    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static final class ParsedString {
        private final String value;
        private final int nextIndex;

        private ParsedString(String value, int nextIndex) {
            this.value = value;
            this.nextIndex = nextIndex;
        }
    }
}
