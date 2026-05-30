package com.openfintechlab.jwe.util;

import com.openfintechlab.jwe.model.EphemeralPublicKey;
import com.openfintechlab.jwe.model.RevealRequest;

/**
 * JSON serialization utility for CLI output.
 */
public final class JsonUtil {
    private JsonUtil() {
    }

    /**
     * Serializes a supported project model as minified JSON.
     *
     * @param object object to serialize
     * @return minified JSON string
     */
    public static String toMinifiedJson(Object object) {
        if (object instanceof RevealRequest revealRequest) {
            return toRevealRequestJson(revealRequest);
        }

        if (object instanceof EphemeralPublicKey ephemeralPublicKey) {
            return toEphemeralPublicKeyJson(ephemeralPublicKey);
        }

        throw new IllegalArgumentException("Unsupported JSON object type: " + object.getClass().getName());
    }

    private static String toRevealRequestJson(RevealRequest request) {
        return "{"
                + jsonField("requestId", request.getRequestId()) + ","
                + jsonField("cardRef", request.getCardRef()) + ","
                + jsonField("channel", request.getChannel()) + ","
                + "\"ephemeralPublicKey\":" + toEphemeralPublicKeyJson(request.getEphemeralPublicKey())
                + "}";
    }

    private static String toEphemeralPublicKeyJson(EphemeralPublicKey key) {
        StringBuilder json = new StringBuilder()
                .append("{")
                .append(jsonField("kty", key.getKty())).append(",")
                .append(jsonField("use", key.getUse())).append(",")
                .append(jsonField("alg", key.getAlg())).append(",")
                .append(jsonField("n", key.getN())).append(",")
                .append(jsonField("e", key.getE()));

        if (key.getPrivateKey() != null) {
            json.append(",").append(jsonField("privateKey", key.getPrivateKey()));
        }

        return json.append("}").toString();
    }

    private static String jsonField(String name, String value) {
        return "\"" + escapeJson(name) + "\":\"" + escapeJson(value) + "\"";
    }

    private static String escapeJson(String value) {
        StringBuilder escaped = new StringBuilder(value.length() + 16);

        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"' -> escaped.append("\\\"");
                case '\\' -> escaped.append("\\\\");
                case '\b' -> escaped.append("\\b");
                case '\f' -> escaped.append("\\f");
                case '\n' -> escaped.append("\\n");
                case '\r' -> escaped.append("\\r");
                case '\t' -> escaped.append("\\t");
                default -> {
                    if (character < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) character));
                    } else {
                        escaped.append(character);
                    }
                }
            }
        }

        return escaped.toString();
    }
}
