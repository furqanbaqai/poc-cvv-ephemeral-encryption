package com.openfintechlab.jwe.util;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * JSON serialization utility for CLI output.
 */
public final class JsonUtil {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    private JsonUtil() {
    }

    /**
     * Serializes an object as minified JSON.
     *
     * @param object object to serialize
     * @return minified JSON string
     * @throws JsonProcessingException when serialization fails
     */
    public static String toMinifiedJson(Object object) throws JsonProcessingException {
        return OBJECT_MAPPER.writeValueAsString(object);
    }
}
