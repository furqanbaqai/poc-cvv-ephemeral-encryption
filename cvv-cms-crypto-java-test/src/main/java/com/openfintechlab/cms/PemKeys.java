package com.openfintechlab.cms;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

final class PemKeys {
    private PemKeys() {
    }

    static PublicKey parsePublicKey(String publicKeyPem) throws Exception {
        String keyBody = publicKeyPem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("\\n", "")
                .replaceAll("\\s", "");

        byte[] encodedKey = Base64.getDecoder().decode(keyBody);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encodedKey));
    }

    static PrivateKey parsePrivateKey(String privateKeyPem) throws Exception {
        String keyBody = privateKeyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("\\n", "")
                .replaceAll("\\s", "");

        byte[] encodedKey = Base64.getDecoder().decode(keyBody);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
    }
}
