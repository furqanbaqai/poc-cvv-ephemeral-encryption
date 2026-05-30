package com.openfintechlab.jwe.model;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * JWK-style RSA public key fields used by the reveal request.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class EphemeralPublicKey {
    private String kty;
    private String use;
    private String alg;
    private String n;
    private String e;
    private String privateKey;

    /**
     * Creates an empty key model for JSON serialization frameworks.
     */
    public EphemeralPublicKey() {
    }

    private EphemeralPublicKey(Builder builder) {
        this.kty = builder.kty;
        this.use = builder.use;
        this.alg = builder.alg;
        this.n = builder.n;
        this.e = builder.e;
        this.privateKey = builder.privateKey;
    }

    public String getKty() {
        return kty;
    }

    public void setKty(String kty) {
        this.kty = kty;
    }

    public String getUse() {
        return use;
    }

    public void setUse(String use) {
        this.use = use;
    }

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public String getN() {
        return n;
    }

    public void setN(String n) {
        this.n = n;
    }

    public String getE() {
        return e;
    }

    public void setE(String e) {
        this.e = e;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * Creates a builder for {@link EphemeralPublicKey}.
     *
     * @return builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link EphemeralPublicKey}.
     */
    public static final class Builder {
        private String kty;
        private String use;
        private String alg;
        private String n;
        private String e;
        private String privateKey;

        private Builder() {
        }

        public Builder kty(String kty) {
            this.kty = kty;
            return this;
        }

        public Builder use(String use) {
            this.use = use;
            return this;
        }

        public Builder alg(String alg) {
            this.alg = alg;
            return this;
        }

        public Builder n(String n) {
            this.n = n;
            return this;
        }

        public Builder e(String e) {
            this.e = e;
            return this;
        }

        public Builder privateKey(String privateKey) {
            this.privateKey = privateKey;
            return this;
        }

        public EphemeralPublicKey build() {
            return new EphemeralPublicKey(this);
        }
    }
}
