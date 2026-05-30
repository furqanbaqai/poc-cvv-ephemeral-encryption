package com.openfintechlab.jwe.model;

/**
 * Request payload sent by the mobile device to reveal an ephemeral encryption
 * public key.
 */
public class RevealRequest {
    private String requestId;
    private String cardRef;
    private String channel;
    private EphemeralPublicKey ephemeralPublicKey;

    /**
     * Creates an empty request model for JSON serialization frameworks.
     */
    public RevealRequest() {
    }

    private RevealRequest(Builder builder) {
        this.requestId = builder.requestId;
        this.cardRef = builder.cardRef;
        this.channel = builder.channel;
        this.ephemeralPublicKey = builder.ephemeralPublicKey;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public String getCardRef() {
        return cardRef;
    }

    public void setCardRef(String cardRef) {
        this.cardRef = cardRef;
    }

    public String getChannel() {
        return channel;
    }

    public void setChannel(String channel) {
        this.channel = channel;
    }

    public EphemeralPublicKey getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public void setEphemeralPublicKey(EphemeralPublicKey ephemeralPublicKey) {
        this.ephemeralPublicKey = ephemeralPublicKey;
    }

    /**
     * Creates a builder for {@link RevealRequest}.
     *
     * @return builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link RevealRequest}.
     */
    public static final class Builder {
        private String requestId;
        private String cardRef;
        private String channel;
        private EphemeralPublicKey ephemeralPublicKey;

        private Builder() {
        }

        public Builder requestId(String requestId) {
            this.requestId = requestId;
            return this;
        }

        public Builder cardRef(String cardRef) {
            this.cardRef = cardRef;
            return this;
        }

        public Builder channel(String channel) {
            this.channel = channel;
            return this;
        }

        public Builder ephemeralPublicKey(EphemeralPublicKey ephemeralPublicKey) {
            this.ephemeralPublicKey = ephemeralPublicKey;
            return this;
        }

        public RevealRequest build() {
            return new RevealRequest(this);
        }
    }
}
