import assert from "node:assert/strict";
import crypto from "node:crypto";
import { describe, it } from "node:test";

import { generateRevealRequest } from "../src/step1_reveal.js";

describe("generateRevealRequest", () => {
  it("generates the reveal request JSON with defaults", async () => {
    const request = await generateRevealRequest();

    assert.match(request.requestId, /^[0-9a-f]{32}$/);
    assert.equal(request.cardRef, "4012 8888 8888 1881");
    assert.equal(request.channel, "mobile");
    assert.deepEqual(
      {
        kty: request.ephemeralPublicKey.kty,
        use: request.ephemeralPublicKey.use,
        alg: request.ephemeralPublicKey.alg,
        e: request.ephemeralPublicKey.e,
      },
      {
        kty: "RSA",
        use: "enc",
        alg: "RSA-OAEP-256",
        e: "AQAB",
      }
    );
    assert.match(request.ephemeralPublicKey.n, /^[A-Za-z0-9_-]+$/);
    assert.equal(Object.hasOwn(request.ephemeralPublicKey, "d"), false);
    assert.equal(Object.hasOwn(request.ephemeralPublicKey, "privateKey"), false);
  });

  it("allows overriding the card reference", async () => {
    const request = await generateRevealRequest("card_12345");

    assert.equal(request.cardRef, "card_12345");
  });

  it("includes the full PEM private key only when debug is enabled", async () => {
    const request = await generateRevealRequest(undefined, { debug: true });
    const privateKey = crypto.createPrivateKey(request.ephemeralPublicKey.privateKey);

    assert.equal(Object.hasOwn(request.ephemeralPublicKey, "d"), false);
    assert.match(
      request.ephemeralPublicKey.privateKey,
      /^-----BEGIN PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+-----END PRIVATE KEY-----$/,
    );
    assert.equal(privateKey.type, "private");
    assert.equal(privateKey.asymmetricKeyType, "rsa");
    assert.equal(privateKey.asymmetricKeyDetails.modulusLength, 2048);
  });
});
