import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  PROTECTED_HEADER,
  buildJwe,
  createPayload,
  encryptContent,
  encryptKey,
  extractPublicKey,
  generateCek,
  generateIv,
  secureClear,
  validateInput,
} from "../src/step2_encrypt.js";

const TEST_INPUT =
  '{"requestId":"ed2e74ce3c26453a97b14d8bebac8ded","cardRef":"4012 8888 8888 1881","channel":"mobile","ephemeralPublicKey":{"kty":"RSA","use":"enc","alg":"RSA-OAEP-256","n":"51FePt844iEDXaYRW84puEUJU7m9cBR5qApPYQEizBthvr7wdBTz4U3xEYyjLSstwCBoXLC5DSPJtK7ZppO6C2fNMzrx7CP3bWJfQmrXOnXiCVOEj3Ib984-yDmdDDs6dp9ZajKtYNVyJSxs6nQwJVbOpRf8tQCrNsr9jb90lCunwW6nXYpSP4NbhfBrN2GgMstEwmF-XQOjNoTBb2yegC8yN9aahpk13kkoKpvYuKAb9lqGX0--d8IfY_G25QhE8Nkop2JIZrRj_Gz2ztVm1NlFo_f-qyVNuAiy94T9bnRysXRGrmHBYULL6_z6IB2xcXTkGdUzvADkU68d_Hmtnw","e":"AQAB"}}';
const POWERSHELL_STRIPPED_TEST_INPUT =
  "{requestId:ed2e74ce3c26453a97b14d8bebac8ded,cardRef:4012 8888 8888 1881,channel:mobile,ephemeralPublicKey:{kty:RSA,use:enc,alg:RSA-OAEP-256,n:51FePt844iEDXaYRW84puEUJU7m9cBR5qApPYQEizBthvr7wdBTz4U3xEYyjLSstwCBoXLC5DSPJtK7ZppO6C2fNMzrx7CP3bWJfQmrXOnXiCVOEj3Ib984-yDmdDDs6dp9ZajKtYNVyJSxs6nQwJVbOpRf8tQCrNsr9jb90lCunwW6nXYpSP4NbhfBrN2GgMstEwmF-XQOjNoTBb2yegC8yN9aahpk13kkoKpvYuKAb9lqGX0--d8IfY_G25QhE8Nkop2JIZrRj_Gz2ztVm1NlFo_f-qyVNuAiy94T9bnRysXRGrmHBYULL6_z6IB2xcXTkGdUzvADkU68d_Hmtnw,e:AQAB}}";

function base64urlDecodeToString(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
  return Buffer.from(padded, "base64").toString("utf8");
}

describe("step2_encrypt CLI", () => {
  it("encrypts the provided reveal request as compact JWE", async () => {
    const input = validateInput(TEST_INPUT);
    const publicKey = extractPublicKey(input.ephemeralPublicKey);
    const payload = createPayload(input.cardRef);
    const cek = generateCek();

    try {
      const iv = generateIv();
      const encryptedKey = encryptKey(cek, publicKey);
      const { ciphertext, tag } = encryptContent(payload, cek, iv);
      const jwe = buildJwe(PROTECTED_HEADER, encryptedKey, iv, ciphertext, tag);
      const parts = jwe.split(".");

      assert.equal(parts.length, 5);
      for (const part of parts) {
        assert.match(part, /^[A-Za-z0-9_-]+$/);
      }

      const protectedHeader = JSON.parse(base64urlDecodeToString(parts[0]));

      assert.deepEqual(protectedHeader, {
        alg: "RSA-OAEP-256",
        enc: "A256GCM",
        typ: "JWE",
        cty: "json",
        kid: "ephemeral-key",
        iat: 1775901000,
      });
    } finally {
      secureClear(cek);
    }
  });

  it("rejects malformed JSON input", async () => {
    assert.throws(() => validateInput("{bad json}"), /Invalid JSON input/);
  });

  it("accepts JSON after legacy Windows PowerShell strips embedded quotes", async () => {
    const input = validateInput(POWERSHELL_STRIPPED_TEST_INPUT);

    assert.equal(input.requestId, "ed2e74ce3c26453a97b14d8bebac8ded");
    assert.equal(input.cardRef, "4012 8888 8888 1881");
    assert.equal(input.channel, "mobile");
    assert.deepEqual(input.ephemeralPublicKey, {
      kty: "RSA",
      use: "enc",
      alg: "RSA-OAEP-256",
      n: "51FePt844iEDXaYRW84puEUJU7m9cBR5qApPYQEizBthvr7wdBTz4U3xEYyjLSstwCBoXLC5DSPJtK7ZppO6C2fNMzrx7CP3bWJfQmrXOnXiCVOEj3Ib984-yDmdDDs6dp9ZajKtYNVyJSxs6nQwJVbOpRf8tQCrNsr9jb90lCunwW6nXYpSP4NbhfBrN2GgMstEwmF-XQOjNoTBb2yegC8yN9aahpk13kkoKpvYuKAb9lqGX0--d8IfY_G25QhE8Nkop2JIZrRj_Gz2ztVm1NlFo_f-qyVNuAiy94T9bnRysXRGrmHBYULL6_z6IB2xcXTkGdUzvADkU68d_Hmtnw",
      e: "AQAB",
    });
  });
});
