import { randomUUID, webcrypto } from "node:crypto";
import { fileURLToPath } from "node:url";


const { subtle } = webcrypto;

const RSA_OAEP_ALGORITHM = {
  name: "RSA-OAEP",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

export async function generateEphemeralKeyPair() {
  const { publicKey, privateKey } = await subtle.generateKey(
    RSA_OAEP_ALGORITHM,
    true,
    ["encrypt", "decrypt"]
  );

  return { publicKey, privateKey };
}

export async function generateRevealRequest(
  cardRef = "4012 8888 8888 1881",
  { debug = false } = {}
) {
  const { publicKey, privateKey } = await generateEphemeralKeyPair();
  const exportedPublicKey = await subtle.exportKey("jwk", publicKey);
  const exportedPrivateKey = debug
    ? await subtle.exportKey("jwk", privateKey)
    : undefined;

  const request = {
    requestId: randomUUID().replaceAll("-", ""),
    cardRef,
    channel: "mobile",
    ephemeralPublicKey: {
      kty: "RSA",
      use: "enc",
      alg: "RSA-OAEP-256",
      n: exportedPublicKey.n,
      e: "AQAB",
    },
  };

  if (debug) {
    request.ephemeralPublicKey.d = exportedPrivateKey.d;
  }

  return request;
}

export async function displayRevealRequest(cardRef, options) {
  const request = await generateRevealRequest(cardRef, options);
  console.log(JSON.stringify(request, null, 2));
  return request;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const debug = process.argv.slice(2).includes("debug");

  displayRevealRequest(undefined, { debug }).catch((error) => {
    console.error("Error generating reveal request:", error);
    process.exitCode = 1;
  });
}
