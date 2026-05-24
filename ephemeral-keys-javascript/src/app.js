import { webcrypto } from "node:crypto";


const { subtle } = webcrypto;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const RSA_OAEP_ALGORITHM = {
  name: "RSA-OAEP",
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

function bytesToBase64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function base64UrlToBytes(value) {
  return Buffer.from(value, "base64url");
}

function bytesToPem(label, bytes) {
  const base64 = Buffer.from(bytes).toString("base64");
  const lines = base64.match(/.{1,64}/g) ?? [];

  return [
    `-----BEGIN ${label}-----`,
    ...lines,
    `-----END ${label}-----`,
  ].join("\n");
}

export async function generateEphemeralKeyPair() {
  const { publicKey, privateKey } = await subtle.generateKey(
    RSA_OAEP_ALGORITHM,
    true,
    ["encrypt", "decrypt"]
  );

  return { publicKey, privateKey };
}


// Console sout for analysis only, not used in the actual flow of the application
console.log("Generating ephemeral key pair...");
generateEphemeralKeyPair()
  .then(async ({ publicKey, privateKey }) => {
    const exportedPublicKey = await subtle.exportKey("spki", publicKey);
    const exportedPrivateKey = await subtle.exportKey("pkcs8", privateKey);

    console.log("Public Key (base64 encoded):", bytesToBase64Url(new Uint8Array(exportedPublicKey)));
    console.log("[CLS]"); 
    console.log("Private Key (base64 encoded):", bytesToBase64Url(new Uint8Array(exportedPrivateKey)));

    console.log("Public Key (PEM/SPKI):\n", bytesToPem("PUBLIC KEY", exportedPublicKey));
    console.log("Private Key (PEM/PKCS8):\n", bytesToPem("PRIVATE KEY", exportedPrivateKey));
  })
  .catch((error) => {
    console.error("Error generating ephemeral key pair:", error);
  });
// END;