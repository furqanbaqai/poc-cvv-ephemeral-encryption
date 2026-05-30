#!/usr/bin/env node
'use strict';

import crypto from "node:crypto";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const VERSION = '1.0.0';
const MAX_INPUT_BYTES = 8 * 1024;

const PROTECTED_HEADER = Object.freeze({
  alg: 'RSA-OAEP-256',
  enc: 'A256GCM',
  typ: 'JWE',
  cty: 'json',
  kid: 'ephemeral-key',
  iat: 1775901000,
});

const PAYLOAD_IAT = 1775901000;
const PAYLOAD_EXP = 1775901030;

/**
 * Encodes bytes using RFC 4648 base64url without padding.
 *
 * @param {Buffer|string} value - Bytes or UTF-8 string to encode.
 * @returns {string} Base64url encoded value.
 */
function base64urlEncode(value) {
  return Buffer.from(value)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/**
 * Parses and validates the single JSON command-line input.
 *
 * @param {string} jsonString - JSON string supplied as the only positional argument.
 * @returns {object} Parsed JSON object.
 * @throws {Error} When the input is missing, too large, malformed, or not an object.
 */
function validateInput(jsonString) {
  if (typeof jsonString !== 'string' || jsonString.length === 0) {
    throw new Error("Missing JSON input. Usage: node ./src/step2_encrypt.js '<json-input>'");
  }

  const trimmedJsonString = jsonString.trim();

  if (Buffer.byteLength(trimmedJsonString, 'utf8') > MAX_INPUT_BYTES) {
    throw new Error('Input JSON exceeds the 8KB maximum size limit');
  }

  let parsed;
  try {
    parsed = JSON.parse(trimmedJsonString);
  } catch {
    parsed = parsePowerShellStrippedJson(trimmedJsonString);
  }

  if (parsed === null || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error('Input JSON must be an object');
  }

  return parsed;
}

/**
 * Parses the object-like argument produced by legacy Windows PowerShell when
 * embedded JSON quotes are stripped before the value reaches Node.js.
 *
 * This is intentionally narrow: it accepts only the reveal request shape used by
 * this CLI, where all leaf values are strings and nested objects use braces.
 *
 * @param {string} input - PowerShell-stripped JSON-like object text.
 * @returns {object} Parsed object.
 * @throws {Error} When the input is not in the supported stripped format.
 */
function parsePowerShellStrippedJson(input) {
  try {
    const parsed = parsePowerShellObject(input);
    if (parsed === null || Array.isArray(parsed) || typeof parsed !== 'object') {
      throw new Error('not an object');
    }
    return parsed;
  } catch {
    throw new Error(
      'Invalid JSON input. If you are using Windows PowerShell, pass "$request" in quotes or pipe JSON to stdin.',
    );
  }
}

/**
 * Recursively parses a simple comma-separated object where keys and string
 * values are unquoted, for example {requestId:abc,ephemeralPublicKey:{e:AQAB}}.
 *
 * @param {string} input - Stripped object text.
 * @returns {object} Parsed object.
 */
function parsePowerShellObject(input) {
  if (!input.startsWith('{') || !input.endsWith('}')) {
    throw new Error('expected object');
  }

  const body = input.slice(1, -1);
  const result = {};

  if (body.trim().length === 0) {
    return result;
  }

  for (const pair of splitTopLevel(body, ',')) {
    const separatorIndex = findTopLevelSeparator(pair, ':');
    if (separatorIndex <= 0) {
      throw new Error('expected key-value pair');
    }

    const key = pair.slice(0, separatorIndex).trim();
    const rawValue = pair.slice(separatorIndex + 1).trim();

    if (!/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(key) || rawValue.length === 0) {
      throw new Error('invalid key-value pair');
    }

    result[key] = rawValue.startsWith('{') ? parsePowerShellObject(rawValue) : rawValue;
  }

  return result;
}

/**
 * Splits text on a delimiter only when not nested inside braces.
 *
 * @param {string} input - Text to split.
 * @param {string} delimiter - Single-character delimiter.
 * @returns {string[]} Top-level segments.
 */
function splitTopLevel(input, delimiter) {
  const parts = [];
  let depth = 0;
  let start = 0;

  for (let index = 0; index < input.length; index += 1) {
    const char = input[index];

    if (char === '{') {
      depth += 1;
    } else if (char === '}') {
      depth -= 1;
      if (depth < 0) {
        throw new Error('unbalanced braces');
      }
    } else if (char === delimiter && depth === 0) {
      parts.push(input.slice(start, index));
      start = index + 1;
    }
  }

  if (depth !== 0) {
    throw new Error('unbalanced braces');
  }

  parts.push(input.slice(start));
  return parts;
}

/**
 * Finds a separator character outside nested braces.
 *
 * @param {string} input - Text to inspect.
 * @param {string} separator - Single-character separator.
 * @returns {number} Separator index, or -1 when not found.
 */
function findTopLevelSeparator(input, separator) {
  let depth = 0;

  for (let index = 0; index < input.length; index += 1) {
    const char = input[index];

    if (char === '{') {
      depth += 1;
    } else if (char === '}') {
      depth -= 1;
      if (depth < 0) {
        throw new Error('unbalanced braces');
      }
    } else if (char === separator && depth === 0) {
      return index;
    }
  }

  if (depth !== 0) {
    throw new Error('unbalanced braces');
  }

  return -1;
}

/**
 * Converts a base64url encoded string to a Buffer.
 *
 * @param {string} value - Base64url encoded value.
 * @returns {Buffer} Decoded bytes.
 * @throws {Error} When the value is not valid base64url.
 */
function base64urlDecode(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('Invalid JWK format: modulus and exponent must be base64url strings');
  }

  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  return Buffer.from(padded, 'base64');
}

/**
 * Imports and validates an RSA public JWK for RSA-OAEP-256 encryption.
 *
 * @param {object} jwk - JWK public key object.
 * @returns {crypto.KeyObject} Imported RSA public key.
 * @throws {Error} When the JWK is missing, invalid, too small, or cannot be imported.
 */
function extractPublicKey(jwk) {
  if (jwk === null || Array.isArray(jwk) || typeof jwk !== 'object') {
    throw new Error('Missing or invalid ephemeralPublicKey: expected a JWK object');
  }

  if (jwk.kty !== 'RSA') {
    throw new Error('Invalid JWK format: kty must be "RSA"');
  }

  if (jwk.alg !== 'RSA-OAEP-256') {
    throw new Error('Invalid JWK format: alg must be "RSA-OAEP-256"');
  }

  if (typeof jwk.n !== 'string' || jwk.n.length === 0) {
    throw new Error('Invalid JWK format: missing RSA modulus "n"');
  }

  if (typeof jwk.e !== 'string' || jwk.e.length === 0) {
    throw new Error('Invalid JWK format: missing RSA exponent "e"');
  }

  const modulus = base64urlDecode(jwk.n);
  const modulusBits = modulus.length * 8 - countLeadingZeroBits(modulus);
  if (modulusBits < 2048) {
    throw new Error('Invalid JWK format: RSA modulus must be at least 2048 bits');
  }

  let publicKey;
  try {
    publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  } catch {
    throw new Error('Failed to import RSA public key from JWK');
  }

  if (publicKey.asymmetricKeyType !== 'rsa') {
    throw new Error('Invalid JWK format: imported key is not RSA');
  }

  return publicKey;
}

/**
 * Counts leading zero bits in a Buffer for accurate modulus size validation.
 *
 * @param {Buffer} buffer - Buffer to inspect.
 * @returns {number} Number of leading zero bits.
 */
function countLeadingZeroBits(buffer) {
  let bits = 0;

  for (const byte of buffer) {
    if (byte === 0) {
      bits += 8;
      continue;
    }

    for (let mask = 0x80; mask > 0; mask >>= 1) {
      if ((byte & mask) !== 0) {
        return bits;
      }
      bits += 1;
    }
  }

  return bits;
}

/**
 * Generates a random 256-bit content encryption key.
 *
 * @returns {Buffer} Random 32-byte CEK.
 */
function generateCek() {
  return crypto.randomBytes(32);
}

/**
 * Generates a random 96-bit IV for AES-GCM.
 *
 * @returns {Buffer} Random 12-byte IV.
 */
function generateIv() {
  return crypto.randomBytes(12);
}

/**
 * Builds the fixed payment-card payload using the normalized PAN.
 *
 * @param {string} cardRef - Card reference string from input.
 * @returns {object} JWE plaintext payload object.
 * @throws {Error} When cardRef is missing, empty, or payload times are invalid.
 */
function createPayload(cardRef) {
  if (typeof cardRef !== 'string' || cardRef.trim().length === 0) {
    throw new Error('Missing or invalid cardRef: expected a non-empty string');
  }

  const normalizedCardRef = cardRef.replace(/\s+/g, '');
  if (normalizedCardRef.length === 0) {
    throw new Error('Missing or invalid cardRef: expected a non-empty string');
  }

  const payload = {
    cardRef: normalizedCardRef,
    pan: normalizedCardRef,
    expiryMonth: '12',
    expiryYear: '29',
    cvv: '123',
    iat: PAYLOAD_IAT,
    exp: PAYLOAD_EXP,
    jti: 'reveal-8f3a1c',
  };

  if (payload.exp <= payload.iat) {
    throw new Error('Invalid payload timestamps: exp must be greater than iat');
  }

  return payload;
}

/**
 * Wraps the CEK with RSA-OAEP using SHA-256 as required by RSA-OAEP-256.
 *
 * @param {Buffer} cek - Content encryption key.
 * @param {crypto.KeyObject} publicKey - RSA public key.
 * @returns {Buffer} RSA-encrypted CEK.
 * @throws {Error} When key wrapping fails.
 */
function encryptKey(cek, publicKey) {
  try {
    return crypto.publicEncrypt(
      {
        key: publicKey,
        oaepHash: 'sha256',
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      },
      cek,
    );
  } catch {
    throw new Error('Encryption failure: failed to wrap CEK with RSA-OAEP-256');
  }
}

/**
 * Encrypts the payload with AES-256-GCM.
 *
 * @param {object} payload - Payload object to encrypt.
 * @param {Buffer} cek - 256-bit content encryption key.
 * @param {Buffer} iv - 96-bit AES-GCM initialization vector.
 * @returns {{ciphertext: Buffer, tag: Buffer}} Ciphertext and 128-bit authentication tag.
 * @throws {Error} When content encryption fails.
 */
function encryptContent(payload, cek, iv) {
  try {
    // AES-256-GCM provides authenticated encryption; the empty AAD matches this prompt's compact JWE requirement.
    const cipher = crypto.createCipheriv('aes-256-gcm', cek, iv);
    cipher.setAAD(Buffer.alloc(0));

    const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    return { ciphertext, tag };
  } catch {
    throw new Error('Encryption failure: failed to encrypt payload with AES-256-GCM');
  }
}

/**
 * Builds a compact JWE string from its five encoded parts.
 *
 * @param {object} protectedHeader - Protected JWE header.
 * @param {Buffer} encryptedKey - RSA-encrypted CEK.
 * @param {Buffer} iv - AES-GCM IV.
 * @param {Buffer} ciphertext - AES-GCM ciphertext.
 * @param {Buffer} tag - AES-GCM authentication tag.
 * @returns {string} JWE compact serialization.
 */
function buildJwe(protectedHeader, encryptedKey, iv, ciphertext, tag) {
  return [
    base64urlEncode(JSON.stringify(protectedHeader)),
    base64urlEncode(encryptedKey),
    base64urlEncode(iv),
    base64urlEncode(ciphertext),
    base64urlEncode(tag),
  ].join('.');
}

/**
 * Clears a sensitive Buffer in place.
 *
 * @param {Buffer|undefined} buffer - Sensitive buffer to clear.
 * @returns {void}
 */
function secureClear(buffer) {
  if (Buffer.isBuffer(buffer)) {
    buffer.fill(0);
  }
}

/**
 * Prints CLI help text.
 *
 * @returns {void}
 */
function printHelp() {
  process.stdout.write("Usage: node ./src/step2_encrypt.js '<json-input>'\n");
  process.stdout.write("   or: '<json-input>' | node ./src/step2_encrypt.js\n");
}

/**
 * Runs the command-line application.
 *
 * @returns {void}
 */
function main() {
  let cek;

  try {
    const args = process.argv.slice(2);

    if (args.length === 1 && (args[0] === '--help' || args[0] === '-h')) {
      printHelp();
      return;
    }

    if (args.length === 1 && (args[0] === '--version' || args[0] === '-v')) {
      process.stdout.write(`${VERSION}\n`);
      return;
    }

    if (args.length > 1) {
      throw new Error("Expected exactly one positional JSON argument. Usage: node ./src/step2_encrypt.js '<json-input>'");
    }

    const jsonInput = args.length === 1
      ? args[0]
      : (process.stdin.isTTY
        ? ''
        : fs.readFileSync(0, 'utf8'));
    const input = validateInput(jsonInput);
    const publicKey = extractPublicKey(input.ephemeralPublicKey);
    const payload = createPayload(input.cardRef);

    cek = generateCek();
    const iv = generateIv();
    const encryptedKey = encryptKey(cek, publicKey);
    const { ciphertext, tag } = encryptContent(payload, cek, iv);
    const jwe = buildJwe(PROTECTED_HEADER, encryptedKey, iv, ciphertext, tag);

    process.stdout.write(`${jwe}\n`);
  } catch (error) {
    process.stderr.write(`${error.message || 'Unexpected encryption failure'}\n`);
    process.exitCode = 1;
  } finally {
    secureClear(cek);
  }
}

export {
  PROTECTED_HEADER,
  base64urlEncode,
  buildJwe,
  createPayload,
  encryptContent,
  encryptKey,
  extractPublicKey,
  findTopLevelSeparator,
  generateCek,
  generateIv,
  parsePowerShellObject,
  parsePowerShellStrippedJson,
  secureClear,
  splitTopLevel,
  validateInput,
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main();
}
