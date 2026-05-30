#!/usr/bin/env node
'use strict';

// ============================================
// step3_decryptjwe.js
// JWE Decryption CLI for ephemeral-keys-javascript
// ============================================

import crypto from 'node:crypto';

const VERSION = '1.0.0';
const MAX_JWE_BYTES = 64 * 1024;
const SUPPORTED_ALG = 'RSA-OAEP-256';
const SUPPORTED_ENC = 'A256GCM';
const EXPECTED_KID = 'ephemeral-key';
const CEK_BYTES = 32;
const IV_BYTES = 12;
const AUTH_TAG_BYTES = 16;
const MIN_RSA_BITS = 2048;

/**
 * Prints CLI usage help.
 *
 * @returns {void}
 */
function printHelp() {
  process.stdout.write(`Usage: node ./src/step3_decryptjwe.js '<jwe-token>' '<private-key>'

Decrypts a JWE compact serialization token using an RSA private key.

Arguments:
  jwe-token      JWE compact serialization string (5 base64url segments)
  private-key    RSA private key in PEM or JWK format

Options:
  --help         Show this help message
  --version      Show version number

Examples:
  node ./src/step3_decryptjwe.js 'eyJhbGciOi...' '-----BEGIN PRIVATE KEY-----\\n...'
  node ./src/step3_decryptjwe.js 'eyJhbGciOi...' '{"kty":"RSA","d":"..."}'

Supported algorithms: RSA-OAEP-256, A256GCM
`);
}

/**
 * Removes dangerous control characters from CLI input while preserving PEM line
 * breaks after literal "\n" conversion.
 *
 * @param {string} value - Raw CLI value.
 * @param {object} options - Sanitization options.
 * @param {boolean} options.allowNewlines - Whether CR/LF/TAB should be preserved.
 * @returns {string} Sanitized and trimmed value.
 */
function sanitizeInput(value, { allowNewlines = false } = {}) {
  const pattern = allowNewlines ? /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g : /[\x00-\x1F\x7F]/g;
  return value.replace(pattern, '').trim();
}

/**
 * Decodes RFC 4648 base64url text into bytes.
 *
 * @param {string} str - Base64url string without padding.
 * @returns {Buffer} Decoded bytes.
 * @throws {Error} When the value is empty or contains invalid characters.
 */
function base64urlDecode(str) {
  if (typeof str !== 'string' || str.length === 0 || !/^[A-Za-z0-9_-]+$/.test(str)) {
    throw new Error('Invalid JWE compact serialization format');
  }

  if (str.length % 4 === 1) {
    throw new Error('Invalid JWE compact serialization format');
  }

  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  return Buffer.from(padded, 'base64');
}

/**
 * Encodes bytes using base64url without padding.
 *
 * @param {Buffer|string} value - Bytes or UTF-8 string.
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
 * Validates CLI arguments and returns sanitized positional values.
 *
 * @param {string[]} argv - Positional CLI arguments.
 * @returns {{jweToken: string, privateKeyString: string}} Sanitized arguments.
 * @throws {Error} When the required two arguments are missing or empty.
 */
function validateArgs(argv) {
  if (argv.length !== 2) {
    throw new Error('Two arguments required: <jwe-token> <private-key>');
  }

  const jweToken = sanitizeInput(argv[0]);
  const privateKeyString = sanitizeInput(argv[1].replace(/\\n/g, '\n'), { allowNewlines: true });

  if (jweToken.length === 0 || privateKeyString.length === 0) {
    throw new Error('Arguments must not be empty or whitespace-only');
  }

  if (Buffer.byteLength(jweToken, 'utf8') > MAX_JWE_BYTES) {
    throw new Error('Invalid JWE compact serialization format');
  }

  return { jweToken, privateKeyString };
}

/**
 * Detects whether a private key argument is PEM or JWK JSON.
 *
 * @param {string} keyString - Sanitized private key input.
 * @returns {'pem'|'jwk'} Detected key format.
 * @throws {Error} When the format cannot be detected.
 */
function detectKeyFormat(keyString) {
  if (/^-----BEGIN (?:RSA )?PRIVATE KEY-----/.test(keyString)) {
    return 'pem';
  }

  if (keyString.startsWith('{')) {
    return 'jwk';
  }

  throw new Error('Invalid private key: expected PEM or JWK JSON');
}

/**
 * Parses and validates an RSA private key from PEM or JWK JSON.
 *
 * @param {string} keyString - Sanitized private key string.
 * @returns {crypto.KeyObject} RSA private key object.
 * @throws {Error} When the key is malformed, non-RSA, or below 2048 bits.
 */
function parsePrivateKey(keyString) {
  const normalizedKeyString = sanitizeInput(keyString.replace(/\\n/g, '\n'), { allowNewlines: true });
  const format = detectKeyFormat(normalizedKeyString);

  if (format === 'pem') {
    return parsePemPrivateKey(normalizedKeyString);
  }

  return parseJwkPrivateKey(normalizedKeyString);
}

/**
 * Parses an RSA private key from PEM.
 *
 * @param {string} pemString - PEM private key text.
 * @returns {crypto.KeyObject} RSA private key object.
 * @throws {Error} When the PEM key is invalid.
 */
function parsePemPrivateKey(pemString) {
  if (!/^-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]+-----END (?:RSA )?PRIVATE KEY-----$/.test(pemString)) {
    throw new Error('Invalid private key: PEM must use BEGIN PRIVATE KEY or BEGIN RSA PRIVATE KEY');
  }

  const pemBuffer = Buffer.from(pemString, 'utf8');
  try {
    const privateKey = crypto.createPrivateKey({ key: pemBuffer });
    validatePrivateKeyObject(privateKey, undefined);
    return privateKey;
  } catch (error) {
    if (error.message.startsWith('Invalid private key:')) {
      throw error;
    }
    throw new Error('Invalid private key: failed to parse PEM RSA private key');
  } finally {
    secureClear(pemBuffer);
  }
}

/**
 * Parses an RSA private key from JWK JSON.
 *
 * @param {string} jwkString - JWK JSON string.
 * @returns {crypto.KeyObject} RSA private key object.
 * @throws {Error} When the JWK key is invalid.
 */
function parseJwkPrivateKey(jwkString) {
  let jwk;
  let nBytes;
  let eBytes;
  let dBytes;

  try {
    jwk = JSON.parse(jwkString);
  } catch {
    throw new Error('Invalid private key: JWK must be valid JSON');
  }

  try {
    if (jwk === null || Array.isArray(jwk) || typeof jwk !== 'object') {
      throw new Error('JWK must be an object');
    }

    if (jwk.kty !== 'RSA') {
      throw new Error('JWK kty must be "RSA"');
    }

    for (const field of ['n', 'e', 'd']) {
      if (typeof jwk[field] !== 'string' || jwk[field].length === 0) {
        throw new Error(`JWK missing required RSA field "${field}"`);
      }
    }

    nBytes = decodeJwkField(jwk.n);
    eBytes = decodeJwkField(jwk.e);
    dBytes = decodeJwkField(jwk.d);

    const privateKey = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
    validatePrivateKeyObject(privateKey, nBytes);
    return privateKey;
  } catch (error) {
    if (error.message.startsWith('Invalid private key:')) {
      throw error;
    }
    throw new Error(`Invalid private key: ${error.message}`);
  } finally {
    secureClear(nBytes);
    secureClear(eBytes);
    secureClear(dBytes);
  }
}

/**
 * Decodes a JWK base64url field.
 *
 * @param {string} value - JWK base64url field value.
 * @returns {Buffer} Decoded bytes.
 * @throws {Error} When the field is not valid base64url.
 */
function decodeJwkField(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
    throw new Error('JWK RSA fields must be base64url strings');
  }

  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), '=');
  return Buffer.from(padded, 'base64');
}

/**
 * Validates a parsed private key object.
 *
 * @param {crypto.KeyObject} privateKey - Parsed key object.
 * @param {Buffer|undefined} modulusBytes - Optional decoded RSA modulus.
 * @returns {void}
 * @throws {Error} When the key is not an RSA private key or is too small.
 */
function validatePrivateKeyObject(privateKey, modulusBytes) {
  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'rsa') {
    throw new Error('Invalid private key: expected RSA private key');
  }

  const modulusBits = privateKey.asymmetricKeyDetails?.modulusLength
    ?? (modulusBytes ? countModulusBits(modulusBytes) : 0);

  if (modulusBits < MIN_RSA_BITS) {
    throw new Error(`Invalid private key: RSA key size must be at least ${MIN_RSA_BITS} bits`);
  }
}

/**
 * Counts significant bits in an RSA modulus buffer.
 *
 * @param {Buffer} modulus - RSA modulus bytes.
 * @returns {number} Number of significant bits.
 */
function countModulusBits(modulus) {
  let leadingZeroBits = 0;

  for (const byte of modulus) {
    if (byte === 0) {
      leadingZeroBits += 8;
      continue;
    }

    for (let mask = 0x80; mask > 0; mask >>= 1) {
      if ((byte & mask) !== 0) {
        return modulus.length * 8 - leadingZeroBits;
      }
      leadingZeroBits += 1;
    }
  }

  return 0;
}

/**
 * Parses and decodes a compact JWE token.
 *
 * @param {string} jweString - JWE compact serialization.
 * @returns {{header: object, encryptedKey: Buffer, iv: Buffer, ciphertext: Buffer, tag: Buffer}} Parsed JWE parts.
 * @throws {Error} When the compact serialization is invalid.
 */
function parseJwe(jweString) {
  if (Buffer.byteLength(jweString, 'utf8') > MAX_JWE_BYTES) {
    throw new Error('Invalid JWE compact serialization format');
  }

  const parts = jweString.split('.');
  if (parts.length !== 5 || parts.some((part) => part.length === 0)) {
    throw new Error('Invalid JWE compact serialization format');
  }

  const [protectedHeaderPart, encryptedKeyPart, ivPart, ciphertextPart, tagPart] = parts;

  let header;
  try {
    const headerJson = base64urlDecode(protectedHeaderPart).toString('utf8');
    header = JSON.parse(headerJson);
  } catch {
    throw new Error('Invalid JWE compact serialization format');
  }

  if (header === null || Array.isArray(header) || typeof header !== 'object') {
    throw new Error('Invalid JWE compact serialization format');
  }

  const encryptedKey = base64urlDecode(encryptedKeyPart);
  const iv = base64urlDecode(ivPart);
  const ciphertext = base64urlDecode(ciphertextPart);
  const tag = base64urlDecode(tagPart);

  if (iv.length !== IV_BYTES || tag.length !== AUTH_TAG_BYTES) {
    secureClear(encryptedKey);
    secureClear(iv);
    secureClear(ciphertext);
    secureClear(tag);
    throw new Error('Invalid JWE compact serialization format');
  }

  return { header, encryptedKey, iv, ciphertext, tag };
}

/**
 * Validates the protected JWE header against the supported algorithm whitelist.
 *
 * @param {object} header - Decoded protected header object.
 * @returns {void}
 * @throws {Error} When the header is unsupported or unsafe.
 */
function validateHeader(header) {
  if (header.alg !== SUPPORTED_ALG) {
    throw new Error(`Unsupported algorithm: ${header.alg}. Expected: ${SUPPORTED_ALG}`);
  }

  if (header.enc !== SUPPORTED_ENC) {
    throw new Error(`Unsupported encryption: ${header.enc}. Expected: ${SUPPORTED_ENC}`);
  }

  if (Object.hasOwn(header, 'zip')) {
    throw new Error('Unsupported compression: zip header is not allowed');
  }

  if (Object.hasOwn(header, 'kid') && !timingSafeStringEqual(String(header.kid), EXPECTED_KID)) {
    throw new Error(`Invalid key identifier: ${header.kid}. Expected: ${EXPECTED_KID}`);
  }
}

/**
 * Compares two strings in constant time after length normalization.
 *
 * @param {string} actual - Actual value.
 * @param {string} expected - Expected value.
 * @returns {boolean} Whether the strings are equal.
 */
function timingSafeStringEqual(actual, expected) {
  const actualBuffer = Buffer.from(actual, 'utf8');
  const expectedBuffer = Buffer.from(expected, 'utf8');
  const maxLength = Math.max(actualBuffer.length, expectedBuffer.length);
  const paddedActual = Buffer.alloc(maxLength);
  const paddedExpected = Buffer.alloc(maxLength);

  try {
    actualBuffer.copy(paddedActual);
    expectedBuffer.copy(paddedExpected);
    return crypto.timingSafeEqual(paddedActual, paddedExpected) && actualBuffer.length === expectedBuffer.length;
  } finally {
    secureClear(actualBuffer);
    secureClear(expectedBuffer);
    secureClear(paddedActual);
    secureClear(paddedExpected);
  }
}

/**
 * Decrypts the RSA-OAEP-256 wrapped Content Encryption Key.
 *
 * @param {Buffer} encryptedKey - RSA-encrypted CEK.
 * @param {crypto.KeyObject} privateKey - RSA private key.
 * @returns {Buffer} Decrypted 32-byte CEK.
 * @throws {Error} When key unwrapping fails or CEK length is invalid.
 */
function decryptCek(encryptedKey, privateKey) {
  let cek;

  try {
    cek = crypto.privateDecrypt(
      {
        key: privateKey,
        oaepHash: 'sha256',
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      },
      encryptedKey,
    );
  } catch {
    throw new Error('Failed to decrypt CEK - invalid private key or corrupted token');
  }

  if (cek.length !== CEK_BYTES) {
    secureClear(cek);
    throw new Error('Failed to decrypt CEK - invalid private key or corrupted token');
  }

  return cek;
}

/**
 * Decrypts AES-256-GCM ciphertext and verifies the authentication tag.
 *
 * @param {Buffer} ciphertext - Encrypted payload bytes.
 * @param {Buffer} cek - 32-byte content encryption key.
 * @param {Buffer} iv - 12-byte initialization vector.
 * @param {Buffer} authTag - 16-byte GCM authentication tag.
 * @returns {Buffer} Decrypted plaintext bytes.
 * @throws {Error} When authentication fails or parameters are invalid.
 */
function decryptContent(ciphertext, cek, iv, authTag) {
  if (iv.length !== IV_BYTES || authTag.length !== AUTH_TAG_BYTES) {
    throw new Error('Invalid JWE compact serialization format');
  }

  try {
    // The matching encryption flow uses AES-256-GCM with empty AAD.
    const decipher = crypto.createDecipheriv('aes-256-gcm', cek, iv);
    decipher.setAAD(Buffer.alloc(0));
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error('Authentication tag verification failed - token may be tampered');
  }
}

/**
 * Parses decrypted plaintext as JSON.
 *
 * @param {Buffer} plaintext - UTF-8 JSON plaintext bytes.
 * @returns {object} Parsed JSON payload.
 * @throws {Error} When plaintext is not valid JSON.
 */
function parsePayload(plaintext) {
  try {
    const payload = JSON.parse(plaintext.toString('utf8'));
    if (payload === null || Array.isArray(payload) || typeof payload !== 'object') {
      throw new Error('payload must be an object');
    }
    return payload;
  } catch {
    throw new Error('Decrypted payload is not valid JSON');
  }
}

/**
 * Zero-fills a sensitive buffer in place.
 *
 * @param {Buffer|undefined} buffer - Buffer to clear.
 * @returns {void}
 */
function secureClear(buffer) {
  if (Buffer.isBuffer(buffer)) {
    buffer.fill(0);
  }
}

/**
 * Runs the command-line application.
 *
 * @returns {void}
 */
function main() {
  let encryptedKey;
  let iv;
  let ciphertext;
  let tag;
  let cek;
  let plaintext;

  try {
    const args = process.argv.slice(2);

    if (args.length === 1 && args[0] === '--help') {
      printHelp();
      return;
    }

    if (args.length === 1 && args[0] === '--version') {
      process.stdout.write(`${VERSION}\n`);
      return;
    }

    const { jweToken, privateKeyString } = validateArgs(args);
    const privateKey = parsePrivateKey(privateKeyString);
    const parsedJwe = parseJwe(jweToken);

    encryptedKey = parsedJwe.encryptedKey;
    iv = parsedJwe.iv;
    ciphertext = parsedJwe.ciphertext;
    tag = parsedJwe.tag;

    validateHeader(parsedJwe.header);
    cek = decryptCek(encryptedKey, privateKey);
    plaintext = decryptContent(ciphertext, cek, iv, tag);

    const payload = parsePayload(plaintext);
    process.stdout.write(`${JSON.stringify(payload)}\n`);
  } catch (error) {
    process.stderr.write(`Error: ${error.message || 'Unexpected JWE decryption failure'}\n`);
    process.exitCode = 1;
  } finally {
    secureClear(cek);
    secureClear(plaintext);
    secureClear(encryptedKey);
    secureClear(iv);
    secureClear(ciphertext);
    secureClear(tag);
  }
}

export {
  AUTH_TAG_BYTES,
  CEK_BYTES,
  EXPECTED_KID,
  IV_BYTES,
  MAX_JWE_BYTES,
  MIN_RSA_BITS,
  SUPPORTED_ALG,
  SUPPORTED_ENC,
  base64urlDecode,
  base64urlEncode,
  decryptCek,
  decryptContent,
  detectKeyFormat,
  parseJwe,
  parsePayload,
  parsePrivateKey,
  secureClear,
  timingSafeStringEqual,
  validateArgs,
  validateHeader,
};

if (process.argv[1]?.endsWith('step3_decryptjwe.js')) {
  main();
}
