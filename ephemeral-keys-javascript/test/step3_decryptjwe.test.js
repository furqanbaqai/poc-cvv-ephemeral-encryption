import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  SUPPORTED_ALG,
  SUPPORTED_ENC,
  base64urlEncode,
  base64urlDecode,
  decryptCek,
  decryptContent,
  parseJwe,
  parsePayload,
  parsePrivateKey,
  secureClear,
  validateArgs,
  validateHeader,
} from '../src/step3_decryptjwe.js';

const PAYLOAD = {
  cardRef: 'card_12345',
  pan: '4111111111111111',
  expiryMonth: '12',
  expiryYear: '29',
  cvv: '123',
  iat: 1775901000,
  exp: 1775901030,
  jti: 'reveal-8f3a1c',
};

function createFixture() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicExponent: 0x10001,
  });
  const cek = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const header = {
    alg: SUPPORTED_ALG,
    enc: SUPPORTED_ENC,
    typ: 'JWE',
    cty: 'json',
    kid: 'ephemeral-key',
  };

  try {
    const encryptedKey = crypto.publicEncrypt(
      {
        key: publicKey,
        oaepHash: 'sha256',
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      },
      cek,
    );

    const cipher = crypto.createCipheriv('aes-256-gcm', cek, iv);
    cipher.setAAD(Buffer.alloc(0));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(PAYLOAD), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    const jwe = [
      base64urlEncode(JSON.stringify(header)),
      base64urlEncode(encryptedKey),
      base64urlEncode(iv),
      base64urlEncode(ciphertext),
      base64urlEncode(tag),
    ].join('.');

    return {
      jwe,
      pem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
      jwk: JSON.stringify(privateKey.export({ format: 'jwk' })),
    };
  } finally {
    secureClear(cek);
  }
}

function decryptFixture(jwe, privateKeyString) {
  let cek;
  let plaintext;
  const privateKey = parsePrivateKey(privateKeyString);
  const parsedJwe = parseJwe(jwe);

  try {
    validateHeader(parsedJwe.header);
    cek = decryptCek(parsedJwe.encryptedKey, privateKey);
    plaintext = decryptContent(parsedJwe.ciphertext, cek, parsedJwe.iv, parsedJwe.tag);
    return parsePayload(plaintext);
  } finally {
    secureClear(cek);
    secureClear(plaintext);
    secureClear(parsedJwe.encryptedKey);
    secureClear(parsedJwe.iv);
    secureClear(parsedJwe.ciphertext);
    secureClear(parsedJwe.tag);
  }
}

describe('step3_decryptjwe CLI helpers', () => {
  it('decrypts a compact JWE with a PEM private key containing literal newline escapes', () => {
    const { jwe, pem } = createFixture();
    const args = validateArgs([jwe, pem.replace(/\n/g, '\\n')]);

    assert.deepEqual(decryptFixture(args.jweToken, args.privateKeyString), PAYLOAD);
  });

  it('decrypts a compact JWE with a JWK private key', () => {
    const { jwe, jwk } = createFixture();

    assert.deepEqual(decryptFixture(jwe, jwk), PAYLOAD);
  });

  it('rejects unsupported algorithms and encryption methods', () => {
    assert.throws(() => validateHeader({ alg: 'RSA1_5', enc: SUPPORTED_ENC }), /Unsupported algorithm/);
    assert.throws(() => validateHeader({ alg: SUPPORTED_ALG, enc: 'A128GCM' }), /Unsupported encryption/);
    assert.throws(() => validateHeader({ alg: SUPPORTED_ALG, enc: SUPPORTED_ENC, zip: 'DEF' }), /zip header/);
  });

  it('rejects tampered ciphertext during authentication tag verification', () => {
    const { jwe, pem } = createFixture();
    const parts = jwe.split('.');
    const tamperedCiphertext = base64urlDecode(parts[3]);
    tamperedCiphertext[0] ^= 0xff;
    parts[3] = base64urlEncode(tamperedCiphertext);

    try {
      assert.throws(() => decryptFixture(parts.join('.'), pem), /Authentication tag verification failed/);
    } finally {
      secureClear(tamperedCiphertext);
    }
  });

  it('validates argument count and compact serialization shape', () => {
    assert.throws(() => validateArgs([]), /Two arguments required/);
    assert.throws(() => validateArgs(['abc', '   ']), /Arguments must not be empty/);
    assert.throws(() => parseJwe('a.b.c.d'), /Invalid JWE compact serialization format/);
    assert.throws(() => parseJwe('a.b..d.e'), /Invalid JWE compact serialization format/);
  });

  it('prints only the minified decrypted JSON payload from the CLI', () => {
    const { jwe, jwk } = createFixture();
    const scriptPath = fileURLToPath(new URL('../src/step3_decryptjwe.js', import.meta.url));
    const result = spawnSync(process.execPath, [scriptPath, jwe, jwk], {
      encoding: 'utf8',
    });

    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '');
    assert.equal(result.stdout.trim(), JSON.stringify(PAYLOAD));
  });
});
