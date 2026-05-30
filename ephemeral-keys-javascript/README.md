# Ephemeral Keys NodeJs Project

Proof of concept for payment card CVV/PAN encryption using ephemeral RSA-OAEP keys and compact JWE.

The project models a three-party flow:

1. `step1_reveal.js`: simulates a mobile device initiating a request and generating an RSA public/private key pair on the fly.
2. `step2_encrypt.js`: simulates middleware encrypting card data into compact JWE and returning the encrypted response.
3. `step3_decryptjwe.js`: simulates the mobile device receiving the JWE response and decrypting it with the private key generated in Step 1.

## Prerequisites

- Node.js 20 or later.
- No runtime npm dependencies. The implementation uses Node.js built-in modules only.

## Project Structure

```text
ephemeral-keys-javascript/
  package.json
  README.md
  .vscode/
    launch.json
  src/
    step1_reveal.js
    step2_encrypt.js
    step3_decryptjwe.js
  test/
    step1_reveal.test.js
    step2_encrypt.test.js
    step3_decryptjwe.test.js
```

## Source Files

| File | Role | Key behavior |
| --- | --- | --- |
| `src/step1_reveal.js` | Mobile request simulator | Generates a 2048-bit RSA-OAEP key pair, emits a reveal request containing the public JWK, and can include the full PEM private key in debug mode. |
| `src/step2_encrypt.js` | Middleware encryption simulator | Accepts reveal request JSON, validates the RSA public JWK, creates the sample card payload, wraps a 256-bit CEK with RSA-OAEP-256, encrypts the payload with AES-256-GCM, and outputs compact JWE. |
| `src/step3_decryptjwe.js` | Mobile response decryption simulator | Accepts compact JWE and a private key, validates the token/header/key, unwraps the CEK, decrypts AES-256-GCM content, and outputs the decrypted JSON payload. |

## Package Scripts

Run commands from the `ephemeral-keys-javascript` directory.

| Script | Command | Purpose |
| --- | --- | --- |
| `start_step1` | `node ./src/step1_reveal.js` | Generate a reveal request JSON. |
| `start_step2` | `node ./src/step2_encrypt.js` | Encrypt a reveal request into compact JWE. |
| `start_step3` | `node ./src/step3_decryptjwe.js` | Decrypt compact JWE with an RSA private key. |
| `test_step2` | `node ./test/step2_encrypt.test.js` | Run only Step 2 tests. |
| `test_step3` | `node ./test/step3_decryptjwe.test.js` | Run only Step 3 tests. |
| `test` | `node --test` | Run the full Node.js test suite. |

## JWE Overview

JWE, JSON Web Encryption, is a standard format for carrying encrypted content. This project uses JWE compact serialization, which is a single string with five base64url-encoded segments separated by dots:

```text
BASE64URL(protected-header).BASE64URL(encrypted-key).BASE64URL(iv).BASE64URL(ciphertext).BASE64URL(tag)
```

| Component | Meaning in this project |
| --- | --- |
| Protected header | JSON metadata describing the cryptographic algorithms. This project accepts `alg: "RSA-OAEP-256"` and `enc: "A256GCM"`. |
| Encrypted key | The AES content encryption key, CEK, encrypted with the mobile device public RSA key using RSA-OAEP with SHA-256. |
| IV | 96-bit initialization vector used for AES-256-GCM. |
| Ciphertext | The encrypted JSON payment-card payload. |
| Authentication tag | 128-bit AES-GCM tag used to detect tampering before plaintext is trusted. |

The Step 2 encryptor creates a new random CEK and IV for each encryption. The Step 3 decryptor rejects unsupported algorithms, invalid compact serialization, compression headers, bad key sizes, wrong private keys, and tampered ciphertext.

## Step 1: Generate Reveal Request

Generate a reveal request JSON:

```sh
npm run start_step1
```

Generate a reveal request JSON that also includes the full PEM private key for local debugging and Step 3 decryption:

```sh
npm run start_step1 -- debug
```

Debug output includes `ephemeralPublicKey.privateKey`:

```json
{
  "requestId": "...",
  "cardRef": "4012 8888 8888 1881",
  "channel": "mobile",
  "ephemeralPublicKey": {
    "kty": "RSA",
    "use": "enc",
    "alg": "RSA-OAEP-256",
    "n": "...",
    "e": "AQAB",
    "privateKey": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
  }
}
```

## Step 2: Encrypt Response

Encrypt a reveal request JSON into compact JWE:

```sh
npm run start_step2 -- '{"requestId":"...","cardRef":"4012 8888 8888 1881","channel":"mobile","ephemeralPublicKey":{"kty":"RSA","use":"enc","alg":"RSA-OAEP-256","n":"...","e":"AQAB"}}'
```

PowerShell example that pipes Step 1 output into Step 2:

```powershell
$request = npm run start_step1 --silent
$request | npm run start_step2 --silent
```

PowerShell can also pass the request as an argument when the variable is quoted:

```powershell
$request = npm run start_step1 --silent
npm run start_step2 -- "$request"
```

## Step 3: Decrypt JWE

Decrypt a compact JWE with an RSA private key in PEM or JWK format:

```sh
npm run start_step3 -- '<jwe-token>' '<private-key>'
```

Direct Node usage:

```sh
node ./src/step3_decryptjwe.js '<jwe-token>' '<private-key>'
```

PowerShell end-to-end debug example:

```powershell
$requestJson = node .\src\step1_reveal.js debug
$request = $requestJson | ConvertFrom-Json
$jwe = $requestJson | node .\src\step2_encrypt.js
node .\src\step3_decryptjwe.js $jwe $request.ephemeralPublicKey.privateKey
```

Successful Step 3 output is only the decrypted minified JSON payload:

```json
{"cardRef":"4012888888881881","pan":"4012888888881881","expiryMonth":"12","expiryYear":"29","cvv":"123","iat":1775901000,"exp":1775901030,"jti":"reveal-8f3a1c"}
```

## Tests

Run the full suite:

```sh
npm test
```

Run focused tests:

```sh
npm run test_step2
npm run test_step3
```

Test coverage includes:

- Step 1 reveal request shape, public JWK fields, debug PEM private key output.
- Step 2 compact JWE shape, protected header, malformed JSON handling, PowerShell-stripped JSON compatibility.
- Step 3 PEM and JWK private-key parsing, JWE header validation, CEK/content decryption, authentication tag failure, CLI output behavior.

## Direct Commands

The npm scripts are wrappers around these direct commands:

```sh
node ./src/step1_reveal.js
node ./src/step1_reveal.js debug
node ./src/step2_encrypt.js '<json-input>'
'<json-input>' | node ./src/step2_encrypt.js
node ./src/step3_decryptjwe.js '<jwe-token>' '<private-key>'
```

## Stop Scripts

There are no stop scripts for this project. All scripts are short-lived command-line programs and exit after printing their output.

If a command is interrupted during local experimentation, stop it with `Ctrl+C`.
