# ephemeral-keys-javascripts

Proof of concept for payment card CVV/PAN encryption with ephemeral RSA-OAEP keys.

This project has two command-line steps:

1. Generate an ephemeral RSA-OAEP public key reveal request.
2. Encrypt card data into a compact JWE using the reveal request public key.
3. Decrypt a compact JWE using the matching RSA private key.

## Prerequisites

- Node.js 20 or later
- No npm package installation is required for runtime encryption; the implementation uses Node.js built-in modules only.

## Project Structure

```text
ephemeral-keys-javascript/
  package.json
  src/
    step1_reveal.js
    step2_encrypt.js
    step3_decryptjwe.js
  test/
    step1_reveal.test.js
    step2_encrypt.test.js
    step3_decryptjwe.test.js
```

## Start Scripts

Run commands from the `ephemeral-keys-javascript` directory.

Generate a reveal request JSON:

```sh
npm run start_step1
```

Generate a reveal request JSON that also includes the full PEM private key for debugging:

```sh
npm run start_step1 -- debug
```

Encrypt a reveal request JSON into compact JWE:

```sh
npm run start_step2 -- '{"requestId":"...","cardRef":"4012 8888 8888 1881","channel":"mobile","ephemeralPublicKey":{"kty":"RSA","use":"enc","alg":"RSA-OAEP-256","n":"...","e":"AQAB"}}'
```

Decrypt a compact JWE with an RSA private key in PEM or JWK format:

```sh
npm run start_step3 -- '<jwe-token>' '<private-key>'
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

## Stop Scripts

There are no stop scripts for this project. Both start scripts are short-lived command-line programs and exit automatically after printing their output.

If a command is interrupted or left running during local experimentation, stop it with `Ctrl+C`.

## Test

Run the Node.js test suite:

```sh
npm test
```

Run only the Step 2 encryption CLI test:

```sh
npm run test_step2
```

Run only the Step 3 decryption CLI test:

```sh
npm run test_step3
```

The Step 2 test uses this reveal request fixture:

```json
{"requestId":"ed2e74ce3c26453a97b14d8bebac8ded","cardRef":"4012 8888 8888 1881","channel":"mobile","ephemeralPublicKey":{"kty":"RSA","use":"enc","alg":"RSA-OAEP-256","n":"51FePt844iEDXaYRW84puEUJU7m9cBR5qApPYQEizBthvr7wdBTz4U3xEYyjLSstwCBoXLC5DSPJtK7ZppO6C2fNMzrx7CP3bWJfQmrXOnXiCVOEj3Ib984-yDmdDDs6dp9ZajKtYNVyJSxs6nQwJVbOpRf8tQCrNsr9jb90lCunwW6nXYpSP4NbhfBrN2GgMstEwmF-XQOjNoTBb2yegC8yN9aahpk13kkoKpvYuKAb9lqGX0--d8IfY_G25QhE8Nkop2JIZrRj_Gz2ztVm1NlFo_f-qyVNuAiy94T9bnRysXRGrmHBYULL6_z6IB2xcXTkGdUzvADkU68d_Hmtnw","e":"AQAB"}}
```

Execute that fixture manually:

```sh
node ./src/step2_encrypt.js '{"requestId":"ed2e74ce3c26453a97b14d8bebac8ded","cardRef":"4012 8888 8888 1881","channel":"mobile","ephemeralPublicKey":{"kty":"RSA","use":"enc","alg":"RSA-OAEP-256","n":"51FePt844iEDXaYRW84puEUJU7m9cBR5qApPYQEizBthvr7wdBTz4U3xEYyjLSstwCBoXLC5DSPJtK7ZppO6C2fNMzrx7CP3bWJfQmrXOnXiCVOEj3Ib984-yDmdDDs6dp9ZajKtYNVyJSxs6nQwJVbOpRf8tQCrNsr9jb90lCunwW6nXYpSP4NbhfBrN2GgMstEwmF-XQOjNoTBb2yegC8yN9aahpk13kkoKpvYuKAb9lqGX0--d8IfY_G25QhE8Nkop2JIZrRj_Gz2ztVm1NlFo_f-qyVNuAiy94T9bnRysXRGrmHBYULL6_z6IB2xcXTkGdUzvADkU68d_Hmtnw","e":"AQAB"}}'
```

## Direct Node Usage

The npm scripts are wrappers around these direct commands:

```sh
node ./src/step1_reveal.js
node ./src/step2_encrypt.js '<json-input>'
'<json-input>' | node ./src/step2_encrypt.js
node ./src/step3_decryptjwe.js '<jwe-token>' '<private-key>'
```

