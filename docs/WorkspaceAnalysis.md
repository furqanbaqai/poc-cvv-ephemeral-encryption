# Workspace Analysis

Date: 2026-06-08

## Scope

Analyzed the full workspace at:

```text
C:\Users\baqai\source\sib\conep-model-cvv-encryption
```

The outer directory is a VS Code workspace container. The Git repository root is:

```text
poc-cvv-ephemeral-encryption/
```

## Workspace Inventory

```text
conep-model-cvv-encryption/
  AGENT.md
  conep-model-cvv-encryption.code-workspace
  poc-cvv-ephemeral-encryption.rar
  poc-cvv-ephemeral-encryption/
    .git/
    .gitignore
    LICENSE
    docs/
    ephemeral-keys-javascript/
    cvv-encryption-java/
```

Detected projects:

| Project | Type | Primary purpose |
| --- | --- | --- |
| `ephemeral-keys-javascript` | Node.js ESM CLI/test project | Functional proof of concept for Step 1 reveal, Step 2 JWE encryption, and Step 3 JWE decryption using Node built-in crypto APIs. |
| `cvv-encryption-java` | Java 17 Maven CLI/test project | Java implementation of the reveal, JWE encryption, and JWE decryption flow with a packaged runnable JAR. |
| `docs` | Shared documentation | Currently contains a stub message model document. |

No Python, Gradle, or other build-system projects were detected.

## Repository State

`git status --short` from `poc-cvv-ephemeral-encryption/` was clean before adding this report.

The root `.gitignore` ignores generated Node and Maven outputs, including `node_modules/`, lockfiles, `target/`, `*.jar`, and `*.class`.

## Project: ephemeral-keys-javascript

Path:

```text
poc-cvv-ephemeral-encryption/ephemeral-keys-javascript
```

Technology:

- Node.js ESM project with `"type": "module"`.
- Requires Node.js 20 or later.
- Uses only Node.js built-in modules at runtime.
- No package lockfile is present, consistent with no external runtime dependencies.

Important files:

```text
package.json
README.md
src/step1_reveal.js
src/step2_encrypt.js
src/step3_decryptjwe.js
test/step1_reveal.test.js
test/step2_encrypt.test.js
test/step3_decryptjwe.test.js
```

CLI scripts:

| Script | Command | Purpose |
| --- | --- | --- |
| `start_step1` | `node ./src/step1_reveal.js` | Generate a reveal request with an ephemeral RSA public key. |
| `start_step2` | `node ./src/step2_encrypt.js` | Encrypt a reveal request into compact JWE. |
| `start_step3` | `node ./src/step3_decryptjwe.js` | Decrypt compact JWE using a matching RSA private key. |
| `test_step2` | `node ./test/step2_encrypt.test.js` | Focused Step 2 tests. |
| `test_step3` | `node ./test/step3_decryptjwe.test.js` | Focused Step 3 tests. |
| `test` | `node --test` | Full Node test suite. |

Behavior summary:

- `step1_reveal.js` generates a 2048-bit RSA-OAEP/SHA-256 key pair and emits minified reveal request JSON.
- `step1_reveal.js debug` includes the PKCS#8 PEM private key for local testing.
- `step2_encrypt.js` accepts reveal JSON by argument or stdin, validates public JWK fields, creates a fixed card payload, wraps a random CEK with RSA-OAEP-256, encrypts content with AES-256-GCM, and emits compact JWE.
- `step3_decryptjwe.js` validates compact JWE structure, supported header values, private key format, RSA size, CEK length, IV length, and authentication tag before printing minified decrypted JSON.

Security observations:

- The implementation uses RSA-OAEP-256 and A256GCM with explicit allowlists.
- The decrypt path rejects unsupported `alg`, unsupported `enc`, compression headers, wrong `kid`, malformed compact serialization, and tampered ciphertext.
- Sensitive buffers are cleared where practical for CEK, plaintext, decoded key material, and JWE component buffers.
- The sample card payload is hardcoded for proof-of-concept behavior and should not be mistaken for production data handling.

Verification performed:

```powershell
cd .\poc-cvv-ephemeral-encryption\ephemeral-keys-javascript
npm test
```

Result:

```text
tests 12
pass 12
fail 0
duration_ms 471.0034
```

End-to-end CLI smoke test:

```powershell
$requestJson = node .\src\step1_reveal.js debug
$request = $requestJson | ConvertFrom-Json
$jwe = $requestJson | node .\src\step2_encrypt.js
node .\src\step3_decryptjwe.js $jwe $request.ephemeralPublicKey.privateKey
```

Result:

```json
{"cardRef":"4012888888881881","pan":"4012888888881881","expiryMonth":"12","expiryYear":"29","cvv":"123","iat":1775901000,"exp":1775901030,"jti":"reveal-8f3a1c"}
```

## Project: cvv-encryption-java

Path:

```text
poc-cvv-ephemeral-encryption/cvv-encryption-java
```

Technology:

- Java 17 Maven project.
- Artifact coordinates: `com.sib:cvv-encryption-util:1.0.0-beta01`.
- Final packaged JAR name: `target/cvv-encryption-java.jar`.
- Uses JDK crypto APIs in main code.
- Test dependencies: Jackson Databind and JUnit Jupiter.
- Maven Shade Plugin creates a runnable JAR with `Main-Class: com.sib.cvv.Main`.

Important files:

```text
pom.xml
README.md
src/main/java/com/sib/cvv/Main.java
src/main/java/com/openfintechlab/jwe/Reveal.java
src/main/java/com/openfintechlab/jwe/JWEEncrypt.java
src/main/java/com/openfintechlab/jwe/JWEDecrypt.java
src/main/java/com/openfintechlab/jwe/model/RevealRequest.java
src/main/java/com/openfintechlab/jwe/model/EphemeralPublicKey.java
src/main/java/com/openfintechlab/jwe/util/KeyGeneratorUtil.java
src/main/java/com/openfintechlab/jwe/util/JsonUtil.java
src/test/java/com/openfintechlab/jwe/RevealTest.java
src/test/java/com/openfintechlab/jwe/JWEEncryptTest.java
src/test/java/com/openfintechlab/jwe/JWEDecryptTest.java
```

CLI commands:

| Command | Purpose |
| --- | --- |
| `java -jar target/cvv-encryption-java.jar reveal` | Generate reveal request JSON with public JWK fields. |
| `java -jar target/cvv-encryption-java.jar reveal debug` | Generate reveal request JSON with debug private key PEM. |
| `java -jar target/cvv-encryption-java.jar jwe-encrypt '<JSON-PAYLOAD>'` | Encrypt card data using reveal request public key. |
| `java -jar target/cvv-encryption-java.jar jwe-decrypt '<JWE-MESSAGE>' '<PRIVATE-KEY>'` | Decrypt compact JWE using private key PEM or JSON-wrapped PEM. |

Behavior summary:

- `Main.java` owns CLI routing, usage output, input parsing, and console behavior.
- `Reveal` and model classes build the reveal request and ephemeral public-key payload.
- `JWEEncrypt` builds the same proof-of-concept card payload shape used by the JavaScript flow and emits compact JWE.
- `JWEDecrypt` validates and decrypts compact JWE with RSA-OAEP-256 and AES-256-GCM.

Design observations:

- Runtime dependencies are intentionally minimal; main code does not rely on Jackson.
- `Main.JsonObjectParser` is a local parser for the constrained CLI input shapes, including Windows PowerShell-stripped object-like input.
- The Maven license metadata says MIT, while the repository has an Apache-style `LICENSE` file and the Node package declares `Apache-2.0`. This license mismatch should be resolved before release.
- README says `target/classes` is sufficient for `reveal`, but encryption/decryption should be run through the packaged JAR unless classpath requirements are explicitly documented and verified.

Verification performed:

```powershell
cd .\poc-cvv-ephemeral-encryption\cvv-encryption-java
mvn test
```

Result:

```text
Tests run: 14, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

Package verification:

```powershell
mvn package
```

Result:

```text
Building jar: target\cvv-encryption-java.jar
Replacing original artifact with shaded artifact.
BUILD SUCCESS
```

Packaged JAR smoke test:

```powershell
java -jar .\target\cvv-encryption-java.jar reveal
```

Result:

```text
Printed minified reveal request JSON with requestId, cardRef, channel, and RSA public JWK fields.
```

## Shared Docs

Path:

```text
poc-cvv-ephemeral-encryption/docs
```

Current files:

```text
MessageModels.md
WorkspaceAnalysis.md
```

`MessageModels.md` is currently a stub and does not describe the actual reveal request, JWE header, encrypted payload, or decrypted payload models. This is the largest documentation gap relative to the code.

## Cross-Project Comparison

Both projects implement the same conceptual three-step proof of concept:

1. Generate an ephemeral RSA reveal request.
2. Encrypt a fixed card payload as compact JWE using the reveal public key.
3. Decrypt compact JWE using the matching private key.

Shared protocol shape:

- Key wrapping: `RSA-OAEP-256`.
- Content encryption: `A256GCM`.
- RSA key size: 2048 bits.
- Public JWK fields: `kty`, `use`, `alg`, `n`, `e`.
- Default card reference: `4012 8888 8888 1881`.
- Payload fields: `cardRef`, `pan`, `expiryMonth`, `expiryYear`, `cvv`, `iat`, `exp`, `jti`.

Notable difference:

- JavaScript normalizes `cardRef` by removing whitespace for both `cardRef` and `pan` in the encrypted payload.
- Java `Main` passes the raw `cardRef` into both `cardRef` and `pan` when constructing `JWEEncrypt`, and `JWEEncrypt` stores those values as supplied. This is a cross-language behavior mismatch to address or document.

## Risks And Gaps

1. `docs/MessageModels.md` is incomplete.
   The protocol shape is spread across READMEs, source, and tests instead of one shared message model.

2. License metadata is inconsistent.
   The repository `LICENSE` appears Apache-style, the Node package declares `Apache-2.0`, and the Java `pom.xml` declares MIT.

3. The proof-of-concept payload contains hardcoded PAN/CVV sample values.
   This is acceptable for a POC, but production readiness would require external input contracts, validation rules, masking/logging rules, and secret-handling review.

4. There is no root README.
   A new user must infer the two-project layout from the workspace file, subproject READMEs, or `AGENT.md`.

5. The outer workspace contains `poc-cvv-ephemeral-encryption.rar`.
   This archive is outside the Git repository. Its contents and purpose were not expanded or verified.

6. Java CLI JSON parsing is custom.
   This keeps runtime dependencies small, but it increases parser maintenance risk. The constrained parser is covered by tests, but broader JSON compatibility should not be assumed without more cases.

## Recommended Next Steps

1. Expand `docs/MessageModels.md` into the authoritative protocol document for reveal request, public key model, JWE header, encrypted payload, decrypted payload, and error behavior.

2. Decide the repository license and align `pom.xml`, `package.json`, and `LICENSE`.

3. Add a root `README.md` under `poc-cvv-ephemeral-encryption/` that links the JavaScript and Java projects and lists verified commands.

4. Add a cross-language compatibility test:
   - JavaScript Step 1 request encrypted by Java Step 2 and decrypted by JavaScript Step 3.
   - Java Step 1 request encrypted by JavaScript Step 2 and decrypted by Java Step 3.

5. Align `cardRef` normalization between JavaScript and Java encrypted payloads, or document that the Java payload intentionally preserves spaces.

6. If the `.rar` archive is part of delivery, document how it is produced and whether it is source, artifact, or external distribution material.

## Verified Commands Summary

```powershell
cd .\poc-cvv-ephemeral-encryption\ephemeral-keys-javascript
npm test
```

Passed: 12 tests.

```powershell
cd .\poc-cvv-ephemeral-encryption\cvv-encryption-java
mvn test
```

Passed: 14 tests.

```powershell
cd .\poc-cvv-ephemeral-encryption\cvv-encryption-java
mvn package
java -jar .\target\cvv-encryption-java.jar reveal
```

Passed: package build succeeded and the packaged JAR printed reveal request JSON.
