# cvv-encryption-java

Java implementation for generating a JWE reveal request payload. The CLI creates an ephemeral RSA key pair, returns the public key as JWK fields, and can include the private key PEM in debug mode for local testing.

## Prerequisites

- Java 17 or later
- Apache Maven 3.8 or later

Verify the tools are available:

```sh
java -version
mvn -version
```

## Project Structure

```text
cvv-encryption-java/
  pom.xml
  README.md
  src/main/java/
    com/openfintechlab/jwe/
      Reveal.java
      JWEEncrypt.java
      JWEDecrypt.java
      model/
        RevealRequest.java
        EphemeralPublicKey.java
      util/
        KeyGeneratorUtil.java
        JsonUtil.java
    com/sib/cvv/
      Main.java
```

`com.sib.cvv.Main` is the packaged CLI entry point and owns all console interaction. `com.openfintechlab.jwe` classes contain reveal, encryption, and decryption helper logic.

## Reveal Command

Generates an ephemeral RSA key pair and constructs a JWE reveal request payload.

### Usage

```bash
java -jar target/cvv-encryption-java.jar reveal [debug]
```

### Standard Mode

Outputs minified JSON with the public key only:

```bash
$ java -jar target/cvv-encryption-java.jar reveal
{"requestId":"e858936675514b84957b53ba7ba4771f","cardRef":"4012 8888 8888 1881","channel":"mobile","ephemeralPublicKey":{"kty":"RSA","use":"enc","alg":"RSA-OAEP-256","n":"...","e":"AQAB"}}
```

### Debug Mode

Outputs minified JSON with both public and private keys:

```bash
$ java -jar target/cvv-encryption-java.jar reveal debug
{"requestId":"e858936675514b84957b53ba7ba4771f","cardRef":"4012 8888 8888 1881","channel":"mobile","ephemeralPublicKey":{"kty":"RSA","use":"enc","alg":"RSA-OAEP-256","n":"...","e":"AQAB","privateKey":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"}}
```

Warning: debug mode exposes the private key. Use it only in development or testing environments.

## JWE Encrypt Command

Encrypts the card payload using the RSA public key from a reveal request JSON and prints a compact JWE token.

### Usage

```bash
java -jar target/cvv-encryption-java.jar jwe-encrypt '<JSON-PAYLOAD>'
```

The JSON payload must contain `cardRef` and `ephemeralPublicKey` with public JWK fields:

```json
{"requestId":"facbd5d0f1feb1f067c81df1644404c8","cardRef":"4012 8888 8888 1881","channel":"mobile","ephemeralPublicKey":{"kty":"RSA","use":"enc","alg":"RSA-OAEP-256","n":"...","e":"AQAB"}}
```

The encrypted JWE uses this protected header:

```json
{"alg":"RSA-OAEP-256","enc":"A256GCM","typ":"JWE","cty":"json","kid":"ephemeral-key","iat":1775901000}
```

The encrypted payload contains:

```json
{"cardRef":"<cardRef>","pan":"<cardRef>","expiryMonth":"12","expiryYear":"29","cvv":"123","iat":1775901000,"exp":1775901030,"jti":"reveal-8f3a1c"}
```

## JWE Decrypt Command

Decrypts a compact JWE token using the RSA private key emitted by `reveal debug` and prints the decrypted payload JSON.

### Usage

```bash
java -jar target/cvv-encryption-java.jar jwe-decrypt '<JWE-MESSAGE>' '<PRIVATE-KEY>'
```

The private key can be passed as raw PEM text with escaped newlines:

```bash
$ java -jar target/cvv-encryption-java.jar jwe-decrypt 'eyJhbGciOi...' '-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----'
{"cardRef":"4012 8888 8888 1881","pan":"4012 8888 8888 1881","expiryMonth":"12","expiryYear":"29","cvv":"123","iat":1775901000,"exp":1775901030,"jti":"reveal-8f3a1c"}
```

It can also be passed as JSON when that is easier for shell scripting:

```bash
java -jar target/cvv-encryption-java.jar jwe-decrypt 'eyJhbGciOi...' '{"privateKey":"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"}'
```

## Output Fields

| Field | Description |
| --- | --- |
| `requestId` | Cryptographically secure 32-character hexadecimal request ID. |
| `cardRef` | Hardcoded card reference: `4012 8888 8888 1881`. |
| `channel` | Hardcoded channel: `mobile`. |
| `ephemeralPublicKey.kty` | RSA JWK key type. |
| `ephemeralPublicKey.use` | JWK key usage, always `enc`. |
| `ephemeralPublicKey.alg` | JWK algorithm, always `RSA-OAEP-256`. |
| `ephemeralPublicKey.n` | Base64url-encoded RSA modulus with no padding. |
| `ephemeralPublicKey.e` | Base64url-encoded RSA public exponent, typically `AQAB`. |
| `ephemeralPublicKey.privateKey` | PKCS#8 PEM private key, only included when `debug` is supplied. |

## Build

Compile the project:

```sh
mvn compile
```

Build the runnable fat JAR:

```sh
mvn package
```

The runnable artifact is:

```text
target/cvv-encryption-java.jar
```

## Test

Run the JUnit test suite:

```sh
mvn test
```

The reveal tests verify:

- standard mode output has public JWK fields only;
- debug mode includes a valid PKCS#8 PEM private key;
- CLI `reveal` and `reveal debug` print minified JSON to stdout;
- request IDs are 32-character lowercase hexadecimal strings.
- CLI `jwe-encrypt` prints compact JWE that decrypts to the expected header and payload.
- CLI `jwe-decrypt` decrypts compact JWE tokens and supports raw PEM or JSON-wrapped private keys.

## Run From Classes

After compiling, run without packaging:

```sh
java -cp target/classes com.sib.cvv.Main reveal
```

When running from classes, use `com.sib.cvv.Main`. The reveal CLI uses only JDK classes at runtime, so `target/classes` is sufficient for this command.

## CLI Validation

| Scenario | Behavior |
| --- | --- |
| No arguments | Print usage to stderr and exit 1. |
| `reveal` | Generate keys and output public-key request JSON. |
| `reveal debug` | Generate keys and output request JSON with private key PEM. |
| `jwe-encrypt <JSON-PAYLOAD>` | Encrypt card data using the reveal request public key. |
| `jwe-decrypt <JWE-MESSAGE> <PRIVATE-KEY>` | Decrypt compact JWE using a private key PEM. |
| Unknown command | Print usage to stderr and exit 1. |
| Too many arguments | Print usage to stderr and exit 1. |

## Security Notes

- Generates a fresh 2048-bit RSA key pair per invocation.
- Uses `SecureRandom.getInstanceStrong()` when available, with `SecureRandom` fallback.
- Encodes public key fields as base64url without padding.
- Emits private key material only when `debug` is explicitly provided.
- Encrypts with RSA-OAEP-256 and AES-256-GCM.
- Decrypts only compact JWE tokens using `RSA-OAEP-256` and `A256GCM`.
- Does not write keys or plaintext to disk.
- Clears sensitive encoded private key byte arrays after PEM conversion.

## Clean

Remove Maven build outputs:

```sh
mvn clean
```
