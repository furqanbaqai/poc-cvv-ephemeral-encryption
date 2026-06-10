# cvv-cms-crypto-java-test

Java 8 Maven command-line project for encrypting and decrypting text with an RSA key pair using only native Java crypto APIs.

The console entry point is `com.sib.cvv.cms.Main`. Business logic is under `com.openfintechlab.cms`:

- `CMSEncrypt`: encrypts plaintext with a PEM public key.
- `CMSDecrypt`: decrypts ciphertext with a PEM private key.
- Nested JOSE mode: encrypts plaintext as compact JWE, then signs that JWE as compact JWS.

## Algorithms

Encryption uses a native Java hybrid envelope:

- Random content key: `AES`, 256-bit
- Text encryption: `AES/GCM/NoPadding`
- GCM IV size: 12 bytes
- GCM authentication tag: 128 bits
- Content-key encryption: `RSA/ECB/OAEPWithSHA-256AndMGF1Padding`
- Public key format: X.509 PEM, `-----BEGIN PUBLIC KEY-----`
- Private key format: PKCS#8 PEM, `-----BEGIN PRIVATE KEY-----`
- Command output: Base64-encoded binary envelope

The legacy envelope is project-specific and starts with an `OFTLCMS` marker. It is not a standards-compliant CMS/PKCS#7 EnvelopedData payload.

Nested JOSE mode uses:

- Inner JWE: `alg=RSA-OAEP-256`, `enc=A256GCM`, `typ=JOSE`, with ISO-8601 `iat` and `exp` protected-header values.
- Outer JWS: `alg=PS256`, `typ=JOSE`, `cty=JWE`, `kid=keyid`.
- Output: compact JWS whose payload is the compact JWE.

## Requirements

- Java 8 or newer
- Maven 3.x

## Build

From this project directory:

```powershell
mvn package
```

This creates:

```powershell
.\target\cvv-cms-crypto-java-test-1.0.0-SNAPSHOT.jar
```

## Test

```powershell
mvn test
```

## Commands

The CLI accepts the command name followed by either the legacy 2-parameter form or the nested JOSE 3-parameter form.

Usage printed by the application:

```powershell
Usage:
  cms-encrypt <text> <public-key-pem>
  cms-encrypt <text> <encryption-public-key-pem> <signing-private-key-pem>
  cms-decrypt <cipher-text> <private-key-pem>
  cms-decrypt <cipher-text> <decryption-private-key-pem> <verification-public-key-pem>
```

Run the commands through the packaged jar:

```powershell
java -jar .\target\cvv-cms-crypto-java-test-1.0.0-SNAPSHOT.jar cms-encrypt <TEXT> <PUBLIC_KEY_PEM>
java -jar .\target\cvv-cms-crypto-java-test-1.0.0-SNAPSHOT.jar cms-encrypt <TEXT> <ENCRYPTION_PUBLIC_KEY_PEM> <SIGNING_PRIVATE_KEY_PEM>
java -jar .\target\cvv-cms-crypto-java-test-1.0.0-SNAPSHOT.jar cms-decrypt <CIPHER_TEXT> <PRIVATE_KEY_PEM>
java -jar .\target\cvv-cms-crypto-java-test-1.0.0-SNAPSHOT.jar cms-decrypt <CIPHER_TEXT> <DECRYPTION_PRIVATE_KEY_PEM> <VERIFICATION_PUBLIC_KEY_PEM>
```

### Command options

| Command | Parameters | Input token | Output | Notes |
| --- | --- | --- | --- | --- |
| `cms-encrypt` | `<text> <public-key-pem>` | Plain text | Base64 `OFTLCMS` envelope | Legacy behavior. Encrypts with the X.509 public key PEM. |
| `cms-encrypt` | `<text> <encryption-public-key-pem> <signing-private-key-pem>` | Plain text | Nested compact JWS-over-JWE token | Encrypts the text as compact JWE, then signs the JWE with PS256. |
| `cms-decrypt` | `<cipher-text> <private-key-pem>` | Base64 `OFTLCMS` envelope or plain compact JWE | Plain text | Legacy decrypt behavior is preserved. Compact JWE input is also accepted. |
| `cms-decrypt` | `<cipher-text> <decryption-private-key-pem> <verification-public-key-pem>` | Nested compact JWS-over-JWE, plain compact JWE, or legacy envelope | Plain text | Verifies nested JWS with the public key before decrypting the inner JWE. |

PEM formats stay the same for all command forms:

- Public keys use X.509 PEM: `-----BEGIN PUBLIC KEY-----`.
- Private keys use PKCS#8 PEM: `-----BEGIN PRIVATE KEY-----`.

Nested JOSE mode requires an extra key because the outer `PS256` JWS signature is created with a private key and verified with the matching public key.

## Encrypt

```powershell
$publicKey = @"
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6mELNrd9We8NzrDojlAv
YbsuaBklR7FzvLgZjk+EIN0MmyYgYf4b66XIRRkfUJ5ZW3Isf2hu2rxKCx/qtT5s
s9clQhELB/gzeNGEqUMl9aKEPEbtf+8ZrGomSVPW0lz8UlT/mmGycCds0GFbyP0r
S6NoEX+fH96lcBawB+Dt3Q1OH7ER9q/RbsRZP5QT1dmKWW0fKZ5atzl2PtdcKsfX
4Hmi/gSb2PmJoPXgQuQEUhrXhGakBzfCt4qnYbQyZlT9oq93fEs/kfQeGoMjjEgQ
Lo+jurWY7i86y2YOhHj2Gzezkf2QaqhcoNdNQKXQZlJSUpi5tloTnD673Kj2AB4E
kwIDAQAB
-----END PUBLIC KEY-----
"@

$cipherText = java -jar .\target\cvv-cms-crypto-java-test-1.0.0-SNAPSHOT.jar cms-encrypt "123" $publicKey
$cipherText
```

## Decrypt

```powershell
$privateKey = @"
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDqYQs2t31Z7w3O
sOiOUC9huy5oGSVHsXO8uBmOT4Qg3QybJiBh/hvrpchFGR9Qnllbcix/aG7avEoL
H+q1Pmyz1yVCEQsH+DN40YSpQyX1ooQ8Ru1/7xmsaiZJU9bSXPxSVP+aYbJwJ2zQ
YVvI/StLo2gRf58f3qVwFrAH4O3dDU4fsRH2r9FuxFk/lBPV2YpZbR8pnlq3OXY+
11wqx9fgeaL+BJvY+Ymg9eBC5ARSGteEZqQHN8K3iqdhtDJmVP2ir3d8Sz+R9B4a
gyOMSBAuj6O6tZjuLzrLZg6EePYbN7OR/ZBqqFyg101ApdBmUlJSmLm2WhOcPrvc
qPYAHgSTAgMBAAECggEAC+JNykF1hqjbX16S/BxOurrd+INF46O4xZnkGdYoUe5D
ZF6Dh9R1n/Yw+Gf0sYbF6yAX54HpFQg1DOlaYkQ/CMNg7T+l+op4OakN+/MeqpzJ
7bB+/FyoRZjARjmNC++RD6+lojNP8+Xb25kEKWXE2zn23eRFsjz80HkmBdA+31Vj
iHSEtQgbvnJ2EeB9oypRQZl5hZF2MCXrKXrz8N3voD5XzYilj36ualcEYMHarH4t
+GM202QczvLWvO5iBjmEZYMgeWVsHkhEY8Jul3YswKV4rTP0RtGOn7LuXWePn/Xx
4oIGpa5PyXfqJ5uPZXvmwHMWhw5NvzSJr3/kTtUeYQKBgQD2LUDhUpk86lyMB27r
fjvob99gdfUyPZ+0R83+oOTvwAFu7Mo+UUNYant1a+it0/cbDDUhzMbehOZNHhZA
fGEZG0zseLdzuLwhJfQr8PwZL7WJLy5kIiD9p5kqLVDGU+NbARj4pldrBx32l2dL
MITfCsfg9+m/iWvwV9IIosXX4wKBgQDzu0ZEtKpvV3ndrfiqpDIhfri5JtXISJiA
TBQeTbqAHE/U21fdLCvCqRQhq5dO6otlEFSy8n3RjLpBebBcVbA0anR+fk7iSiC/
ZjRXrqbG7+OhsjrmnsUEktj7bR5mg1ZcYg9qGvzvddjMpPO3IL989dvdbqO6fvbH
0XLeXQDfkQKBgQCGbEuDPiEi3C5Q4DY3LST1VTE6cO7E0lWEkbjwE1cvez7NHUuK
H8GQZASqJ5RUZuwFvvK8VB87noJLFeS8ra4vkXK9pWU3MWa5Cwp7fAmMjzqngDXq
w6AUIhJGr5vt0BzTspO6IsqVTLuVzTLAIexMBo0CUR04U4e3I50yzf8OVQKBgA4M
47YePB0DC/FtkAI2SPWJWpjB1l0fYjszJ42/qVqtRyTcKCqF21fza0etnqFcAAEp
edh/BiXIWQxhOXt5LRk4cdLA8Uc2QsEF4UqUtOSO+65cmeylhnIHDR8hYTlDpPza
Yk0ZlS8wufjCIZKS/rbzbWNMd3/Oxecq+dY7wkshAoGAbnabxZQ0cJqAMr1J/RoZ
Si/A0olrj89lsobV+euezARdpHr5gEnq1CnUaFKp9B/JgdXkMRWwfs8P/M5u83Kt
0bETkTkE/0qZih/O4+hwDoYRPG9YcJ9jIMlHMv+V5GdtR4y5MmoKKRZtYLwuTXyN
MU5j7g7qSFUJXTbNlEo17gs=
-----END PRIVATE KEY-----
"@

java -jar .\target\cvv-cms-crypto-java-test-1.0.0-SNAPSHOT.jar cms-decrypt $cipherText $privateKey
```

Expected output for the example above:

```text
123
```
