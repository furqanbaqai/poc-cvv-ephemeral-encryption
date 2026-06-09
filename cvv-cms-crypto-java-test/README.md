# cvv-cms-crypto-java-test

Java 8 Maven command-line project for encrypting and decrypting text with an RSA key pair using only native Java crypto APIs.

The console entry point is `com.sib.cvv.cms.Main`. Business logic is under `com.openfintechlab.cms`:

- `CMSEncrypt`: encrypts plaintext with a PEM public key.
- `CMSDecrypt`: decrypts ciphertext with a PEM private key.

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

The envelope is project-specific and starts with an `OFTLCMS` marker. It is not a standards-compliant CMS/PKCS#7 EnvelopedData payload.

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

```powershell
java -jar .\target\cvv-cms-crypto-java-test-1.0.0-SNAPSHOT.jar cms-encrypt <TEXT> <PUBLIC_KEY_PEM>
java -jar .\target\cvv-cms-crypto-java-test-1.0.0-SNAPSHOT.jar cms-decrypt <CIPHER_TEXT> <PRIVATE_KEY_PEM>
```

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
