# my_pgp Cipher Workbench

A dependency-free Python implementation of the assignment's XOR, AES, RSA, and hybrid PGP modes, plus a local browser workbench for building reversible cipher pipelines.

## Included

- Assignment CLI: `xor`, `aes`, `rsa`, `pgp-xor`, `pgp-aes`
- AES-128, AES-192, and AES-256 with 128-bit blocks
- RSA key generation using Carmichael's function and the largest valid Fermat exponent
- Hybrid RSA + XOR/AES modes
- Composable pipeline: AES, XOR, byte-Vigenère, byte-Caesar, reverse
- UTF-8, hexadecimal, and Base64 input/output
- Secure hexadecimal key generator using Python `secrets` or browser `crypto.getRandomValues`
- Responsive light/dark frontend
- Unit and integration tests

## Run CLI

```bash
make
./mypgp -h
printf 'All men must die' | ./mypgp aes -c -b 57696e74657220697320636f6d696e67
```

RSA key generation follows the subject's little-endian notation:

```bash
./mypgp rsa -g d3 e3
```

Pipeline CLI:

```bash
printf 'hello' | ./mypgp pipeline -c \
  --steps '[{"algorithm":"caesar","shift":13},{"algorithm":"aes","key":"00112233445566778899aabbccddeeff"}]' \
  --input-format text --output-format hex
```

To decrypt, pass the same JSON with `-d`; the application automatically applies the steps in reverse order.

## Run frontend

```bash
make web
```

Open `http://127.0.0.1:8080`. No message or key leaves the local process.

## Test

```bash
make test
```

## Important security note

This is an educational and assignment-compatible implementation. The mandated RSA operation is textbook RSA, and the symmetric stream convention uses zero padding. Do not use those compatibility modes for production secrets. Production software should use a reviewed library, authenticated encryption, and standard RSA padding such as OAEP.
