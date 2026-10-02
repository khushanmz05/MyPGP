# my_pgp Architecture

## Target layout

The current `my_pgp.py` is an AES experiment. The implementation should be split into small modules so that the command-line contract and cryptographic primitives can be tested independently.

```text
my_pgp/
  __init__.py
  __main__.py       # python -m my_pgp entry point
  cli.py            # argument parsing, dispatch, exit code 84
  encoding.py       # hex, little-endian integers, line/input handling
  errors.py         # user-facing validation errors
  xor_cipher.py     # XOR block and stream modes
  aes.py            # AES-128/192/256 block cipher
  rsa.py            # RSA math, key generation, key serialization
  pgp.py            # RSA + XOR/AES hybrid format
  asymmetric.py     # second asymmetric cryptosystem adapter
tests/
  test_encoding.py
  test_xor.py
  test_aes.py
  test_rsa.py
  test_pgp.py
Makefile
README.md
```

The project may remain a single executable script if the dump requires it, but the boundaries above should still exist as functions or classes. The Makefile must expose `all`, `re`, `clean`, and `fclean` without committing generated files.

## Data flow

```text
stdin bytes
  -> cli.py validates system/mode/options/key
  -> encoding.py parses hexadecimal keys and RSA key pairs
  -> selected algorithm
       xor_cipher: bytes <-> bytes
       aes:       16-byte blocks <-> 16-byte blocks
       rsa:       little-endian integer <-> little-endian integer
       pgp:       RSA-encrypted symmetric key + symmetric ciphertext
  -> stdout in the format required by the subject
```

`encoding.py` is the only place that should convert between hexadecimal text, bytes, and integers. Numbers are little-endian: the first byte on the left is the least significant byte. Symmetric stream mode pads only the final short block with zero bytes; block mode reads one line and excludes its trailing newline.

## Implementation order

1. Establish the CLI, input/output conventions, and error handling.
2. Implement and test XOR as the simplest end-to-end path.
3. Complete AES-128, then generalize the key schedule to AES-192 and AES-256.
4. Implement RSA arithmetic, key generation, and message conversion.
5. Add the second asymmetric system behind a stable adapter.
6. Compose RSA with XOR or AES for PGP.
7. Add integration tests, regression vectors, documentation, and Makefile checks.

## Cross-cutting rules

- Successful commands return `0`; invalid arguments, malformed keys, impossible operations, and processing errors write diagnostics to stderr and return `84`.
- Ciphertext and numeric results are emitted as lowercase hexadecimal without accidental debug output.
- Demo code must not execute on import or during normal CLI use.
- Every primitive gets known-answer tests plus round-trip tests. Integration tests must exercise the exact examples from the subject.
- RSA key generation uses the largest valid Fermat prime exponent and Carmichael's function, as required by the subject.