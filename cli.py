"""Command-line interface for the algorithms currently implemented."""

from __future__ import annotations

import sys
from collections.abc import Sequence

from aes import aes_decrypt_block, aes_encrypt_block
from encoding import EncodingError, bytes_to_hex, hex_to_bytes, read_input
from errors import CliError
from xor_cipher import xor_bytes


USAGE = """USAGE
    python3 -m my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]

DESCRIPTION
    Cipher or decipher MESSAGE using a given CRYPTO_SYSTEM.
    The MESSAGE is read from standard input.

CRYPTO_SYSTEM
    xor     computation using XOR algorithm
    aes     computation using AES-128 algorithm

MODE
    -c      MESSAGE is clear and we want to cipher it
    -d      MESSAGE is ciphered and we want to decipher it

OPTIONS
    -b      process exactly one block

IMPLEMENTED KEY SIZES
    AES-128 requires a 16-byte hexadecimal key.
"""


def _parse_arguments(arguments: Sequence[str]) -> tuple[str, bool, bool, str]:
    if len(arguments) < 3:
        raise CliError("missing crypto system, mode, or key")

    crypto_system = arguments[0].lower()
    if crypto_system not in {"xor", "aes"}:
        raise CliError(f"unsupported crypto system: {arguments[0]}")

    mode = arguments[1]
    if mode not in {"-c", "-d"}:
        raise CliError("mode must be -c or -d")

    block_mode = False
    options = list(arguments[2:])
    if "-b" in options:
        block_mode = True
        options.remove("-b")
    if len(options) != 1:
        raise CliError("exactly one key is required")
    if crypto_system == "aes" and not block_mode:
        raise CliError("AES stream mode is not implemented yet; use -b")
    return crypto_system, mode == "-d", block_mode, options[0]


def _run_xor(decrypt: bool, block_mode: bool, key: str, input_stream) -> bytes:
    data = read_input(block_mode=True if decrypt else block_mode, input_stream=input_stream)
    if decrypt:
        data = hex_to_bytes(data.decode("ascii"))
    return xor_bytes(data, hex_to_bytes(key), block_mode=block_mode, decrypt=decrypt)


def _run_aes(decrypt: bool, key: str, input_stream) -> bytes:
    key_bytes = hex_to_bytes(key)
    data = read_input(block_mode=True, input_stream=input_stream)
    if decrypt:
        data = hex_to_bytes(data.decode("ascii"))
        return aes_decrypt_block(data, key_bytes)
    return aes_encrypt_block(data, key_bytes)


def main(
    arguments: Sequence[str] | None = None,
    input_stream=None,
    output_stream=None,
    error_stream=None,
) -> int:
    arguments = sys.argv[1:] if arguments is None else arguments
    output_stream = sys.stdout.buffer if output_stream is None else output_stream
    error_stream = sys.stderr if error_stream is None else error_stream

    if arguments in ([], ["-h"], ["--help"]):
        output_stream.write(USAGE.encode())
        return 0

    try:
        crypto_system, decrypt, block_mode, key = _parse_arguments(arguments)
        input_stream = sys.stdin.buffer if input_stream is None else input_stream
        if crypto_system == "xor":
            result = _run_xor(decrypt, block_mode, key, input_stream)
        else:
            result = _run_aes(decrypt, key, input_stream)
        if decrypt:
            output_stream.write(result)
        else:
            output_stream.write(bytes_to_hex(result).encode())
        return 0
    except (CliError, EncodingError, UnicodeError) as error:
        error_stream.write(f"my_pgp: {error}\n")
        return 84


if __name__ == "__main__":
    raise SystemExit(main())