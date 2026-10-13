"""Assignment-compatible command line plus a composable pipeline extension."""
from __future__ import annotations
import json, secrets, sys
from collections.abc import Sequence
from .aes import aes_bytes
from .encoding import EncodingError, bytes_to_hex, decode_input, encode_output, hex_to_bytes, read_input
from .errors import CliError
from .pgp import pgp_decrypt, pgp_encrypt
from .pipeline import parse_pipeline, run_pipeline
from .rsa import generate_keypair, rsa_decrypt, rsa_encrypt
from .xor_cipher import xor_bytes

USAGE = """USAGE
  ./mypgp CRYPTO_SYSTEM MODE [OPTIONS] [key]
  ./mypgp pipeline MODE --steps JSON [--input-format text|hex|base64] [--output-format text|hex|base64]
  ./mypgp keygen [BYTES]

CRYPTO_SYSTEM
  xor | aes | rsa | pgp-xor | pgp-aes
MODE
  -c encrypt, -d decrypt, -g P Q generate RSA keys
OPTIONS
  -b process one block (XOR/AES/PGP)
"""

def _write(stream, value: bytes | str) -> None:
    stream.write(value if isinstance(value, bytes) else value.encode())

def _pipeline_command(args, stdin) -> str:
    if len(args) < 4 or args[1] not in ("-c", "-d") or "--steps" not in args:
        raise CliError("pipeline requires -c/-d and --steps JSON")
    def option(name, default):
        return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else default
    steps = parse_pipeline(option("--steps", ""))
    input_format = option("--input-format", "hex" if args[1] == "-d" else "text")
    output_format = option("--output-format", "text" if args[1] == "-d" else "hex")
    raw = read_input(False, stdin).decode("utf-8")
    return encode_output(run_pipeline(decode_input(raw, input_format), steps, args[1] == "-d"), output_format)

def execute(arguments: Sequence[str], stdin) -> bytes | str:
    args = list(arguments)
    if not args or args[0] in ("-h", "--help"):
        return USAGE
    if args[0] == "keygen":
        size = int(args[1]) if len(args) > 1 else 16
        if size < 1 or size > 4096:
            raise CliError("key size must be between 1 and 4096 bytes")
        return secrets.token_hex(size) + "\n"
    if args[0] == "pipeline":
        return _pipeline_command(args, stdin) + "\n"
    system = args[0].lower()
    if system == "rsa" and len(args) == 4 and args[1] == "-g":
        public, private = generate_keypair(args[2], args[3])
        return f"public key: {public}\nprivate key: {private}\n"
    if system not in {"xor", "aes", "rsa", "pgp-xor", "pgp-aes"} or len(args) < 3:
        raise CliError("invalid or incomplete command")
    mode = args[1]
    if mode not in ("-c", "-d"):
        raise CliError("mode must be -c or -d")
    decrypt = mode == "-d"
    block = "-b" in args[2:-1]
    key = args[-1]
    data = read_input(block if not decrypt else True, stdin)
    if system == "rsa":
        return rsa_decrypt(data.decode(), key) if decrypt else rsa_encrypt(data, key) + "\n"
    if system.startswith("pgp-"):
        algorithm = system[4:]
        return pgp_decrypt(data.decode(), key, algorithm, block) if decrypt else pgp_encrypt(data, key, algorithm, block) + "\n"
    if decrypt:
        data = hex_to_bytes(data.decode().strip())
    result = xor_bytes(data, hex_to_bytes(key), block, decrypt) if system == "xor" else aes_bytes(data, hex_to_bytes(key), decrypt, block, True)
    return result if decrypt else bytes_to_hex(result) + "\n"

def main(arguments=None, input_stream=None, output_stream=None, error_stream=None) -> int:
    args = sys.argv[1:] if arguments is None else arguments
    stdin = sys.stdin.buffer if input_stream is None else input_stream
    stdout = sys.stdout.buffer if output_stream is None else output_stream
    stderr = sys.stderr if error_stream is None else error_stream
    try:
        _write(stdout, execute(args, stdin))
        return 0
    except (CliError, EncodingError, UnicodeError, ValueError) as exc:
        stderr.write(f"mypgp: {exc}\n")
        return 84
