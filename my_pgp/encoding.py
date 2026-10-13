"""Project encodings: hexadecimal bytes and little-endian integers."""
from __future__ import annotations
import base64
import sys
from collections.abc import Iterable

class EncodingError(ValueError):
    """A value cannot be represented in the requested format."""

def hex_to_bytes(value: str) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise EncodingError("hexadecimal values must contain pairs of digits")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise EncodingError("invalid hexadecimal value") from exc

def bytes_to_hex(value: bytes | bytearray | Iterable[int]) -> str:
    try:
        return bytes(value).hex()
    except (TypeError, ValueError) as exc:
        raise EncodingError("value is not a valid byte sequence") from exc

def bytes_to_int_le(value: bytes | bytearray | Iterable[int]) -> int:
    try:
        return int.from_bytes(bytes(value), "little", signed=False)
    except (TypeError, ValueError) as exc:
        raise EncodingError("value is not a valid byte sequence") from exc

def int_to_bytes_le(value: int, size: int | None = None) -> bytes:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EncodingError("integer must be non-negative")
    minimum = max(1, (value.bit_length() + 7) // 8)
    width = minimum if size is None else size
    if not isinstance(width, int) or width < 0 or value >= 1 << (8 * width):
        raise EncodingError("integer does not fit in the requested size")
    return value.to_bytes(width, "little")

def int_from_hex_le(value: str) -> int:
    return bytes_to_int_le(hex_to_bytes(value))

def int_to_hex_le(value: int, size: int | None = None) -> str:
    return int_to_bytes_le(value, size).hex()

def read_input(block_mode: bool = False, input_stream=None) -> bytes:
    stream = sys.stdin.buffer if input_stream is None else input_stream
    data = stream.read()
    if isinstance(data, str):
        data = data.encode()
    if not isinstance(data, bytes):
        raise EncodingError("input stream must provide bytes")
    if block_mode and data.endswith(b"\n"):
        data = data[:-1]
    return data

def zero_padded_blocks(data: bytes, block_size: int) -> list[bytes]:
    if not isinstance(data, bytes):
        raise EncodingError("data must be bytes")
    if block_size <= 0:
        raise EncodingError("block size must be positive")
    if not data:
        return []
    blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
    blocks[-1] = blocks[-1].ljust(block_size, b"\0")
    return blocks

def decode_input(value: str, fmt: str) -> bytes:
    if fmt == "text":
        return value.encode("utf-8")
    if fmt == "hex":
        return hex_to_bytes("".join(value.split()))
    if fmt == "base64":
        try:
            return base64.b64decode(value, validate=True)
        except Exception as exc:
            raise EncodingError("invalid base64 input") from exc
    raise EncodingError(f"unsupported input format: {fmt}")

def encode_output(value: bytes, fmt: str) -> str:
    if fmt == "hex":
        return value.hex()
    if fmt == "base64":
        return base64.b64encode(value).decode("ascii")
    if fmt == "text":
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise EncodingError("output is not valid UTF-8; choose hex or base64") from exc
    raise EncodingError(f"unsupported output format: {fmt}")
