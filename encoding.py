"""Conversions and input handling shared by the cryptographic algorithms."""

from __future__ import annotations

import sys
from collections.abc import Iterable


class EncodingError(ValueError):
    """Raised when a value cannot be represented by the project format."""


def hex_to_bytes(value: str) -> bytes:
    """Decode an even-length hexadecimal string."""
    if not isinstance(value, str) or len(value) % 2 != 0:
        raise EncodingError("hexadecimal values must contain pairs of digits")

    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise EncodingError("invalid hexadecimal value") from error


def bytes_to_hex(value: bytes | bytearray | Iterable[int]) -> str:
    """Encode bytes as lowercase hexadecimal without separators."""
    try:
        return bytes(value).hex()
    except (TypeError, ValueError) as error:
        raise EncodingError("value is not a valid byte sequence") from error


def bytes_to_int_le(value: bytes | bytearray | Iterable[int]) -> int:
    """Interpret a byte sequence as a little-endian non-negative integer."""
    try:
        return int.from_bytes(bytes(value), byteorder="little", signed=False)
    except (TypeError, ValueError) as error:
        raise EncodingError("value is not a valid byte sequence") from error


def int_to_bytes_le(value: int, size: int | None = None) -> bytes:
    """Encode an integer as little-endian bytes, preserving an optional width."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise EncodingError("integer must be a non-negative value")
    if size is not None and (not isinstance(size, int) or isinstance(size, bool) or size < 0):
        raise EncodingError("size must be a non-negative integer")

    minimum_size = max(1, (value.bit_length() + 7) // 8)
    output_size = minimum_size if size is None else size
    if value >= 1 << (8 * output_size):
        raise EncodingError("integer does not fit in the requested size")
    return value.to_bytes(output_size, byteorder="little", signed=False)


def read_input(block_mode: bool = False, input_stream=None) -> bytes:
    """Read stdin, removing one trailing LF in block mode only."""
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
    """Split data into blocks and zero-pad only the final short block."""
    if block_size <= 0:
        raise EncodingError("block size must be positive")
    if not isinstance(data, bytes):
        raise EncodingError("data must be bytes")
    if not data:
        return []

    blocks = [data[index:index + block_size] for index in range(0, len(data), block_size)]
    if len(blocks[-1]) < block_size:
        blocks[-1] = blocks[-1].ljust(block_size, b"\x00")
    return blocks