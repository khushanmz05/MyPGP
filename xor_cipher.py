"""XOR encryption for fixed-size blocks and byte streams."""

from __future__ import annotations

from encoding import EncodingError, hex_to_bytes, zero_padded_blocks


def xor_block(message: bytes, key: bytes, decrypt: bool = False) -> bytes:
	"""XOR one little-endian number block with a same-size key."""
	if not isinstance(message, bytes) or not isinstance(key, bytes):
		raise EncodingError("message and key must be bytes")
	if not key:
		raise EncodingError("key must not be empty")
	if len(message) != len(key):
		raise EncodingError("message and key blocks must have the same size")
	if decrypt:
		return bytes(
			reversed(
				bytes(message_byte ^ key_byte for message_byte, key_byte in zip(message, key))
			)
		)
	return bytes(
		message_byte ^ key_byte for message_byte, key_byte in zip(reversed(message), key)
	)


def xor_bytes(
	message: bytes,
	key: bytes,
	block_mode: bool = False,
	decrypt: bool = False,
) -> bytes:
	"""XOR bytes with a key in the subject's little-endian format."""
	if not isinstance(message, bytes) or not isinstance(key, bytes):
		raise EncodingError("message and key must be bytes")
	if not key:
		raise EncodingError("key must not be empty")

	if block_mode:
		return xor_block(message, key, decrypt=decrypt)

	return b"".join(
		xor_block(block, key, decrypt=decrypt)
		for block in zero_padded_blocks(message, len(key))
	)


def xor_hex(
	message: bytes,
	key_hex: str,
	block_mode: bool = False,
	decrypt: bool = False,
) -> bytes:
	"""XOR a byte message with a hexadecimal key."""
	return xor_bytes(
		message,
		hex_to_bytes(key_hex),
		block_mode=block_mode,
		decrypt=decrypt,
	)
