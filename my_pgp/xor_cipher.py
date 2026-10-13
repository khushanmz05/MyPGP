"""XOR block and zero-padded stream modes in the subject's byte layout."""
from .encoding import EncodingError, zero_padded_blocks

def xor_block(message: bytes, key: bytes, decrypt: bool = False) -> bytes:
    if not isinstance(message, bytes) or not isinstance(key, bytes):
        raise EncodingError("message and key must be bytes")
    if not key or len(message) != len(key):
        raise EncodingError("message and key blocks must have the same non-zero size")
    mixed = bytes(a ^ b for a, b in zip(message, key))
    return mixed[::-1] if decrypt else bytes(a ^ b for a, b in zip(message[::-1], key))

def xor_bytes(message: bytes, key: bytes, block_mode: bool = False, decrypt: bool = False) -> bytes:
    if not key:
        raise EncodingError("key must not be empty")
    if block_mode:
        return xor_block(message, key, decrypt)
    if decrypt and len(message) % len(key):
        raise EncodingError("ciphertext length must be a multiple of the XOR key size")
    return b"".join(xor_block(block, key, decrypt) for block in zero_padded_blocks(message, len(key)))
