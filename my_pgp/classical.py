"""Educational classical ciphers suitable for composition."""
from .encoding import EncodingError

def caesar(data: bytes, shift: int, decrypt: bool = False) -> bytes:
    amount = (-shift if decrypt else shift) % 256
    return bytes((value + amount) % 256 for value in data)

def vigenere(data: bytes, key: bytes, decrypt: bool = False) -> bytes:
    if not key:
        raise EncodingError("Vigenere key must not be empty")
    direction = -1 if decrypt else 1
    return bytes((value + direction * key[index % len(key)]) % 256 for index, value in enumerate(data))

def reverse_bytes(data: bytes, decrypt: bool = False) -> bytes:
    return data[::-1]
