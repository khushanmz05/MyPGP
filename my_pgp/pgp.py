"""Assignment-compatible hybrid RSA + XOR/AES encryption."""
from .aes import aes_bytes
from .encoding import EncodingError, hex_to_bytes
from .rsa import rsa_decrypt, rsa_encrypt
from .xor_cipher import xor_bytes

def split_hybrid_key(value: str) -> tuple[str, str]:
    if not value or value.isspace():
        raise EncodingError("hybrid key requires SYMMETRIC_KEY RSA_KEY")
    parts = value.split()
    if len(parts) != 2:
        raise EncodingError("hybrid key requires SYMMETRIC_KEY RSA_KEY")
    return parts[0], parts[1]

def pgp_encrypt(message: bytes, combined_key: str, symmetric: str, block_mode: bool = False) -> str:
    symmetric_hex, rsa_key = split_hybrid_key(combined_key)
    key = hex_to_bytes(symmetric_hex)
    encrypted_key = rsa_encrypt(key, rsa_key)
    if symmetric == "aes":
        ciphertext = aes_bytes(message, key, False, block_mode, True)
    elif symmetric == "xor":
        ciphertext = xor_bytes(message, key, block_mode, False)
    else:
        raise EncodingError("PGP symmetric algorithm must be xor or aes")
    return encrypted_key + "\n" + ciphertext.hex()

def pgp_decrypt(ciphertext_hex: str, combined_key: str, symmetric: str, block_mode: bool = False) -> bytes:
    encrypted_key, rsa_key = split_hybrid_key(combined_key)
    key = rsa_decrypt(encrypted_key, rsa_key)
    data = hex_to_bytes("".join(ciphertext_hex.split()))
    if symmetric == "aes":
        return aes_bytes(data, key, True, block_mode, True)
    if symmetric == "xor":
        return xor_bytes(data, key, block_mode, True)
    raise EncodingError("PGP symmetric algorithm must be xor or aes")
