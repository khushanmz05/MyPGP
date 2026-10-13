"""Textbook RSA required by the assignment (little-endian serialization)."""
from __future__ import annotations
from math import gcd
from .encoding import EncodingError, bytes_to_int_le, int_from_hex_le, int_to_bytes_le, int_to_hex_le

FERMAT_PRIMES = (65537, 257, 17, 5, 3)

def lcm(a: int, b: int) -> int:
    return a // gcd(a, b) * b

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def mod_inverse(value: int, modulus: int) -> int:
    g, x, _ = extended_gcd(value, modulus)
    if g != 1:
        raise EncodingError("value has no modular inverse")
    return x % modulus

def parse_key(value: str) -> tuple[int, int]:
    parts = value.split("-")
    if len(parts) != 2:
        raise EncodingError("RSA key must use EXPONENT-MODULUS format")
    exponent, modulus = (int_from_hex_le(part) for part in parts)
    if exponent <= 0 or modulus <= 1:
        raise EncodingError("invalid RSA key components")
    return exponent, modulus

def serialize_key(exponent: int, modulus: int) -> str:
    return f"{int_to_hex_le(exponent)}-{int_to_hex_le(modulus)}"

def generate_keypair(p_hex: str, q_hex: str) -> tuple[str, str]:
    p, q = int_from_hex_le(p_hex), int_from_hex_le(q_hex)
    if p <= 2 or q <= 2 or p == q:
        raise EncodingError("P and Q must be distinct odd primes greater than two")
    modulus = p * q
    lam = lcm(p - 1, q - 1)
    exponent = next((candidate for candidate in FERMAT_PRIMES if candidate < lam and gcd(candidate, lam) == 1), None)
    if exponent is None:
        raise EncodingError("no valid Fermat exponent for these primes")
    private = mod_inverse(exponent, lam)
    return serialize_key(exponent, modulus), serialize_key(private, modulus)

def rsa_transform_int(value: int, key: str) -> int:
    exponent, modulus = parse_key(key)
    if value >= modulus:
        raise EncodingError("message integer must be smaller than the RSA modulus")
    return pow(value, exponent, modulus)

def rsa_encrypt(message: bytes, key: str) -> str:
    return int_to_hex_le(rsa_transform_int(bytes_to_int_le(message), key))

def rsa_decrypt(ciphertext_hex: str, key: str) -> bytes:
    value = rsa_transform_int(int_from_hex_le(ciphertext_hex.strip()), key)
    return int_to_bytes_le(value)
