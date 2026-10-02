import unittest

from aes import (
    aes_decrypt_block,
    aes_decrypt_standard_block,
    aes_encrypt_block,
    aes_encrypt_standard_block,
    expand_key,
)
from encoding import EncodingError, hex_to_bytes


class Aes128Tests(unittest.TestCase):
    def test_nist_aes_128_vector(self):
        key = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
        plaintext = hex_to_bytes("00112233445566778899aabbccddeeff")
        ciphertext = hex_to_bytes("69c4e0d86a7b0430d8cdb78070b4c55a")

        self.assertEqual(aes_encrypt_standard_block(plaintext, key), ciphertext)
        self.assertEqual(aes_decrypt_standard_block(ciphertext, key), plaintext)

    def test_subject_aes_vector(self):
        key = b"Winter is coming"
        plaintext = b"All men must die"
        ciphertext = hex_to_bytes("744ce22c385958348f0df26eceb62eef")

        self.assertEqual(aes_encrypt_block(plaintext, key), ciphertext)
        self.assertEqual(aes_decrypt_block(ciphertext, key), plaintext)

    def test_key_expansion_returns_eleven_round_keys(self):
        keys = expand_key(hex_to_bytes("000102030405060708090a0b0c0d0e0f"))
        self.assertEqual(len(keys), 11)
        self.assertEqual(keys[1].hex(), "d6aa74fdd2af72fadaa678f1d6ab76fe")

    def test_blocks_and_keys_must_be_16_bytes(self):
        with self.assertRaises(EncodingError):
            aes_encrypt_block(b"short", b"0" * 16)
        with self.assertRaises(EncodingError):
            aes_encrypt_block(b"0" * 16, b"short")


if __name__ == "__main__":
    unittest.main()