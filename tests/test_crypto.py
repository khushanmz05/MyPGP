import io
import unittest
from my_pgp.aes import aes_decrypt_standard_block, aes_encrypt_standard_block, aes_bytes
from my_pgp.cli import main
from my_pgp.pipeline import run_pipeline
from my_pgp.rsa import generate_keypair, rsa_decrypt, rsa_encrypt
from my_pgp.xor_cipher import xor_bytes

class AESTests(unittest.TestCase):
    def test_fips_aes_128(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        clear = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(aes_encrypt_standard_block(clear, key), expected)
        self.assertEqual(aes_decrypt_standard_block(expected, key), clear)

    def test_fips_aes_192(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
        clear = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191")
        self.assertEqual(aes_encrypt_standard_block(clear, key), expected)
        self.assertEqual(aes_decrypt_standard_block(expected, key), clear)

    def test_fips_aes_256(self):
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        clear = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        self.assertEqual(aes_encrypt_standard_block(clear, key), expected)
        self.assertEqual(aes_decrypt_standard_block(expected, key), clear)

    def test_project_example(self):
        message = b"All men must die"
        key = bytes.fromhex("57696e74657220697320636f6d696e67")
        encrypted = aes_bytes(message, key, False, True, True)
        self.assertEqual(encrypted.hex(), "744ce22c385958348f0df26eceb62eef")
        self.assertEqual(aes_bytes(encrypted, key, True, True, True), message)

class XORTests(unittest.TestCase):
    def test_subject_example(self):
        msg = b"You know nothing, Jon Snow"
        key = bytes.fromhex("576861742069732064656164206d6179206e6576657220646965")
        encrypted = xor_bytes(msg, key, True, False)
        self.assertEqual(encrypted.hex(), "20070f2700071c6a4449060a490515164e4e12190b190011063c")
        self.assertEqual(xor_bytes(encrypted, key, True, True), msg)

class RSATests(unittest.TestCase):
    def test_subject_small_key(self):
        public, private = generate_keypair("d3", "e3")
        self.assertEqual(public, "0101-19bb")
        self.assertEqual(private, "9d5b-19bb")
        ciphertext = rsa_encrypt(b"WF", public)
        self.assertEqual(ciphertext, "8f84")
        self.assertEqual(rsa_decrypt(ciphertext, private), b"WF")

class PipelineTests(unittest.TestCase):
    def test_composed_round_trip(self):
        steps = [
            {"algorithm": "caesar", "shift": 29},
            {"algorithm": "vigenere", "key": "deadbeef"},
            {"algorithm": "aes", "key": "00112233445566778899aabbccddeeff", "project_format": False},
            {"algorithm": "reverse"},
        ]
        message = b"pipeline message"
        encrypted = run_pipeline(message, steps)
        self.assertEqual(run_pipeline(encrypted, steps, True), message)

class CLITests(unittest.TestCase):
    def test_errors_return_84(self):
        output, error = io.BytesIO(), io.StringIO()
        result = main(["bad", "-c", "00"], io.BytesIO(b"x"), output, error)
        self.assertEqual(result, 84)
        self.assertIn("mypgp:", error.getvalue())

if __name__ == "__main__":
    unittest.main()
