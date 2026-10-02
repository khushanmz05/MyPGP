import unittest

from encoding import EncodingError, bytes_to_hex
from xor_cipher import xor_block, xor_bytes, xor_hex


class XorTests(unittest.TestCase):
	def test_block_mode_matches_subject_example(self):
		message = b"You know nothing, Jon Snow"
		key = "576861742069732064656164206d6179206e6576657220646965"
		expected = "20070f2700071c6a4449060a490515164e4e12190b190011063c"

		self.assertEqual(bytes_to_hex(xor_hex(message, key, block_mode=True)), expected)
		self.assertEqual(
			xor_hex(bytes.fromhex(expected), key, block_mode=True, decrypt=True),
			message,
		)

	def test_xor_is_reversible(self):
		message = b"secret message"
		key = b"01234567890123"

		encrypted = xor_bytes(message, key)
		self.assertEqual(xor_bytes(encrypted, key, decrypt=True), message)

	def test_stream_mode_zero_pads_only_the_final_block(self):
		self.assertEqual(xor_bytes(b"abcdef", b"1234"), b"UQQU12UQ")
		self.assertEqual(
			xor_bytes(b"UQQU12UQ", b"1234", decrypt=True),
			b"abcdef\x00\x00",
		)

	def test_exact_stream_blocks_are_not_padded(self):
		message = b"abcdefgh"
		key = b"1234"

		self.assertEqual(len(xor_bytes(message, key)), len(message))

	def test_empty_stream_is_empty(self):
		self.assertEqual(xor_bytes(b"", b"key"), b"")

	def test_block_mode_requires_equal_sizes(self):
		with self.assertRaises(EncodingError):
			xor_bytes(b"short", b"key", block_mode=True, decrypt=True)

	def test_empty_keys_are_rejected(self):
		with self.assertRaises(EncodingError):
			xor_block(b"data", b"")


if __name__ == "__main__":
	unittest.main()
