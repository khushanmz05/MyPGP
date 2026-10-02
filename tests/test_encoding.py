import io
import unittest

from encoding import (
    EncodingError,
    bytes_to_hex,
    bytes_to_int_le,
    hex_to_bytes,
    int_to_bytes_le,
    read_input,
    zero_padded_blocks,
)


class EncodingTests(unittest.TestCase):
    def test_hex_round_trip_is_lowercase(self):
        self.assertEqual(hex_to_bytes("67452301"), b"gE#\x01")
        self.assertEqual(bytes_to_hex(b"\xAB\x00\x1f"), "ab001f")

    def test_little_endian_integer_conversion(self):
        value = hex_to_bytes("67452301")
        self.assertEqual(bytes_to_int_le(value), 0x01234567)
        self.assertEqual(int_to_bytes_le(0x01234567, size=4), value)

    def test_message_integer_example(self):
        self.assertEqual(bytes_to_int_le(b"WF"), 18007)

    def test_integer_width_preserves_leading_zeroes(self):
        self.assertEqual(int_to_bytes_le(1, size=4), b"\x01\x00\x00\x00")
        self.assertEqual(int_to_bytes_le(0), b"\x00")

    def test_invalid_hex_and_integer_values(self):
        with self.assertRaises(EncodingError):
            hex_to_bytes("abc")
        with self.assertRaises(EncodingError):
            hex_to_bytes("zz")
        with self.assertRaises(EncodingError):
            int_to_bytes_le(-1)
        with self.assertRaises(EncodingError):
            int_to_bytes_le(256, size=1)

    def test_block_mode_removes_only_trailing_line_feed(self):
        self.assertEqual(read_input(True, io.BytesIO(b"message\n")), b"message")
        self.assertEqual(read_input(True, io.BytesIO(b"message\n\n")), b"message\n")
        self.assertEqual(read_input(False, io.BytesIO(b"message\n")), b"message\n")

    def test_zero_padded_blocks(self):
        self.assertEqual(zero_padded_blocks(b"abcdef", 4), [b"abcd", b"ef\x00\x00"])
        self.assertEqual(zero_padded_blocks(b"abcd", 4), [b"abcd"])
        self.assertEqual(zero_padded_blocks(b"", 4), [])


if __name__ == "__main__":
    unittest.main()