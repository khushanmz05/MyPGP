"""AES-128 encryption and decryption for one 16-byte block."""

from __future__ import annotations

from encoding import EncodingError


S_BOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

INV_S_BOX = tuple(
    next(index for index, value in enumerate(S_BOX) if value == byte)
    for byte in range(256)
)
RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _validate_block(value: bytes, name: str) -> None:
    if not isinstance(value, bytes) or len(value) != 16:
        raise EncodingError(f"{name} must contain exactly 16 bytes")


def _xor(left: list[int], right: list[int]) -> list[int]:
    return [left[index] ^ right[index] for index in range(16)]


def _sub_bytes(state: list[int], box: tuple[int, ...] = S_BOX) -> list[int]:
    return [box[byte] for byte in state]


def _shift_rows(state: list[int]) -> list[int]:
    result = [0] * 16
    for row in range(4):
        for column in range(4):
            result[4 * column + row] = state[4 * ((column + row) % 4) + row]
    return result


def _inverse_shift_rows(state: list[int]) -> list[int]:
    result = [0] * 16
    for row in range(4):
        for column in range(4):
            result[4 * column + row] = state[4 * ((column - row) % 4) + row]
    return result


def _multiply(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        left = ((left << 1) ^ 0x11B) if left & 0x80 else left << 1
        right >>= 1
    return result & 0xFF


def _mix_columns(state: list[int]) -> list[int]:
    result = state[:]
    for column in range(4):
        start = 4 * column
        a0, a1, a2, a3 = state[start:start + 4]
        result[start:start + 4] = [
            _multiply(a0, 2) ^ _multiply(a1, 3) ^ a2 ^ a3,
            a0 ^ _multiply(a1, 2) ^ _multiply(a2, 3) ^ a3,
            a0 ^ a1 ^ _multiply(a2, 2) ^ _multiply(a3, 3),
            _multiply(a0, 3) ^ a1 ^ a2 ^ _multiply(a3, 2),
        ]
    return result


def _inverse_mix_columns(state: list[int]) -> list[int]:
    result = state[:]
    for column in range(4):
        start = 4 * column
        a0, a1, a2, a3 = state[start:start + 4]
        result[start:start + 4] = [
            _multiply(a0, 14) ^ _multiply(a1, 11) ^ _multiply(a2, 13) ^ _multiply(a3, 9),
            _multiply(a0, 9) ^ _multiply(a1, 14) ^ _multiply(a2, 11) ^ _multiply(a3, 13),
            _multiply(a0, 13) ^ _multiply(a1, 9) ^ _multiply(a2, 14) ^ _multiply(a3, 11),
            _multiply(a0, 11) ^ _multiply(a1, 13) ^ _multiply(a2, 9) ^ _multiply(a3, 14),
        ]
    return result


def expand_key(key: bytes) -> list[bytes]:
    """Return the eleven AES-128 round keys."""
    _validate_block(key, "key")
    words = [list(key[index:index + 4]) for index in range(0, 16, 4)]
    for word_index in range(4, 44):
        word = words[word_index - 1][:]
        if word_index % 4 == 0:
            word = [S_BOX[byte] for byte in word[1:] + word[:1]]
            word[0] ^= RCON[word_index // 4]
        words.append([left ^ right for left, right in zip(words[word_index - 4], word)])
    return [bytes(byte for word in words[index:index + 4] for byte in word) for index in range(0, 44, 4)]


def aes_encrypt_standard_block(message: bytes, key: bytes) -> bytes:
    """Encrypt one AES-128 block using the conventional byte layout."""
    _validate_block(message, "message")
    round_keys = expand_key(key)
    state = _xor(list(message), list(round_keys[0]))
    for round_key in round_keys[1:-1]:
        state = _mix_columns(_shift_rows(_sub_bytes(state)))
        state = _xor(state, list(round_key))
    state = _shift_rows(_sub_bytes(state))
    state = _xor(state, list(round_keys[-1]))
    return bytes(state)


def aes_decrypt_standard_block(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt one AES-128 block using the conventional byte layout."""
    _validate_block(ciphertext, "ciphertext")
    round_keys = expand_key(key)
    state = _xor(list(ciphertext), list(round_keys[-1]))
    for round_key in reversed(round_keys[1:-1]):
        state = _inverse_shift_rows(_sub_bytes(state, INV_S_BOX))
        state = _xor(state, list(round_key))
        state = _inverse_mix_columns(state)
    state = _inverse_shift_rows(_sub_bytes(state, INV_S_BOX))
    state = _xor(state, list(round_keys[0]))
    return bytes(state)


def _reverse_words(value: bytes) -> bytes:
    return b"".join(value[index:index + 4][::-1] for index in range(0, 16, 4))


def aes_encrypt_block(message: bytes, key: bytes) -> bytes:
    """Encrypt one project-format AES-128 block."""
    _validate_block(message, "message")
    _validate_block(key, "key")
    return _reverse_words(aes_encrypt_standard_block(message, _reverse_words(key)))


def aes_decrypt_block(ciphertext: bytes, key: bytes) -> bytes:
    """Decrypt one project-format AES-128 block."""
    _validate_block(ciphertext, "ciphertext")
    _validate_block(key, "key")
    return aes_decrypt_standard_block(_reverse_words(ciphertext), _reverse_words(key))