"""Dependency-free AES-128/192/256 block cipher and project stream mode."""
from .encoding import EncodingError, zero_padded_blocks

def _gmul(a: int, b: int) -> int:
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = ((a << 1) ^ 0x11B) & 0xFF if a & 0x80 else (a << 1) & 0xFF
        b >>= 1
    return result

def _gf_pow(a: int, power: int) -> int:
    result = 1
    while power:
        if power & 1:
            result = _gmul(result, a)
        a = _gmul(a, a)
        power >>= 1
    return result

def _rotl8(value: int, count: int) -> int:
    return ((value << count) | (value >> (8 - count))) & 0xFF

def _make_sbox() -> tuple[int, ...]:
    out = []
    for x in range(256):
        inv = 0 if x == 0 else _gf_pow(x, 254)
        out.append(inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63)
    return tuple(out)

S_BOX = _make_sbox()
INV_S_BOX = tuple(next(i for i, value in enumerate(S_BOX) if value == byte) for byte in range(256))

def _validate_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) not in (16, 24, 32):
        raise EncodingError("AES key must contain 16, 24, or 32 bytes")

def _validate_block(block: bytes, name: str) -> None:
    if not isinstance(block, bytes) or len(block) != 16:
        raise EncodingError(f"{name} must contain exactly 16 bytes")

def _xor(left: list[int], right: bytes | list[int]) -> list[int]:
    return [a ^ b for a, b in zip(left, right)]

def _shift_rows(state: list[int], inverse: bool = False) -> list[int]:
    result = [0] * 16
    for row in range(4):
        for col in range(4):
            source = (col - row) % 4 if inverse else (col + row) % 4
            result[4 * col + row] = state[4 * source + row]
    return result

def _mix_columns(state: list[int], inverse: bool = False) -> list[int]:
    result = state[:]
    matrix = ((14, 11, 13, 9), (9, 14, 11, 13), (13, 9, 14, 11), (11, 13, 9, 14)) if inverse else ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))
    for col in range(4):
        values = state[4 * col:4 * col + 4]
        for row in range(4):
            result[4 * col + row] = _gmul(values[0], matrix[row][0]) ^ _gmul(values[1], matrix[row][1]) ^ _gmul(values[2], matrix[row][2]) ^ _gmul(values[3], matrix[row][3])
    return result

def expand_key(key: bytes) -> list[bytes]:
    _validate_key(key)
    nk = len(key) // 4
    nr = nk + 6
    words = [list(key[i:i + 4]) for i in range(0, len(key), 4)]
    rcon = 1
    for index in range(nk, 4 * (nr + 1)):
        temp = words[index - 1][:]
        if index % nk == 0:
            temp = [S_BOX[x] for x in temp[1:] + temp[:1]]
            temp[0] ^= rcon
            rcon = _gmul(rcon, 2)
        elif nk > 6 and index % nk == 4:
            temp = [S_BOX[x] for x in temp]
        words.append([a ^ b for a, b in zip(words[index - nk], temp)])
    return [bytes(x for word in words[i:i + 4] for x in word) for i in range(0, len(words), 4)]

def aes_encrypt_standard_block(message: bytes, key: bytes) -> bytes:
    _validate_block(message, "message")
    keys = expand_key(key)
    state = _xor(list(message), keys[0])
    for round_key in keys[1:-1]:
        state = [S_BOX[x] for x in state]
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _xor(state, round_key)
    state = _shift_rows([S_BOX[x] for x in state])
    return bytes(_xor(state, keys[-1]))

def aes_decrypt_standard_block(ciphertext: bytes, key: bytes) -> bytes:
    _validate_block(ciphertext, "ciphertext")
    keys = expand_key(key)
    state = _xor(list(ciphertext), keys[-1])
    for round_key in reversed(keys[1:-1]):
        state = _shift_rows(state, True)
        state = [INV_S_BOX[x] for x in state]
        state = _xor(state, round_key)
        state = _mix_columns(state, True)
    state = _shift_rows(state, True)
    state = [INV_S_BOX[x] for x in state]
    return bytes(_xor(state, keys[0]))

def _reverse_words(value: bytes) -> bytes:
    return b"".join(value[i:i + 4][::-1] for i in range(0, len(value), 4))

def aes_encrypt_block(message: bytes, key: bytes, project_format: bool = True) -> bytes:
    _validate_block(message, "message")
    _validate_key(key)
    if not project_format:
        return aes_encrypt_standard_block(message, key)
    return _reverse_words(aes_encrypt_standard_block(message, _reverse_words(key)))

def aes_decrypt_block(ciphertext: bytes, key: bytes, project_format: bool = True) -> bytes:
    _validate_block(ciphertext, "ciphertext")
    _validate_key(key)
    if not project_format:
        return aes_decrypt_standard_block(ciphertext, key)
    return aes_decrypt_standard_block(_reverse_words(ciphertext), _reverse_words(key))

def aes_bytes(data: bytes, key: bytes, decrypt: bool = False, block_mode: bool = False, project_format: bool = True) -> bytes:
    _validate_key(key)
    if block_mode and len(data) != 16:
        raise EncodingError("AES block mode requires exactly 16 bytes")
    if decrypt and len(data) % 16:
        raise EncodingError("AES ciphertext length must be a multiple of 16 bytes")
    blocks = [data] if block_mode else zero_padded_blocks(data, 16)
    transform = aes_decrypt_block if decrypt else aes_encrypt_block
    return b"".join(transform(block, key, project_format) for block in blocks)
