"""
aes_from_scratch.py
--------------------
A pure-Python implementation of AES-128 (Rijndael), written purely to teach
how the cipher works internally: key expansion, SubBytes, ShiftRows,
MixColumns and AddRoundKey.

WARNING - EDUCATIONAL ONLY
This implementation is NOT constant-time, NOT audited, and NOT suitable
for protecting real data. The rest of this project (src/crypto_primitives.py,
src/volume.py) uses the vetted `cryptography` library for anything that
actually touches real files/volumes. Use this module only to read the code,
step through it in a debugger, and understand the algorithm.
"""

from __future__ import annotations
from typing import List

# ---------------------------------------------------------------------------
# AES S-box and inverse S-box (standard, from FIPS-197)
# ---------------------------------------------------------------------------
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

Nb = 4   # block size in 32-bit words (always 4 for AES)
Nk = 4   # key size in 32-bit words (4 = AES-128)
Nr = 10  # number of rounds for AES-128


def _xtime(a: int) -> int:
    """Multiply by x (i.e. 2) in GF(2^8) modulo the AES reduction polynomial."""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _gmul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8)."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1B
        b >>= 1
    return result


def key_expansion(key: bytes) -> List[List[int]]:
    """Expand a 16-byte key into Nr+1 round keys (each a list of 16 bytes)."""
    assert len(key) == 16, "aes_from_scratch only supports AES-128 (16-byte keys)"
    w = [list(key[4 * i:4 * i + 4]) for i in range(Nk)]
    for i in range(Nk, Nb * (Nr + 1)):
        temp = list(w[i - 1])
        if i % Nk == 0:
            temp = temp[1:] + temp[:1]              # RotWord
            temp = [SBOX[b] for b in temp]           # SubWord
            temp[0] ^= RCON[i // Nk - 1]
        w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])

    round_keys = []
    for r in range(Nr + 1):
        rk = []
        for c in range(4):
            rk.extend(w[r * 4 + c])
        round_keys.append(rk)
    return round_keys


def _add_round_key(state: List[int], round_key: List[int]) -> List[int]:
    return [state[i] ^ round_key[i] for i in range(16)]


def _sub_bytes(state: List[int]) -> List[int]:
    return [SBOX[b] for b in state]


def _inv_sub_bytes(state: List[int]) -> List[int]:
    return [INV_SBOX[b] for b in state]


def _shift_rows(state: List[int]) -> List[int]:
    # state is column-major: state[r + 4*c]
    s = state[:]
    for r in range(1, 4):
        row = [s[r + 4 * c] for c in range(4)]
        row = row[r:] + row[:r]
        for c in range(4):
            s[r + 4 * c] = row[c]
    return s


def _inv_shift_rows(state: List[int]) -> List[int]:
    s = state[:]
    for r in range(1, 4):
        row = [s[r + 4 * c] for c in range(4)]
        row = row[-r:] + row[:-r]
        for c in range(4):
            s[r + 4 * c] = row[c]
    return s


def _mix_columns(state: List[int]) -> List[int]:
    s = state[:]
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        s[4 * c + 0] = _gmul(col[0], 2) ^ _gmul(col[1], 3) ^ col[2] ^ col[3]
        s[4 * c + 1] = col[0] ^ _gmul(col[1], 2) ^ _gmul(col[2], 3) ^ col[3]
        s[4 * c + 2] = col[0] ^ col[1] ^ _gmul(col[2], 2) ^ _gmul(col[3], 3)
        s[4 * c + 3] = _gmul(col[0], 3) ^ col[1] ^ col[2] ^ _gmul(col[3], 2)
    return s


def _inv_mix_columns(state: List[int]) -> List[int]:
    s = state[:]
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        s[4 * c + 0] = _gmul(col[0], 14) ^ _gmul(col[1], 11) ^ _gmul(col[2], 13) ^ _gmul(col[3], 9)
        s[4 * c + 1] = _gmul(col[0], 9) ^ _gmul(col[1], 14) ^ _gmul(col[2], 11) ^ _gmul(col[3], 13)
        s[4 * c + 2] = _gmul(col[0], 13) ^ _gmul(col[1], 9) ^ _gmul(col[2], 14) ^ _gmul(col[3], 11)
        s[4 * c + 3] = _gmul(col[0], 11) ^ _gmul(col[1], 13) ^ _gmul(col[2], 9) ^ _gmul(col[3], 14)
    return s


def encrypt_block(block: bytes, key: bytes) -> bytes:
    """Encrypt a single 16-byte block with AES-128. Educational, ECB single block."""
    assert len(block) == 16
    round_keys = key_expansion(key)
    state = list(block)
    state = _add_round_key(state, round_keys[0])
    for rnd in range(1, Nr):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[rnd])
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[Nr])
    return bytes(state)


def decrypt_block(block: bytes, key: bytes) -> bytes:
    """Decrypt a single 16-byte block with AES-128."""
    assert len(block) == 16
    round_keys = key_expansion(key)
    state = list(block)
    state = _add_round_key(state, round_keys[Nr])
    for rnd in range(Nr - 1, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[rnd])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, round_keys[0])
    return bytes(state)


if __name__ == "__main__":
    # Quick self-test using the FIPS-197 Appendix B test vector.
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")[:16]
    ct = encrypt_block(plaintext, key)
    pt2 = decrypt_block(ct, key)
    print("plaintext :", plaintext.hex())
    print("ciphertext:", ct.hex())
    print("decrypted :", pt2.hex())
    assert pt2 == plaintext, "round trip failed"
    print("Round-trip OK.")
