import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src import aes_from_scratch as aes


def test_fips197_vector():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ct = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    ct = aes.encrypt_block(plaintext, key)
    assert ct == expected_ct


def test_round_trip_random_blocks():
    for _ in range(20):
        key = os.urandom(16)
        block = os.urandom(16)
        ct = aes.encrypt_block(block, key)
        pt = aes.decrypt_block(ct, key)
        assert pt == block


def test_different_keys_different_ciphertext():
    block = b"A" * 16
    ct1 = aes.encrypt_block(block, os.urandom(16))
    ct2 = aes.encrypt_block(block, os.urandom(16))
    assert ct1 != ct2
