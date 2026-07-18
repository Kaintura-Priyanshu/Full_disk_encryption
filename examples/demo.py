import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src import aes_from_scratch as aes
from src import volume as vol


def demo_aes_internals():
    print("=" * 70)
    print("1) Pure-Python AES-128 (educational) — single block round trip")
    print("=" * 70)
    key = os.urandom(16)
    block = b"Hello, AES demo!"  # exactly 16 bytes
    ct = aes.encrypt_block(block, key)
    pt = aes.decrypt_block(ct, key)
    print(f"key:        {key.hex()}")
    print(f"plaintext:  {block!r}")
    print(f"ciphertext: {ct.hex()}")
    print(f"decrypted:  {pt!r}")
    assert pt == block
    print("OK: decrypt(encrypt(x)) == x\n")


def demo_container():
    print("=" * 70)
    print("2) Encrypted container (AES-256-XTS, scrypt-derived key)")
    print("=" * 70)
    with tempfile.TemporaryDirectory() as d:
        container_path = os.path.join(d, "demo.pyfde")
        password = "correct-horse-battery-staple"
        secret_data = b"These bytes should never appear in the container file.\n" * 20

        with vol.Volume.create(container_path, password, size_mb=1) as v:
            v.add_file("secret_notes.txt", secret_data)
            print(f"Created container, capacity = {v.capacity_bytes()} bytes")

        with vol.Volume.open(container_path, password) as v:
            print("Files inside container:")
            for e in v.list_files():
                print(f"  - {e.name} ({e.length} bytes)")
            extracted = v.extract_file("secret_notes.txt")
            assert extracted == secret_data
            print("OK: extracted bytes match original exactly\n")

        print("=" * 70)
        print("3) Confirming the plaintext is NOT visible in the container file")
        print("=" * 70)
        with open(container_path, "rb") as f:
            raw = f.read()
        needle = b"These bytes should never appear"
        assert needle not in raw
        print(f"OK: the phrase {needle!r} does not appear anywhere in "
              f"the {len(raw)}-byte container file.\n")

        print("=" * 70)
        print("4) Wrong password is rejected")
        print("=" * 70)
        try:
            vol.Volume.open(container_path, "totally-wrong-password")
            print("FAIL: should have raised WrongPassword")
        except vol.WrongPassword:
            print("OK: wrong password correctly rejected\n")


if __name__ == "__main__":
    demo_aes_internals()
    demo_container()
    print("Demo complete.")
