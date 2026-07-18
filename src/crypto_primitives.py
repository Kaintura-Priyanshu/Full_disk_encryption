"""
crypto_primitives.py
---------------------
All ACTUAL data-touching cryptography in this project goes through here, and
every primitive below is provided by the `cryptography` library (which wraps
OpenSSL). aes_from_scratch.py exists purely to teach the algorithm; this file
is what real files/volumes are encrypted with.

Design choices (documented for the reader/learner):

* Cipher / mode: AES-256 in XTS mode.
  XTS is the standard mode for disk/sector encryption (used by BitLocker,
  dm-crypt/LUKS in "xts-plain64" configuration, FileVault2, etc.) because it
  is a *tweakable* cipher: identical plaintext sectors encrypt differently
  depending on their sector number, without needing an authentication tag
  per sector (which classic disks have no room for) and without needing a
  random per-sector IV to be stored anywhere.

* Key derivation: scrypt (memory-hard, resists GPU/ASIC brute force better
  than PBKDF2 for password-based keys).

* XTS needs a *32-byte* key for AES-128-XTS or a *64-byte* key for
  AES-256-XTS (the key is really two independent AES keys concatenated).
  We derive 64 bytes of key material and split it in half.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SECTOR_SIZE = 512          # bytes; matches classic disk sector size
XTS_KEY_LEN = 64           # AES-256-XTS -> 32-byte key1 + 32-byte key2
SCRYPT_N = 2 ** 15         # CPU/memory cost parameter (~tens of ms; raise for production)
SCRYPT_R = 8
SCRYPT_P = 1
SALT_LEN = 16


def derive_key(password: str, salt: bytes, length: int = XTS_KEY_LEN) -> bytes:
    """Derive `length` bytes of key material from a password using scrypt."""
    kdf = Scrypt(salt=salt, length=length, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def encrypt_sector(key: bytes, sector_index: int, plaintext: bytes) -> bytes:
    """
    Encrypt exactly one SECTOR_SIZE block of plaintext with AES-256-XTS.
    `sector_index` becomes the XTS "tweak" (must be unique per sector and
    consistent between encrypt/decrypt calls for the same sector).
    """
    if len(plaintext) != SECTOR_SIZE:
        raise ValueError(f"XTS sectors must be exactly {SECTOR_SIZE} bytes")
    tweak = sector_index.to_bytes(16, "little")
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def decrypt_sector(key: bytes, sector_index: int, ciphertext: bytes) -> bytes:
    if len(ciphertext) != SECTOR_SIZE:
        raise ValueError(f"XTS sectors must be exactly {SECTOR_SIZE} bytes")
    tweak = sector_index.to_bytes(16, "little")
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


@dataclass
class DerivedKey:
    key: bytes
    salt: bytes


def derive_from_password(password: str, salt: bytes | None = None) -> DerivedKey:
    salt = salt or new_salt()
    return DerivedKey(key=derive_key(password, salt), salt=salt)
