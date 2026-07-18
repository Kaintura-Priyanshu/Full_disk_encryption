# PyFDE — A Full-Disk-Encryption Project

A small, from-first-principles project for learning how full-disk encryption
(FDE) actually works under the hood — the block cipher, the key derivation,
the disk-sector encryption mode, and the container format that ties it all
together — implemented in Python.

This is **not** a replacement for LUKS, BitLocker, FileVault, or VeraCrypt.
It's a teaching project: readable code, a real test suite, and a README that
explains *why* each design choice was made.

## What's inside

| File | Purpose |
|---|---|
| `src/aes_from_scratch.py` | Pure-Python AES-128 (Rijndael) implemented from the FIPS-197 spec — key expansion, `SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey`. **Educational only** (see warning below). |
| `src/crypto_primitives.py` | The cryptography actually used to protect data: AES-256-**XTS** (the disk-encryption mode used by BitLocker/LUKS/FileVault) + **scrypt** key derivation, both via the audited [`cryptography`](https://cryptography.io) library. |
| `src/volume.py` | The container ("virtual encrypted disk") format: plaintext header, password-verifier block, encrypted directory table, encrypted data sectors. |
| `src/cli.py` | `pyfde init / add / extract / list` command-line tool. |
| `tests/` | pytest suite: known-answer test vector for AES, round-trip tests, wrong-password rejection, full-container handling, and a test that greps the raw container bytes for the plaintext to prove it isn't there. |
| `examples/demo.py` | Runnable, narrated walkthrough of the whole system. |

## Why two crypto modules?

Writing AES yourself is one of the best ways to actually understand block
ciphers — so `aes_from_scratch.py` exists purely so you can read it, step
through it, and see the FIPS-197 test vector pass. But hand-rolled crypto is
never something you should trust with real data (no side-channel hardening,
no constant-time guarantees, easy to get subtly wrong). So the actual file
encryption in this project — `crypto_primitives.py` and `volume.py` — goes
through the well-reviewed `cryptography` library instead. That split mirrors
how real systems work: engineers study the primitives but ship vetted
implementations.

## How real FDE informed the design

- **AES-XTS mode**: Disks are addressed in fixed-size sectors with no room to
  store a random IV or authentication tag per sector. XTS solves this by
  using the sector number itself as a cryptographic "tweak," so two sectors
  with identical plaintext still produce different ciphertext, without extra
  storage overhead. This is exactly why BitLocker, dm-crypt/LUKS, and
  FileVault 2 all use it.
- **scrypt key derivation**: deriving the disk key straight from a password
  would make offline brute-forcing cheap. scrypt is memory-hard, which makes
  large-scale password guessing significantly more expensive on GPUs/ASICs.
- **Password verifier block**: a small known-plaintext block encrypted with
  the derived key, stored so the tool can say "wrong password" immediately
  instead of silently returning garbage.
- **Sector-addressed container**: files are split across fixed 512-byte
  sectors and independently encrypted, matching how a real disk-encryption
  layer sits *underneath* the filesystem rather than encrypting a single
  monolithic blob.

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run the guided demo
python3 examples/demo.py

# Run the test suite
pytest tests/ -v

# Use the CLI
python3 -m src.cli init my_vault.pyfde --size-mb 10
python3 -m src.cli add my_vault.pyfde ./notes.txt
python3 -m src.cli list my_vault.pyfde
python3 -m src.cli extract my_vault.pyfde notes.txt --out ./restored.txt
```

## Container format

```
sector 0            plaintext header  (magic, salt, capacity, next-free-sector)
sector 1            password verifier (AES-256-XTS encrypted known plaintext)
sectors 2..9         directory table  (AES-256-XTS encrypted, 8 sectors = 4096 bytes)
sectors 10..end      file data        (AES-256-XTS encrypted, 512 bytes/sector)
```

Every sector — including directory and data sectors — is encrypted
independently, tweaked by its own absolute sector index, so identical
512-byte blocks anywhere in the container still encrypt to different
ciphertext.

## Limitations (by design — this is a learning project)

- No file deletion (bump allocator only grows); no wear-leveling.
- No crash-consistency journal — a crash mid-write can corrupt the directory
  table.
- No per-sector authentication (like real disk-sector encryption, XTS trades
  authentication for the ability to fit in a fixed sector size — a limitation
  worth understanding, not a bug to "fix" here).
- `aes_from_scratch.py` is not constant-time and must never be used for
  anything you actually want kept secret.

## Suggested extensions (good next steps if you want to keep learning)

- Add a Merkle-tree or HMAC-based integrity layer on top of the XTS sectors
  (this is essentially what dm-integrity / dm-verity add to dm-crypt).
- Implement AES-256-XTS yourself in `aes_from_scratch.py` style, and diff
  your ciphertext against `cryptography`'s output for the same key/tweak.
- Add file deletion with a free-sector bitmap.
- Add a FUSE filesystem front-end so the container mounts like a real drive.

## License

MIT — see `LICENSE`.
