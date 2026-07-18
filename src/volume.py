"""
volume.py
---------
A minimal encrypted "container" (think: a toy, file-based stand-in for a
LUKS/BitLocker volume) that stores multiple files inside one encrypted blob,
sector by sector, using AES-256-XTS (see crypto_primitives.py).

On-disk layout (all offsets in units of SECTOR_SIZE = 512 bytes):

    sector 0            -> plaintext header (magic, salt, capacity, next-free-sector)
    sector 1            -> "verifier" block, encrypted; used to check the password
    sectors 2..2+T-1     -> directory table (TOC), encrypted, T = TOC_SECTORS
    sectors 2+T..end     -> data region, encrypted, one file's bytes may span
                            many consecutive sectors

Every sector is encrypted independently with AES-256-XTS, tweaked by its own
absolute sector index, exactly like real full-disk encryption tweaks each
disk sector by its LBA (logical block address).

This is a teaching tool, not a production disk-encryption product: there is
no wear-leveling, no crash-consistency journal, and file deletion is not
implemented (a bump allocator only ever grows).
"""

from __future__ import annotations

import math
import os
import struct
from dataclasses import dataclass
from typing import List, Optional

from . import crypto_primitives as cp

MAGIC = b"PYFDEV01"
HEADER_SECTOR = 0
VERIFIER_SECTOR = 1
TOC_SECTORS = 8                       # 8 * 512 = 4096 bytes of directory space
DATA_START_SECTOR = 2 + TOC_SECTORS

VERIFIER_PLAINTEXT = (b"PYFDE-PASSWORD-OK" + b"\x00" * cp.SECTOR_SIZE)[: cp.SECTOR_SIZE]

# Directory entry: 64-byte name + 8-byte start sector + 8-byte length + 1-byte flag
NAME_LEN = 64
ENTRY_FMT = f"<{NAME_LEN}sQQB"
ENTRY_SIZE = struct.calcsize(ENTRY_FMT)          # 81 bytes
ENTRIES_PER_SECTOR = cp.SECTOR_SIZE // ENTRY_SIZE
MAX_ENTRIES = ENTRIES_PER_SECTOR * TOC_SECTORS

HEADER_FMT = "<8s16sQQQ"   # magic, salt, data_sector_count, toc_sector_count, next_free_sector
HEADER_SIZE = struct.calcsize(HEADER_FMT)


@dataclass
class DirEntry:
    name: str
    start_sector: int   # relative to DATA_START_SECTOR
    length: int         # exact byte length of the file
    in_use: bool = True


class WrongPassword(Exception):
    pass


class VolumeFull(Exception):
    pass


class Volume:
    def __init__(self, path: str, key: bytes, data_sector_count: int,
                 next_free_sector: int, fh):
        self._path = path
        self._key = key
        self._data_sector_count = data_sector_count
        self._next_free_sector = next_free_sector
        self._fh = fh

    # ---------------------------------------------------------------
    # Creation / opening
    # ---------------------------------------------------------------
    @classmethod
    def create(cls, path: str, password: str, size_mb: float) -> "Volume":
        if os.path.exists(path):
            raise FileExistsError(f"{path} already exists")

        data_sector_count = int((size_mb * 1024 * 1024) // cp.SECTOR_SIZE)
        if data_sector_count < 1:
            raise ValueError("size_mb too small: needs at least one 512-byte sector")

        derived = cp.derive_from_password(password)
        total_sectors = DATA_START_SECTOR + data_sector_count

        with open(path, "wb") as fh:
            # Reserve the whole file up front, zero-filled.
            fh.truncate(total_sectors * cp.SECTOR_SIZE)

            header = struct.pack(
                HEADER_FMT, MAGIC, derived.salt, data_sector_count, TOC_SECTORS, 0
            )
            header = header.ljust(cp.SECTOR_SIZE, b"\x00")
            fh.seek(HEADER_SECTOR * cp.SECTOR_SIZE)
            fh.write(header)

            verifier_ct = cp.encrypt_sector(derived.key, VERIFIER_SECTOR, VERIFIER_PLAINTEXT)
            fh.seek(VERIFIER_SECTOR * cp.SECTOR_SIZE)
            fh.write(verifier_ct)

            # Zero out (encrypted) TOC sectors so an empty directory reads back clean.
            empty_entries = bytes(cp.SECTOR_SIZE)
            for i in range(TOC_SECTORS):
                sector_index = 2 + i
                ct = cp.encrypt_sector(derived.key, sector_index, empty_entries)
                fh.seek(sector_index * cp.SECTOR_SIZE)
                fh.write(ct)

        return cls.open(path, password)

    @classmethod
    def open(cls, path: str, password: str) -> "Volume":
        fh = open(path, "r+b")
        fh.seek(HEADER_SECTOR * cp.SECTOR_SIZE)
        header_raw = fh.read(cp.SECTOR_SIZE)[:HEADER_SIZE]
        magic, salt, data_sector_count, toc_sector_count, next_free_sector = struct.unpack(
            HEADER_FMT, header_raw
        )
        if magic != MAGIC:
            fh.close()
            raise ValueError("Not a valid PYFDE container (bad magic)")
        if toc_sector_count != TOC_SECTORS:
            fh.close()
            raise ValueError("Unsupported container version (TOC size mismatch)")

        key = cp.derive_key(password, salt)

        fh.seek(VERIFIER_SECTOR * cp.SECTOR_SIZE)
        verifier_ct = fh.read(cp.SECTOR_SIZE)
        try:
            verifier_pt = cp.decrypt_sector(key, VERIFIER_SECTOR, verifier_ct)
        except Exception as exc:  # pragma: no cover - defensive
            fh.close()
            raise WrongPassword("Incorrect password") from exc

        if verifier_pt != VERIFIER_PLAINTEXT:
            fh.close()
            raise WrongPassword("Incorrect password")

        return cls(path, key, data_sector_count, next_free_sector, fh)

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "Volume":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ---------------------------------------------------------------
    # Low-level sector I/O
    # ---------------------------------------------------------------
    def _write_sector(self, absolute_sector: int, plaintext: bytes) -> None:
        plaintext = plaintext.ljust(cp.SECTOR_SIZE, b"\x00")[: cp.SECTOR_SIZE]
        ct = cp.encrypt_sector(self._key, absolute_sector, plaintext)
        self._fh.seek(absolute_sector * cp.SECTOR_SIZE)
        self._fh.write(ct)

    def _read_sector(self, absolute_sector: int) -> bytes:
        self._fh.seek(absolute_sector * cp.SECTOR_SIZE)
        ct = self._fh.read(cp.SECTOR_SIZE)
        return cp.decrypt_sector(self._key, absolute_sector, ct)

    def _write_header(self) -> None:
        header = struct.pack(
            HEADER_FMT, MAGIC, self._salt(), self._data_sector_count,
            TOC_SECTORS, self._next_free_sector,
        )
        header = header.ljust(cp.SECTOR_SIZE, b"\x00")
        self._fh.seek(HEADER_SECTOR * cp.SECTOR_SIZE)
        self._fh.write(header)

    def _salt(self) -> bytes:
        self._fh.seek(HEADER_SECTOR * cp.SECTOR_SIZE)
        header_raw = self._fh.read(cp.SECTOR_SIZE)[:HEADER_SIZE]
        _, salt, *_ = struct.unpack(HEADER_FMT, header_raw)
        return salt

    # ---------------------------------------------------------------
    # Directory table (TOC)
    # ---------------------------------------------------------------
    def _read_toc(self) -> List[DirEntry]:
        entries: List[DirEntry] = []
        raw = b""
        for i in range(TOC_SECTORS):
            raw += self._read_sector(2 + i)
        for i in range(MAX_ENTRIES):
            chunk = raw[i * ENTRY_SIZE:(i + 1) * ENTRY_SIZE]
            if len(chunk) < ENTRY_SIZE:
                break
            name_raw, start_sector, length, in_use = struct.unpack(ENTRY_FMT, chunk)
            if in_use:
                name = name_raw.rstrip(b"\x00").decode("utf-8", errors="replace")
                entries.append(DirEntry(name, start_sector, length, True))
        return entries

    def _write_toc(self, entries: List[DirEntry]) -> None:
        if len(entries) > MAX_ENTRIES:
            raise VolumeFull(f"Directory full (max {MAX_ENTRIES} files)")
        buf = bytearray(TOC_SECTORS * cp.SECTOR_SIZE)
        for i, e in enumerate(entries):
            name_bytes = e.name.encode("utf-8")[:NAME_LEN].ljust(NAME_LEN, b"\x00")
            packed = struct.pack(ENTRY_FMT, name_bytes, e.start_sector, e.length, 1)
            buf[i * ENTRY_SIZE:(i + 1) * ENTRY_SIZE] = packed
        for i in range(TOC_SECTORS):
            sector_index = 2 + i
            chunk = bytes(buf[i * cp.SECTOR_SIZE:(i + 1) * cp.SECTOR_SIZE])
            self._write_sector(sector_index, chunk)

    # ---------------------------------------------------------------
    # Public file operations
    # ---------------------------------------------------------------
    def list_files(self) -> List[DirEntry]:
        return self._read_toc()

    def add_file(self, name: str, data: bytes) -> None:
        entries = self._read_toc()
        if any(e.name == name for e in entries):
            raise FileExistsError(f"'{name}' already exists in this container")

        sectors_needed = max(1, math.ceil(len(data) / cp.SECTOR_SIZE))
        if self._next_free_sector + sectors_needed > self._data_sector_count:
            raise VolumeFull("Not enough free space in the container")

        start_sector = self._next_free_sector
        for i in range(sectors_needed):
            chunk = data[i * cp.SECTOR_SIZE:(i + 1) * cp.SECTOR_SIZE]
            self._write_sector(DATA_START_SECTOR + start_sector + i, chunk)

        entries.append(DirEntry(name=name, start_sector=start_sector, length=len(data)))
        self._write_toc(entries)

        self._next_free_sector += sectors_needed
        self._write_header()

    def extract_file(self, name: str) -> bytes:
        entries = self._read_toc()
        match = next((e for e in entries if e.name == name), None)
        if match is None:
            raise FileNotFoundError(f"'{name}' not found in this container")

        sectors_needed = max(1, math.ceil(match.length / cp.SECTOR_SIZE))
        out = bytearray()
        for i in range(sectors_needed):
            out += self._read_sector(DATA_START_SECTOR + match.start_sector + i)
        return bytes(out[: match.length])

    def free_space_bytes(self) -> int:
        return (self._data_sector_count - self._next_free_sector) * cp.SECTOR_SIZE

    def capacity_bytes(self) -> int:
        return self._data_sector_count * cp.SECTOR_SIZE
