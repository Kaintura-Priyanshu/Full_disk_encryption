import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src import volume as vol


@pytest.fixture
def container_path():
    with tempfile.TemporaryDirectory() as d:
        yield os.path.join(d, "test.pyfde")


def test_create_and_reopen(container_path):
    v = vol.Volume.create(container_path, "correct-horse", size_mb=1)
    v.close()

    v2 = vol.Volume.open(container_path, "correct-horse")
    assert v2.list_files() == []
    v2.close()


def test_wrong_password_rejected(container_path):
    v = vol.Volume.create(container_path, "correct-horse", size_mb=1)
    v.close()

    with pytest.raises(vol.WrongPassword):
        vol.Volume.open(container_path, "wrong-password")


def test_add_and_extract_roundtrip(container_path):
    payload = os.urandom(3000)  # spans multiple 512-byte sectors
    with vol.Volume.create(container_path, "hunter2", size_mb=1) as v:
        v.add_file("secret.bin", payload)

    with vol.Volume.open(container_path, "hunter2") as v:
        out = v.extract_file("secret.bin")
        assert out == payload
        names = [e.name for e in v.list_files()]
        assert names == ["secret.bin"]


def test_duplicate_name_rejected(container_path):
    with vol.Volume.create(container_path, "pw", size_mb=1) as v:
        v.add_file("a.txt", b"hello")
        with pytest.raises(FileExistsError):
            v.add_file("a.txt", b"again")


def test_volume_full_raises(container_path):
    # A tiny container: 1 data sector past header/verifier/TOC overhead.
    with vol.Volume.create(container_path, "pw", size_mb=0.01) as v:
        capacity = v.capacity_bytes()
        with pytest.raises(vol.VolumeFull):
            v.add_file("too_big.bin", os.urandom(capacity + 1024))


def test_ciphertext_does_not_contain_plaintext(container_path):
    secret = b"THIS_IS_MY_SECRET_MARKER_STRING"
    with vol.Volume.create(container_path, "pw", size_mb=1) as v:
        v.add_file("s.bin", secret * 20)

    with open(container_path, "rb") as f:
        raw = f.read()
    assert secret not in raw
