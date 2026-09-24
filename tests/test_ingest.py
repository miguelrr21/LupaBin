import hashlib

import pytest

from dissect.errors import DissectError
from dissect.evidence.models import Limits
from dissect.ingest.reader import read_sample


def test_hashes_match_exact_bytes(tmp_path):
    path = tmp_path / "input"
    path.write_bytes(b"abc")
    blob = read_sample(path, Limits())
    assert blob.data == b"abc"
    assert blob.sample.sha256 == hashlib.sha256(b"abc").hexdigest()
    assert blob.sample.md5 == "900150983cd24fb0d6963f7d28e17f72"
    assert blob.sample.size == 3
    assert blob.sample.type == "unknown"
    assert "path" not in blob.sample.model_dump()


@pytest.mark.parametrize("payload", [b"", b"12345"])
def test_empty_or_oversized_is_rejected(tmp_path, payload):
    path = tmp_path / "private-name"
    path.write_bytes(payload)
    with pytest.raises(DissectError) as caught:
        read_sample(path, Limits(input_bytes=4))
    assert "private-name" not in str(caught.value)


def test_limit_is_inclusive(tmp_path):
    path = tmp_path / "input"
    path.write_bytes(b"1234")
    assert read_sample(path, Limits(input_bytes=4)).sample.size == 4


def test_directory_rejected(tmp_path):
    with pytest.raises(DissectError) as caught:
        read_sample(tmp_path, Limits())
    assert caught.value.code == "input_not_file"


def test_missing_file_rejected(tmp_path):
    with pytest.raises(DissectError) as caught:
        read_sample(tmp_path / "missing-private-name", Limits())
    assert caught.value.code == "input_not_found"
    assert "missing-private-name" not in str(caught.value)


def test_empty_file_has_its_own_reason(tmp_path):
    path = tmp_path / "empty"
    path.write_bytes(b"")
    with pytest.raises(DissectError) as caught:
        read_sample(path, Limits())
    assert caught.value.code == "input_empty"


def test_size_changed_after_open_is_not_trusted(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace

    path = tmp_path / "input"
    path.write_bytes(b"1234")
    original = os.fstat
    calls = 0

    def changed(fd):
        nonlocal calls
        actual = original(fd)
        calls += 1
        return SimpleNamespace(
            st_mode=actual.st_mode, st_size=actual.st_size, st_mtime_ns=actual.st_mtime_ns + calls
        )

    monkeypatch.setattr(os, "fstat", changed)
    with pytest.raises(DissectError) as caught:
        read_sample(path, Limits())
    assert caught.value.code == "input_changed"


def test_stale_stat_cannot_bypass_read_limit(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace

    path = tmp_path / "input"
    path.write_bytes(b"12345")
    actual = path.stat()
    monkeypatch.setattr(
        os,
        "fstat",
        lambda fd: SimpleNamespace(
            st_mode=actual.st_mode, st_size=1, st_mtime_ns=actual.st_mtime_ns
        ),
    )
    with pytest.raises(DissectError) as caught:
        read_sample(path, Limits(input_bytes=4))
    assert caught.value.code == "input_limit"
