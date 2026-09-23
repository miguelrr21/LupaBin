import pytest

from tests.fixtures.pe_builder import build_decode_demo, build_pe, main


def test_generator_creates_expected_bytes(tmp_path, monkeypatch):
    path = tmp_path / "practice.bin"
    monkeypatch.setattr("sys.argv", ["pe_builder", "--output", str(path)])
    main()
    assert path.read_bytes() == build_pe()


def test_generator_never_overwrites_existing_file(tmp_path, monkeypatch):
    path = tmp_path / "existing"
    path.write_bytes(b"preserve")
    monkeypatch.setattr("sys.argv", ["pe_builder", "--output", str(path)])
    with pytest.raises(FileExistsError):
        main()
    assert path.read_bytes() == b"preserve"


def test_yara_limited_fixture_is_reproducible(tmp_path, monkeypatch):
    path = tmp_path / "limited.bin"
    monkeypatch.setattr(
        "sys.argv", ["pe_builder", "--scenario", "yara-limited", "--output", str(path)]
    )
    main()
    assert path.read_bytes() == build_pe() + b"DISSECT PRACTICE\0" * 20


def test_decode_demo_fixture_is_reproducible(tmp_path, monkeypatch):
    path = tmp_path / "decode.bin"
    monkeypatch.setattr(
        "sys.argv", ["pe_builder", "--scenario", "decode-demo", "--output", str(path)]
    )
    main()
    assert path.read_bytes() == build_decode_demo()
    assert path.read_bytes().startswith(build_pe())
