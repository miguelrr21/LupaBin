import pytest

from tests.fixtures.pe_builder import build_pe, main


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
