import json
import struct

from typer.testing import CliRunner

from dissect.analysis import analyze_bytes
from dissect.cli import app
from dissect.errors import DissectError
from tests.fixtures.pe_builder import build_pe

runner = CliRunner()


def test_help_does_not_require_docker():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "analyze" in result.stdout


def test_cli_json_is_machine_readable(tmp_path, monkeypatch):
    path = tmp_path / "sample"
    path.write_bytes(build_pe())
    monkeypatch.setattr(
        "dissect.cli.analyze_isolated", lambda data, limits: analyze_bytes(data, limits)
    )
    result = runner.invoke(app, ["analyze", str(path), "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["evidence"][0]["id"] == "E1"
    assert result.stderr == ""


def test_no_fallback_when_docker_unavailable(tmp_path, monkeypatch):
    path = tmp_path / "secret-filename"
    path.write_bytes(build_pe())

    def unavailable(data, limits):
        raise DissectError("docker_unavailable")

    monkeypatch.setattr("dissect.cli.analyze_isolated", unavailable)
    result = runner.invoke(app, ["analyze", str(path), "--json"])
    assert result.exit_code == 1
    assert result.stdout == ""
    assert json.loads(result.stderr)["error"]["code"] == "docker_unavailable"
    assert "secret-filename" not in result.stderr


def test_partial_analysis_has_distinct_exit_code(tmp_path, monkeypatch):
    data = bytearray(build_pe())
    struct.pack_into("<I", data, 0x324, 0xF0000000)
    path = tmp_path / "sample"
    path.write_bytes(data)
    monkeypatch.setattr(
        "dissect.cli.analyze_isolated", lambda data, limits: analyze_bytes(data, limits)
    )
    result = runner.invoke(app, ["analyze", str(path), "--json"])
    assert result.exit_code == 3
    assert json.loads(result.stdout)["analysis"]["status"] == "partial"
