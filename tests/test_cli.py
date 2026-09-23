import json
import struct

from typer.testing import CliRunner

from dissect.analysis import analyze_bytes
from dissect.cli import app
from dissect.errors import DissectError
from tests.fixtures.pe_builder import build_decode_demo, build_pe

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


def fake_isolation(monkeypatch):
    monkeypatch.setattr(
        "dissect.cli.analyze_isolated", lambda data, limits: analyze_bytes(data, limits)
    )


def saved(tmp_path, monkeypatch, data):
    fake_isolation(monkeypatch)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(data)
    result = runner.invoke(app, ["analyze", str(sample), "--json"])
    report = tmp_path / "report.json"
    report.write_text(result.stdout, encoding="utf-8")
    return sample, report


def test_default_output_is_the_didactic_report(tmp_path, monkeypatch):
    fake_isolation(monkeypatch)
    path = tmp_path / "sample"
    path.write_bytes(build_decode_demo())
    result = runner.invoke(app, ["analyze", str(path)])
    assert result.exit_code == 0
    assert result.stdout.startswith("DISSECT · informe didáctico")
    assert "worker aislado" in result.stdout
    markdown = runner.invoke(app, ["analyze", str(path), "--markdown"])
    assert markdown.stdout.startswith("# Dissect: informe didáctico")
    both = runner.invoke(app, ["analyze", str(path), "--json", "--markdown"])
    assert both.exit_code == 2


def test_explain_says_whether_a_saved_report_was_checked(tmp_path, monkeypatch):
    sample, report = saved(tmp_path, monkeypatch, build_decode_demo())
    unchecked = runner.invoke(app, ["explain", str(report)])
    assert unchecked.exit_code == 0
    assert "sin contrastarlo con la muestra" in unchecked.stdout
    checked = runner.invoke(app, ["explain", str(report), "--sample", str(sample)])
    assert checked.exit_code == 0
    assert "contrastado con la muestra" in checked.stdout
    document = runner.invoke(app, ["explain", str(report), "--format", "json"])
    assert json.loads(document.stdout)["schema_version"] == "0.1.0"


def test_explain_rejects_a_report_that_the_sample_contradicts(tmp_path, monkeypatch):
    sample, report = saved(tmp_path, monkeypatch, build_decode_demo())
    data = json.loads(report.read_text(encoding="utf-8"))
    xor = next(
        f
        for f in data["evidence"]
        if f["kind"] == "decoded_string" and f["transform"]["name"] == "xor-repeating-v1"
    )
    xor["transform"]["key_hex"] = "a6"  # still a valid, canonical key: only the bytes refute it
    report.write_text(json.dumps(data), encoding="utf-8")
    assert runner.invoke(app, ["explain", str(report)]).exit_code == 0  # structurally valid
    result = runner.invoke(app, ["explain", str(report), "--sample", str(sample)])
    assert result.exit_code == 1
    assert json.loads(result.stderr)["error"]["code"] == "report_mismatch"
    other = tmp_path / "other.bin"
    other.write_bytes(build_pe())
    result = runner.invoke(app, ["explain", str(report), "--sample", str(other)])
    assert json.loads(result.stderr)["error"]["code"] == "report_mismatch"


def test_explain_rejects_what_is_not_a_valid_report(tmp_path):
    for content in ("not json", '{"schema_version": "0.4.0"}', ""):
        path = tmp_path / "bad.json"
        path.write_text(content, encoding="utf-8")
        result = runner.invoke(app, ["explain", str(path)])
        assert result.exit_code == 1
        assert json.loads(result.stderr)["error"]["code"] == "invalid_report"
