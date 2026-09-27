import base64
import io
import json
import zipfile

from typer.testing import CliRunner

from lupabin.analysis import analyze_bytes
from lupabin.cli import app
from lupabin.evidence.models import Report
from tests.fixtures.pe_builder import build_pe
from tests.test_web import analyze, client


def test_one_web_report_preserves_facts_and_offers_both_learning_tools():
    data = build_pe()
    response = analyze(client(), data)
    assert response.status_code == 200
    body = response.json()
    report = Report.model_validate_json(body["downloads"]["report"])
    assert body["challenge"]["challenge"]["sample_sha256"] == report.sample.sha256
    with zipfile.ZipFile(io.BytesIO(base64.b64decode(body["downloads"]["ghidra"]))) as archive:
        assert set(archive.namelist()) == {"lupabin-ghidra.json", "ImportLupaBin.java"}
        exported = json.loads(archive.read("lupabin-ghidra.json"))
    assert exported["report"] == report.model_dump(mode="json")
    assert body["virustotal"] is None


def test_challenge_sample_check_rejects_forged_literal_before_generating_questions(tmp_path):
    literal = "LUPABIN LITERAL PROOF"
    data = build_pe() + b"\0" + literal.encode() + b"\0"
    document = analyze_bytes(data).model_dump(mode="json")
    fact = next(
        item
        for item in document["evidence"]
        if item["kind"] == "string" and item["data"]["text"] == literal
    )
    fact["data"]["text"] = "Z" * len(literal)
    fact["data"]["raw_hex"] = fact["data"]["text"].encode().hex()
    forged = Report.model_validate_json(json.dumps(document))
    sample = tmp_path / "sample.bin"
    saved = tmp_path / "report.json"
    sample.write_bytes(data)
    saved.write_text(forged.model_dump_json(), encoding="utf-8")
    result = CliRunner().invoke(app, ["challenge", str(saved), "--sample", str(sample), "--json"])
    assert result.exit_code == 1
    assert json.loads(result.stderr)["error"]["code"] == "report_mismatch"
    assert not result.stdout
