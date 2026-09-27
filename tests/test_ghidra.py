import base64
import hashlib
import io
import json
import os
import struct
import tarfile
import zipfile
from importlib.resources import files
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lupabin.analysis import analyze_bytes
from lupabin.cli import app
from lupabin.errors import LupaBinError
from lupabin.ghidra import build_bundle, build_document
from tests.fixtures.pe_builder import build_call_demo, build_decode_demo, build_pe
from tests.test_web import analyze, client


def unpack(bundle):
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        assert set(archive.namelist()) == {"lupabin-ghidra.json", "ImportLupaBin.java"}
        return json.loads(archive.read("lupabin-ghidra.json")), archive.read("ImportLupaBin.java")


def test_bundle_preserves_report_and_is_deterministic():
    data = build_pe()
    report = analyze_bytes(data)
    bundle = build_bundle(report, data)
    document, script = unpack(bundle)
    assert document["schema_version"] == "1.0.0"
    assert document["report"] == report.model_dump(mode="json")
    assert build_bundle(report, data) == bundle
    assert script == (files("lupabin.ghidra") / "ImportLupaBin.java").read_bytes()
    assert {a["evidence_id"] for a in document["annotations"]} == {f.id for f in report.evidence}


def test_built_distributions_include_exact_java_resource():
    value = os.environ.get("LUPABIN_DISTRIBUTIONS")
    if not value:
        pytest.skip("LUPABIN_DISTRIBUTIONS no definido: requiere wheel y sdist ya construidos")
    directory = Path(value)
    wheels = list(directory.glob("lupabin-*.whl"))
    sources = list(directory.glob("lupabin-*.tar.gz"))
    assert len(wheels) == len(sources) == 1
    expected = (files("lupabin.ghidra") / "ImportLupaBin.java").read_bytes()
    with zipfile.ZipFile(wheels[0]) as wheel:
        assert wheel.read("lupabin/ghidra/ImportLupaBin.java") == expected
    with tarfile.open(sources[0]) as source:
        names = [
            n for n in source.getnames() if n.endswith("/src/lupabin/ghidra/ImportLupaBin.java")
        ]
        assert len(names) == 1
        member = source.extractfile(names[0])
        assert member is not None
        with member:
            assert member.read() == expected


def test_wrong_sample_hash_is_rejected():
    data = build_pe()
    with pytest.raises(LupaBinError) as error:
        build_bundle(analyze_bytes(data), data + b"different")
    assert error.value.code == "report_mismatch"


def test_saved_literal_bytes_must_match_sample():
    data = build_pe()
    report = analyze_bytes(data)
    raw = report.model_dump()
    fact = next(f for f in raw["evidence"] if f["kind"] == "string")
    text = "Z" * fact["data"]["characters"]
    fact["data"]["text"] = text
    fact["data"]["raw_hex"] = text.encode(fact["data"]["encoding"]).hex()
    with pytest.raises(LupaBinError) as error:
        build_document(type(report).model_validate(raw), data)
    assert error.value.code == "report_mismatch"


def test_offsets_are_not_rvas_and_calls_keep_explicit_rvas():
    data = build_call_demo("LoadLibraryW", {0: "example.dll"})
    report = analyze_bytes(data)
    document = build_document(report, data)
    for annotation in document.annotations:
        fact = next(f for f in report.evidence if f.id == annotation.evidence_id)
        if fact.location is not None:
            assert annotation.rva == fact.location.rva
            assert annotation.offset == fact.location.offset
    call = next(a for a in document.annotations if a.kind == "api_call")
    assert call.offset != call.rva
    string = next(a for a in document.annotations if a.kind == "string")
    assert string.rva is None


def test_decoded_locations_hash_encoded_bytes_not_decoded_text():
    data = build_decode_demo()
    report = analyze_bytes(data)
    document = build_document(report, data)
    decoded = [a for a in document.annotations if a.kind == "decoded_string"]
    assert decoded
    for annotation in decoded:
        fact = next(f for f in report.evidence if f.id == annotation.evidence_id)
        raw = data[annotation.offset : annotation.offset + annotation.length]
        assert annotation.range_sha256 == hashlib.sha256(raw).hexdigest()
        assert (
            annotation.range_sha256 != hashlib.sha256(bytes.fromhex(fact.data.raw_hex)).hexdigest()
        )
        assert annotation.confidence == "inferred"
        assert "codificados" in annotation.text


def test_yara_instances_have_separate_offsets():
    data = build_pe() + b"\0LUPABIN PRACTICE\0LUPABIN PRACTICE\0"
    report = analyze_bytes(data)
    document = build_document(report, data)
    fact = next(f for f in report.evidence if f.kind == "yara_match" and len(f.data.instances) >= 2)
    found = [a for a in document.annotations if a.evidence_id == fact.id]
    assert len(found) == len(fact.data.instances)
    assert [a.offset for a in found] == [i.offset for i in fact.data.instances]
    assert len({a.key for a in found}) == len(found)
    assert all(a.rva is None for a in found)


def test_partiality_and_hostile_text_are_data_only():
    data = bytearray(build_pe(dll=b"{@url https://invalid/}\x1b[31m.dll"))
    struct.pack_into("<I", data, 0x324, 0xF0000000)
    report = analyze_bytes(bytes(data))
    document, script = unpack(build_bundle(report, bytes(data)))
    assert document["report"]["analysis"]["status"] == "partial"
    assert document["report"]["limitations"] == report.model_dump(mode="json")["limitations"]
    texts = " ".join(a["text"] for a in document["annotations"])
    assert "{@" not in texts and "\x1b" not in texts
    assert b"https://invalid/" not in script
    assert document["notice"]


def test_cli_never_overwrites_and_requires_sample(tmp_path):
    data = build_pe()
    report = tmp_path / "report.json"
    sample = tmp_path / "sample.bin"
    output = tmp_path / "ghidra.zip"
    report.write_text(analyze_bytes(data).model_dump_json(), encoding="utf-8")
    sample.write_bytes(data)
    runner = CliRunner()
    args = ["export-ghidra", str(report), "--sample", str(sample), "--output", str(output)]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    before = output.read_bytes()
    result = runner.invoke(app, args)
    assert result.exit_code != 0
    assert output.read_bytes() == before
    assert (
        runner.invoke(app, ["export-ghidra", str(report), "--output", str(output)]).exit_code == 2
    )


def test_cli_mismatch_does_not_create_output_and_partial_exit_is_preserved(tmp_path):
    data = bytearray(build_pe())
    struct.pack_into("<I", data, 0x324, 0xF0000000)
    report = tmp_path / "report.json"
    sample = tmp_path / "sample.bin"
    output = tmp_path / "ghidra.zip"
    report.write_text(analyze_bytes(bytes(data)).model_dump_json(), encoding="utf-8")
    sample.write_bytes(build_pe())
    args = ["export-ghidra", str(report), "--sample", str(sample), "--output", str(output)]
    runner = CliRunner()
    result = runner.invoke(app, args)
    assert result.exit_code == 1
    assert not output.exists()
    assert json.loads(result.stderr)["error"]["code"] == "report_mismatch"
    sample.write_bytes(data)
    assert runner.invoke(app, args).exit_code == 3
    assert output.is_file()


@pytest.mark.parametrize(
    ("limit", "message"),
    [
        ("MAX_DOCUMENT_BYTES", "document exceeds"),
        ("MAX_CHECK_BYTES", "range hashing exceeds"),
        ("MAX_ANNOTATIONS", "annotation count exceeds"),
    ],
)
def test_export_budgets_fail_explicitly(monkeypatch, limit, message):
    data = build_pe()
    report = analyze_bytes(data)
    monkeypatch.setattr(f"lupabin.ghidra.{limit}", 1)
    with pytest.raises(ValueError, match=message):
        build_bundle(report, data)


def test_document_budget_counts_serialized_annotations_before_accumulating(monkeypatch):
    from lupabin.ghidra import Document

    data = build_pe()
    report = analyze_bytes(data)
    empty_size = len(Document(report=report, annotations=()).model_dump_json().encode("utf-8"))
    monkeypatch.setattr("lupabin.ghidra.MAX_DOCUMENT_BYTES", empty_size + 1)
    with pytest.raises(ValueError, match="document exceeds"):
        build_document(report, data)


def test_yara_payload_is_rendered_once_per_fact(monkeypatch):
    from lupabin import ghidra

    data = build_pe() + b"\0LUPABIN PRACTICE\0LUPABIN PRACTICE\0"
    report = analyze_bytes(data)
    rendered = []
    original = ghidra._text

    def traced(fact):
        rendered.append(fact.id)
        return original(fact)

    monkeypatch.setattr(ghidra, "_text", traced)
    document = build_document(report, data)
    assert len(document.annotations) > len(report.evidence)
    assert rendered == [fact.id for fact in report.evidence]


def test_cli_rejects_forged_literal_with_sample(tmp_path):
    data = build_pe()
    raw = analyze_bytes(data).model_dump(mode="json")
    fact = next(f for f in raw["evidence"] if f["kind"] == "string")
    text = "Z" * fact["data"]["characters"]
    fact["data"]["text"] = text
    fact["data"]["raw_hex"] = text.encode(fact["data"]["encoding"]).hex()
    report = tmp_path / "forged.json"
    sample = tmp_path / "sample.bin"
    output = tmp_path / "export.zip"
    report.write_text(json.dumps(raw), encoding="utf-8")
    sample.write_bytes(data)
    result = CliRunner().invoke(
        app, ["export-ghidra", str(report), "--sample", str(sample), "--output", str(output)]
    )
    assert result.exit_code == 1
    assert json.loads(result.stderr)["error"]["code"] == "report_mismatch"
    assert not output.exists()


def test_web_export_stays_inside_concurrency_slot(monkeypatch):
    from lupabin.web.guard import Slots

    active = []

    class TrackedSlots(Slots):
        async def __aenter__(self):
            result = await super().__aenter__()
            active.append(True)
            return result

        async def __aexit__(self, *args):
            active.pop()
            return await super().__aexit__(*args)

    def export(report, data):
        assert active == [True]
        return build_bundle(report, data)

    monkeypatch.setattr("lupabin.web.app.Slots", TrackedSlots)
    monkeypatch.setattr("lupabin.web.app.ghidra_bundle", export)
    response = analyze(client(), build_pe())
    assert response.status_code == 200
    assert response.json()["downloads"]["ghidra"]
    assert not active


def test_web_export_failure_does_not_discard_report(monkeypatch):
    def rejected(*args):
        raise ValueError("invalid export")

    monkeypatch.setattr("lupabin.web.app.ghidra_bundle", rejected)
    response = analyze(client(), build_pe())
    assert response.status_code == 200
    body = response.json()
    assert "ghidra" not in body["downloads"]
    assert body["downloads"]["ghidra_error"]
    assert json.loads(body["downloads"]["report"])["sample"]["sha256"] == body["sample"]["sha256"]


def test_web_download_is_same_bundle_without_new_analysis_or_vt():
    test = client()
    data = build_pe()
    body = analyze(test, data).json()
    bundle = base64.b64decode(body["downloads"]["ghidra"], validate=True)
    document, _ = unpack(bundle)
    assert document["report"] == json.loads(body["downloads"]["report"])
    assert len([a for a, _ in test.docker.calls if a[0] == "start"]) == 1
    assert test.vt_calls == []
    assert 'id="ghidra-download"' in test.get("/").text
