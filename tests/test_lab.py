import io
import json
import zipfile

from typer.testing import CliRunner

from lupabin.analysis import analyze_bytes
from lupabin.cli import app
from lupabin.lab import build_lab_bundle
from lupabin.saved_report import CHECKED
from tests.fixtures.pe_builder import build_capability_demo, build_pe

EXPECTED_ENTRIES = {
    "GUIA_DOCENTE.md",
    "evidencias-ghidra.zip",
    "informe.json",
    "informe.md",
    "resumen.html",
    "reto.json",
}


def test_lab_bundle_contains_deterministic_teaching_artifacts():
    data = build_capability_demo()
    report = analyze_bytes(data)
    first = build_lab_bundle(report, data, origin=CHECKED)
    second = build_lab_bundle(report, data, origin=CHECKED)
    assert first == second

    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        assert set(archive.namelist()) == EXPECTED_ENTRIES
        guide = archive.read("GUIA_DOCENTE.md").decode("utf-8")
        assert report.sample.sha256 in guide
        assert "lupabin challenge informe.json --answers respuestas.json" in guide
        reto = json.loads(archive.read("reto.json").decode("utf-8"))
        assert reto["challenge"]["questions"]
        assert reto["answers_template"]["challenge_id"] == reto["challenge"]["id"]
        html_doc = archive.read("resumen.html").decode("utf-8")
        assert report.sample.sha256 in html_doc
        assert report.sample.sha256 in archive.read("informe.md").decode("utf-8")
        with zipfile.ZipFile(io.BytesIO(archive.read("evidencias-ghidra.zip"))) as ghidra_zip:
            assert set(ghidra_zip.namelist()) == {"lupabin-ghidra.json", "ImportLupaBin.java"}


def test_cli_export_lab_creates_bundle_and_refuses_overwrite(tmp_path):
    data = build_capability_demo()
    report_obj = analyze_bytes(data)
    report_path = tmp_path / "report.json"
    sample_path = tmp_path / "sample.bin"
    output_path = tmp_path / "lab.zip"
    report_path.write_text(report_obj.model_dump_json(), encoding="utf-8")
    sample_path.write_bytes(data)

    runner = CliRunner()
    args = [
        "export-lab",
        str(report_path),
        "--sample",
        str(sample_path),
        "--output",
        str(output_path),
    ]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    assert output_path.is_file()

    before = output_path.read_bytes()
    again = runner.invoke(app, args)
    assert again.exit_code == 2
    assert output_path.read_bytes() == before

    # Verify extracted report.json and answers_template work directly with lupabin challenge
    with zipfile.ZipFile(output_path) as archive:
        extracted_report = tmp_path / "informe.json"
        extracted_answers = tmp_path / "respuestas.json"
        extracted_report.write_bytes(archive.read("informe.json"))
        reto = json.loads(archive.read("reto.json").decode("utf-8"))
        extracted_answers.write_text(json.dumps(reto["answers_template"]), encoding="utf-8")
    graded = runner.invoke(
        app,
        ["challenge", str(extracted_report), "--answers", str(extracted_answers), "--json"],
    )
    assert graded.exit_code == 0, graded.output
    assert json.loads(graded.stdout)["result"]["challenge_id"] == reto["challenge"]["id"]


def test_cli_export_lab_rejects_mismatched_sample(tmp_path):
    data = build_capability_demo()
    report_path = tmp_path / "report.json"
    sample_path = tmp_path / "other.bin"
    output_path = tmp_path / "lab.zip"
    report_path.write_text(analyze_bytes(data).model_dump_json(), encoding="utf-8")
    sample_path.write_bytes(build_pe())

    result = CliRunner().invoke(
        app,
        [
            "export-lab",
            str(report_path),
            "--sample",
            str(sample_path),
            "--output",
            str(output_path),
        ],
    )
    assert result.exit_code == 1
    assert json.loads(result.stderr)["error"]["code"] == "report_mismatch"
    assert not output_path.exists()
