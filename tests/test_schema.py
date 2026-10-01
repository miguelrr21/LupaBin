import json
from pathlib import Path

from jsonschema import Draft202012Validator

from lupabin.evidence.schema import schema_text


def test_generated_schema_is_current():
    assert Path("docs/evidence-schema.json").read_text(encoding="utf-8") == schema_text()


def test_schema_is_valid():
    Draft202012Validator.check_schema(json.loads(schema_text()))


def test_real_report_conforms_to_exported_schema():
    from lupabin.analysis import analyze_bytes
    from tests.fixtures.pe_builder import build_pe

    report = json.loads(analyze_bytes(build_pe()).model_dump_json())
    Draft202012Validator(json.loads(schema_text())).validate(report)
