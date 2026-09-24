import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from dissect.evidence.schema import schema_text


def test_generated_schema_is_current():
    assert Path("docs/evidence-schema.json").read_text(encoding="utf-8") == schema_text()


@pytest.mark.parametrize("version", ["0.1.0", "0.2.0", "0.3.0", "0.4.0", "0.5.0"])
def test_historical_schema_is_preserved(version):
    old = json.loads(Path(f"docs/schemas/{version}.json").read_text(encoding="utf-8"))
    assert old["properties"]["schema_version"]["const"] == version
    Draft202012Validator.check_schema(old)
    assert old != json.loads(schema_text())


def test_schema_is_valid():
    Draft202012Validator.check_schema(json.loads(schema_text()))


def test_real_report_conforms_to_exported_schema():
    from dissect.analysis import analyze_bytes
    from tests.fixtures.pe_builder import build_pe

    report = json.loads(analyze_bytes(build_pe()).model_dump_json())
    Draft202012Validator(json.loads(schema_text())).validate(report)
