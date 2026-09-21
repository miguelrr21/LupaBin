import json
from pathlib import Path

from jsonschema import Draft202012Validator

from dissect.evidence.schema import schema_text


def test_generated_schema_is_current():
    assert Path("docs/evidence-schema.json").read_text(encoding="utf-8") == schema_text()


def test_schema_is_valid():
    Draft202012Validator.check_schema(json.loads(schema_text()))
