import io
import json

from lupabin.evidence.models import Limits, Report
from lupabin.worker import process
from tests.fixtures.pe_builder import build_pe


def test_worker_round_trip():
    output, errors = io.BytesIO(), io.BytesIO()
    assert process(io.BytesIO(build_pe()), output, errors, Limits()) == 0
    report = Report.model_validate_json(output.getvalue())
    fact = next(f for f in report.evidence if f.kind == "import")
    assert fact.data.dll.text == "kernel32.dll"
    assert errors.getvalue() == b""


def test_worker_does_not_emit_truncated_json():
    output, errors = io.BytesIO(), io.BytesIO()
    assert process(io.BytesIO(build_pe()), output, errors, Limits(output_bytes=10)) == 1
    assert output.getvalue() == b""
    assert json.loads(errors.getvalue())["error"]["code"] == "output_limit"


def test_worker_rejects_oversized_input():
    output, errors = io.BytesIO(), io.BytesIO()
    assert process(io.BytesIO(b"12345"), output, errors, Limits(input_bytes=4)) == 1
    assert output.getvalue() == b""
    assert json.loads(errors.getvalue())["error"]["code"] == "input_limit"
