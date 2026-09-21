import struct

import pytest

from dissect.analysis import analyze_bytes
from dissect.evidence.models import Limits
from tests.fixtures.pe_builder import build_pe


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("delay", [False, True])
@pytest.mark.parametrize("ordinal", [None, 0, 1])
def test_original_imports(bits, delay, ordinal):
    report = analyze_bytes(build_pe(bits=bits, delay=delay, ordinal=ordinal))
    assert report.analysis.status == "completed"
    assert report.sample.type == ("PE32" if bits == 32 else "PE32+")
    assert len(report.evidence) == 1
    fact = report.evidence[0]
    assert fact.id == "E1"
    assert fact.data.dll.text == "kernel32.dll"
    assert fact.data.table == ("delay" if delay else "normal")
    assert fact.data.ordinal == ordinal
    assert (fact.data.function.text if fact.data.function else None) == (
        "ExitProcess" if ordinal is None else None
    )
    assert fact.location.offset == 0x320
    assert fact.location.rva == 0x1120
    assert fact.confidence == "observed"


def test_non_ascii_names_are_not_replaced():
    report = analyze_bytes(build_pe(dll=b"\xff.dll", function=b"\xfefunction"))
    assert report.analysis.status == "completed"
    fact = report.evidence[0]
    assert fact.data.dll.raw_hex == b"\xff.dll".hex()
    assert fact.data.dll.text is None
    assert fact.data.function.raw_hex == b"\xfefunction".hex()
    assert fact.data.function.text is None


def test_no_import_table_is_not_a_safety_verdict():
    report = analyze_bytes(build_pe(imports=False))
    assert report.evidence == ()
    assert report.analysis.status == "completed"
    assert report.extractor_runs[0].normal == "complete"
    assert "verdict" not in report.model_dump()


@pytest.mark.parametrize("data", [b"MZ" + b"\0" * 100, b"not a PE", build_pe()[:300]])
def test_malformed_is_never_success(data):
    report = analyze_bytes(data)
    assert report.analysis.status == "failed"
    assert report.sample.type == "unknown"
    assert report.evidence == ()
    assert report.extractor_errors


def test_bad_table_is_not_reported_as_absent():
    data = bytearray(build_pe())
    struct.pack_into("<I", data, 0x200, 0xF0000000)
    report = analyze_bytes(bytes(data))
    assert report.analysis.status == "failed"
    assert report.extractor_runs[0].normal == "partial"
    assert report.extractor_errors[0].code == "invalid_import_table"


def test_valid_evidence_survives_later_corrupt_thunk():
    data = bytearray(build_pe())
    struct.pack_into("<I", data, 0x324, 0xF0000000)
    report = analyze_bytes(bytes(data))
    assert report.analysis.status == "partial"
    assert len(report.evidence) == 1
    assert report.extractor_errors


def test_limit_is_explicit():
    data = bytearray(build_pe())
    struct.pack_into("<I", data, 0x324, 0x1160)
    report = analyze_bytes(bytes(data), Limits(imports=1))
    assert report.analysis.status == "partial"
    assert len(report.evidence) == 1
    assert any(error.code == "import_limit" for error in report.extractor_errors)


def test_pe_warning_prevents_complete_claim():
    data = bytearray(build_pe())
    struct.pack_into("<I", data, 0x98 + 16, 0)
    report = analyze_bytes(bytes(data))
    assert report.analysis.status == "partial"
    assert any(error.code == "parser_warning" for error in report.extractor_errors)


def test_repeatable_facts():
    one = analyze_bytes(build_pe())
    two = analyze_bytes(build_pe())
    assert one.evidence == two.evidence
    assert one.sample == two.sample
    assert one.extractor_runs == two.extractor_runs
