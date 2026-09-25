import struct

import pytest

from lupabin.analysis import analyze_bytes
from lupabin.evidence.models import Limits
from tests.fixtures.pe_builder import build_pe


def imports(report):
    return [fact for fact in report.evidence if fact.kind == "import"]


def coverage(report, component):
    return next(
        part.status for part in report.extractor_runs[0].components if part.name == component
    )


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("delay", [False, True])
@pytest.mark.parametrize("ordinal", [None, 0, 1])
def test_original_imports(bits, delay, ordinal):
    report = analyze_bytes(build_pe(bits=bits, delay=delay, ordinal=ordinal))
    assert report.analysis.status == "completed"
    assert report.sample.type == ("PE32" if bits == 32 else "PE32+")
    assert len(imports(report)) == 1
    fact = imports(report)[0]
    assert fact.id in {item.id for item in report.evidence}
    assert fact.data.dll.text == "kernel32.dll"
    assert fact.data.table == ("delay" if delay else "normal")
    assert fact.data.ordinal == ordinal
    assert (fact.data.function.text if fact.data.function else None) == (
        "ExitProcess" if ordinal is None else None
    )
    assert fact.location.offset == 0x320
    assert fact.location.rva == 0x1120
    assert fact.data.iat_rva == 0x1140  # the slot calls go through, not the lookup entry
    assert fact.location.section.text == ".idata"
    assert fact.confidence == "observed"


def test_non_ascii_names_are_not_replaced():
    report = analyze_bytes(build_pe(dll=b"\xff.dll", function=b"\xfefunction"))
    assert report.analysis.status == "completed"
    fact = imports(report)[0]
    assert fact.data.dll.raw_hex == b"\xff.dll".hex()
    assert fact.data.dll.text is None
    assert fact.data.function.raw_hex == b"\xfefunction".hex()
    assert fact.data.function.text is None


def test_no_import_table_is_not_a_safety_verdict():
    report = analyze_bytes(build_pe(imports=False))
    assert not imports(report)
    assert report.analysis.status == "completed"
    assert coverage(report, "imports_normal") == "complete"
    assert "verdict" not in report.model_dump()


@pytest.mark.parametrize("data", [b"MZ" + b"\0" * 100, b"not a PE", build_pe()[:300]])
def test_malformed_is_never_success(data):
    report = analyze_bytes(data)
    assert report.analysis.status == "partial"
    assert report.sample.type == "unknown"
    assert all(fact.kind == "string" for fact in report.evidence)
    assert report.extractor_runs[0].status == "failed"
    assert report.extractor_errors


def test_bad_table_is_not_reported_as_absent():
    data = bytearray(build_pe())
    struct.pack_into("<I", data, 0x200, 0xF0000000)
    report = analyze_bytes(bytes(data))
    assert report.analysis.status == "partial"
    assert coverage(report, "imports_normal") == "partial"
    assert report.extractor_errors[0].code == "invalid_import_table"


def test_valid_evidence_survives_later_corrupt_thunk():
    data = bytearray(build_pe())
    struct.pack_into("<I", data, 0x324, 0xF0000000)
    report = analyze_bytes(bytes(data))
    assert report.analysis.status == "partial"
    assert len(imports(report)) == 1
    assert report.extractor_errors


def test_limit_is_explicit():
    data = bytearray(build_pe())
    struct.pack_into("<I", data, 0x324, 0x1160)
    report = analyze_bytes(bytes(data), Limits(imports=1))
    assert report.analysis.status == "partial"
    assert len(imports(report)) == 1
    assert any(reason.code == "import_limit" for reason in report.limitations)


def test_pe_warning_prevents_complete_claim():
    data = bytearray(build_pe())
    struct.pack_into("<I", data, 0x98 + 16, 0)
    report = analyze_bytes(bytes(data))
    assert report.analysis.status == "partial"
    assert any(reason.code == "parser_warning" for reason in report.limitations)


def test_repeatable_facts():
    one = analyze_bytes(build_pe())
    two = analyze_bytes(build_pe())
    assert one.evidence == two.evidence
    assert one.sample == two.sample
    assert one.extractor_runs == two.extractor_runs


def test_truncated_iat_prevents_complete_coverage():
    data = bytearray(build_pe())
    struct.pack_into("<I", data, 0x210, 0x1FFC)
    report = analyze_bytes(bytes(data))
    assert report.analysis.status == "partial"
    assert coverage(report, "imports_normal") == "partial"


def test_bound_iat_without_lookup_is_not_interpreted_as_names():
    data = bytearray(build_pe())
    struct.pack_into("<II", data, 0x200, 0, 1)
    report = analyze_bytes(bytes(data))
    assert report.analysis.status == "partial"
    assert not imports(report)
