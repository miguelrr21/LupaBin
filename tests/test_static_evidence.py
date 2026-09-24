import struct

import pytest

from dissect.analysis import analyze_bytes
from dissect.evidence.models import Limits
from tests.fixtures.pe_builder import build_pe


def facts(report, kind):
    return [item for item in report.evidence if item.kind == kind]


def test_header_and_section_values_are_original():
    report = analyze_bytes(build_pe())
    assert report.schema_version == "0.6.0"
    header = facts(report, "pe_header")[0]
    assert header.data.timestamp_raw == 0
    assert header.data.machine == 0x14C
    assert "compiled_at" not in report.model_dump_json()
    section = facts(report, "section")[0]
    assert section.data.name_raw_hex == b".idata\0\0".hex()
    assert section.data.raw_offset == 512
    assert section.location.offset == 0x178
    assert section.data.raw_size == 4096
    assert section.data.permissions == ("read",)


@pytest.mark.parametrize(
    "payload,expected",
    [
        (b"\0" * 4096, 0.0),
        (b"\0\1" * 2048, 1.0),
        (bytes(range(256)) * 16, 8.0),
    ],
)
def test_entropy_vectors(payload, expected):
    data = bytearray(build_pe(imports=False))
    data[512:] = payload
    report = analyze_bytes(bytes(data))
    entropy = facts(report, "entropy")[0]
    assert entropy.data.bits_per_byte == expected
    assert entropy.location.offset == 512
    assert entropy.data.byte_count == 4096
    assert entropy.provenance.evidence_ids == (facts(report, "section")[0].id,)
    assert "packed" not in report.model_dump_json()


def test_empty_section_has_no_entropy():
    data = bytearray(build_pe(imports=False))
    struct.pack_into("<I", data, 0x178 + 16, 0)
    report = analyze_bytes(bytes(data))
    assert not facts(report, "entropy")


def test_truncated_section_preserves_declarations_not_fake_measurement():
    report = analyze_bytes(build_pe()[:-100])
    assert facts(report, "pe_header")
    assert facts(report, "section")
    assert not facts(report, "entropy")
    assert any(f.data.code == "section_raw_out_of_bounds" for f in facts(report, "header_anomaly"))
    assert report.analysis.status == "partial"


def test_strings_survive_unknown_format():
    report = analyze_bytes(b"\0literal.example\0")
    assert report.sample.type == "unknown"
    assert report.analysis.status == "partial"
    assert not facts(report, "pe_header")
    assert facts(report, "string")[0].data.text == "literal.example"


@pytest.mark.parametrize("prefix", [b"", b"\0"])
def test_utf16_both_alignments(prefix):
    report = analyze_bytes(prefix + "HELLO".encode("utf-16-le") + b"\0\0")
    items = [f for f in facts(report, "string") if f.data.encoding == "utf-16-le"]
    assert len(items) == 1
    assert items[0].data.text == "HELLO"
    assert items[0].location.offset == len(prefix)
    assert items[0].location.length == 10


def test_string_prefix_is_explicit():
    report = analyze_bytes(b"A" * 1100)
    item = facts(report, "string")[0]
    assert item.data.text == "A" * 1024
    assert item.data.complete is False
    assert item.data.total_characters == 1100
    assert item.location.length == 1024
    assert any(reason.code == "string_length_limit" for reason in report.limitations)


def test_string_quota_is_not_import_quota():
    report = analyze_bytes(build_pe(), Limits(imports=1, strings=1))
    assert len(facts(report, "import")) == 1
    assert len(facts(report, "string")) == 1
    assert any(reason.code == "string_limit" for reason in report.limitations)


def test_no_text_is_completed_scan_not_failed_scan():
    report = analyze_bytes(b"\0\1\2")
    run = next(run for run in report.extractor_runs if run.source == "strings")
    assert run.status == "completed"
    assert run.evidence_count == 0
    assert report.analysis.status == "partial"


def test_entropy_budget_abstains_instead_of_measuring_prefix():
    report = analyze_bytes(build_pe(), Limits(entropy_bytes=100))
    assert not facts(report, "entropy")
    assert any(reason.code == "entropy_limit" for reason in report.limitations)


def export_fixture(*, forwarder=False, bad_name=False, aliases=False):
    data = bytearray(build_pe())
    struct.pack_into("<II", data, 0x98 + 96, 0x1400, 0x100)
    struct.pack_into(
        "<IIHHIIIIIII",
        data,
        0x600,
        0,
        0,
        0,
        0,
        0x1100,
        7,
        2,
        2 if aliases else 1,
        0x1440,
        0x1450,
        0x1460,
    )
    struct.pack_into("<II", data, 0x640, 0x1480 if forwarder else 0x1800, 0)
    struct.pack_into("<II", data, 0x650, 0xFFFFFF if bad_name else 0x1470, 0x1478)
    struct.pack_into("<HH", data, 0x660, 0, 0)
    data[0x670:0x677] = b"Symbol\0"
    data[0x678:0x67E] = b"Alias\0"
    data[0x680:0x68D] = b"other.Target\0"
    return bytes(data)


@pytest.mark.parametrize("forwarder", [False, True])
def test_exports_preserve_symbols_and_forwarders(forwarder):
    report = analyze_bytes(export_fixture(forwarder=forwarder))
    item = facts(report, "export")[0]
    assert item.data.ordinal == 7
    assert item.data.names[0].text == "Symbol"
    assert item.location.offset == 0x640
    assert item.data.target_rva == (0x1480 if forwarder else 0x1800)
    assert (item.data.forwarder.text if item.data.forwarder else None) == (
        "other.Target" if forwarder else None
    )
    assert len(facts(report, "export")) == 1


def test_export_names_corruption_does_not_invent_unnamed_symbol():
    report = analyze_bytes(export_fixture(bad_name=True))
    item = facts(report, "export")[0]
    assert item.data.names_status == "incomplete"
    assert item.data.names == ()
    assert report.analysis.status == "partial"


def test_export_aliases_are_not_lost():
    item = facts(analyze_bytes(export_fixture(aliases=True)), "export")[0]
    assert [name.text for name in item.data.names] == ["Symbol", "Alias"]
