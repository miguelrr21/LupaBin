import json
import struct

import pytest
from pydantic import ValidationError

from dissect.analysis import analyze_bytes
from dissect.evidence.models import Limits, Report
from tests.fixtures.pe_builder import build_demo, build_pe
from tests.test_static_evidence import export_fixture, facts


@pytest.mark.parametrize("bits", [32, 64])
def test_demo_is_complete_and_covers_new_kinds(bits):
    report = analyze_bytes(build_demo(bits=bits))
    assert report.analysis.status == "completed"
    assert len(facts(report, "section")) == 2
    assert len(facts(report, "entropy")) == 2
    assert len(facts(report, "export")) == 1
    assert any(f.data.text == "DISSECT PRACTICE" for f in facts(report, "string"))


def test_duplicate_names_remain_distinct_sections():
    data = bytearray(build_demo())
    data[0x1A0:0x1A8] = data[0x178:0x180]
    sections = facts(analyze_bytes(bytes(data)), "section")
    assert [f.data.index for f in sections] == [0, 1]
    assert sections[0].data.name_raw_hex == sections[1].data.name_raw_hex


@pytest.mark.parametrize(
    "offset,value,code",
    [
        (0x1A0 + 20, 0x200, "section_raw_overlap"),
        (0x1A0 + 12, 0x1000, "section_virtual_overlap"),
        (0x1A0 + 8, 0x5000, "section_exceeds_image"),
        (0x98 + 16, 0xFFFF, "entry_point_outside_image"),
    ],
)
def test_anomalies_have_real_structural_references(offset, value, code):
    data = bytearray(build_demo())
    struct.pack_into("<I", data, offset, value)
    report = analyze_bytes(bytes(data))
    found = [f for f in facts(report, "header_anomaly") if f.data.code == code]
    assert len(found) == 1
    refs = {f.id: f for f in report.evidence}
    assert all(
        refs[ref].kind in ("section", "pe_header") for ref in found[0].provenance.evidence_ids
    )


def test_header_timestamps_are_not_dates():
    data = bytearray(build_pe())
    struct.pack_into("<I", data, 0x88, 0xFFFFFFFF)
    assert facts(analyze_bytes(bytes(data)), "pe_header")[0].data.timestamp_raw == 0xFFFFFFFF


def test_section_unicode_name_is_preserved_without_replacement():
    data = bytearray(build_pe())
    raw = "é".encode().ljust(8, b"\0")
    data[0x178:0x180] = raw
    item = facts(analyze_bytes(bytes(data)), "section")[0]
    assert item.data.name_raw_hex == raw.hex()
    assert item.data.name_text == "é"


def test_strings_keep_duplicate_locations_and_threshold():
    report = analyze_bytes(b"abc\0ABCD\0ABCD\0")
    strings = facts(report, "string")
    assert [f.data.text for f in strings] == ["ABCD", "ABCD"]
    assert [f.location.offset for f in strings] == [4, 9]


def test_string_encodings_are_merged_by_offset_before_quota():
    data = "WIDE".encode("utf-16-le") + b"\0\0LATER\0"
    strings = facts(analyze_bytes(data, Limits(strings=1)), "string")
    assert len(strings) == 1
    assert strings[0].data.encoding == "utf-16-le"


def test_export_ordinal_overflow_abstains():
    data = bytearray(export_fixture())
    struct.pack_into("<I", data, 0x610, 0xFFFFFFFF)
    struct.pack_into("<I", data, 0x644, 0x1800)
    report = analyze_bytes(bytes(data))
    assert len(facts(report, "export")) == 1
    assert report.analysis.status == "partial"
    assert any(reason.code == "invalid_export_table" for reason in report.extractor_errors)


def test_exports_without_names_are_not_dictionary_completed():
    data = bytearray(export_fixture())
    struct.pack_into("<I", data, 0x618, 0)
    item = facts(analyze_bytes(bytes(data)), "export")[0]
    assert item.data.names == ()
    assert item.data.names_status == "complete"


@pytest.mark.parametrize(
    "limit,code",
    [
        ({"exports": 1}, "export_limit"),
        ({"export_names": 1}, "export_name_limit"),
    ],
)
def test_export_quotas_are_explicit(limit, code):
    report = analyze_bytes(export_fixture(aliases=True), Limits(**limit))
    assert any(reason.code == code for reason in report.limitations)
    assert report.analysis.status == "partial"


def test_output_budget_keeps_valid_references_and_explains_omissions():
    limits = Limits(output_bytes=1024 * 1024 + 1500)
    report = analyze_bytes(build_demo(), limits)
    assert report.analysis.status == "partial"
    ids = {f.id for f in report.evidence}
    assert all(set(f.provenance.evidence_ids) <= ids for f in report.evidence)
    assert any(r.code in ("evidence_budget", "dependency_omitted") for r in report.limitations)
    assert len(report.model_dump_json().encode()) < limits.output_bytes


@pytest.mark.parametrize(
    "mutation",
    [
        lambda f: f["data"].update(bits_per_byte=float("nan")),
        lambda f: f["data"].update(bits_per_byte=float("inf")),
        lambda f: f["data"].update(bits_per_byte=9.0),
        lambda f: f["data"].update(byte_count=1),
        lambda f: f.update(provenance={"evidence_ids": ["E1"]}),
    ],
)
def test_entropy_contract_rejects_invalid_measurement(mutation):
    data = json.loads(analyze_bytes(build_pe()).model_dump_json())
    item = next(f for f in data["evidence"] if f["kind"] == "entropy")
    mutation(item)
    with pytest.raises(ValidationError):
        Report.model_validate_json(json.dumps(data))


def test_string_contract_rejects_fabricated_text():
    data = json.loads(analyze_bytes(build_pe()).model_dump_json())
    item = next(f for f in data["evidence"] if f["kind"] == "string")
    item["data"]["text"] = "fabricated"
    with pytest.raises(ValidationError):
        Report.model_validate_json(json.dumps(data))


def test_report_rejects_type_that_disagrees_with_header():
    data = json.loads(analyze_bytes(build_pe()).model_dump_json())
    data["sample"]["type"] = "PE32+"
    with pytest.raises(ValidationError):
        Report.model_validate_json(json.dumps(data))


def test_anomaly_must_be_supported_by_its_referenced_fields():
    data = json.loads(analyze_bytes(build_demo(corrupt=True)).model_dump_json())
    item = next(f for f in data["evidence"] if f["kind"] == "header_anomaly")
    item["data"]["code"] = "section_raw_overlap"
    with pytest.raises(ValidationError):
        Report.model_validate_json(json.dumps(data))


def test_section_limit_is_not_an_absent_section():
    report = analyze_bytes(build_demo(), Limits(sections=1))
    assert len(facts(report, "section")) == 1
    assert any(reason.code == "section_limit" for reason in report.limitations)
    assert report.analysis.status == "partial"
