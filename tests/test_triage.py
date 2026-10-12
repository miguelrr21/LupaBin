import json
import struct

import pytest
from pydantic import ValidationError

from lupabin.analysis import analyze_bytes
from lupabin.errors import LupaBinError
from lupabin.evidence.models import Limits, Report
from lupabin.evidence.triage_checks import verify_triage
from lupabin.explain.engine import explain, validate
from lupabin.extractors.pe import PEExtractor
from lupabin.glossary.catalog import load_glossary
from lupabin.ingest.reader import from_bytes
from lupabin.saved_report import check_against_sample, load_report
from tests.fixtures.pe_builder import build_demo
from tests.test_pe_resources import _block, _tree, _version
from tests.test_pe_triage import _GUID_BYTES, _PE, _certificate

GLOSSARY = load_glossary()
KINDS = ("pdb_reference", "certificate_entry", "overlay", "version_string")
PARTS = ("debug_info", "certificates", "overlay", "version_info")
PDB_PATH = b"C:\\build\\demo\\demo.pdb"
RECORD_AT = 0xA40
TREE_AT = 0x1200


def _text(value: str) -> bytes:
    return (value + "\0").encode("utf-16-le")


def build(
    bits=32,
    *,
    path=PDB_PATH,
    strings=(("CompanyName", "Lupa Example"), ("OriginalFilename", "demo.exe")),
    raw_strings=(),
    before=b"OVERLAY!",
    table=None,
    after=b"tail",
):
    """The demo with a debug directory, a version resource in a third section, a
    certificate table and bytes around it."""
    data = bytearray(build_demo(bits=bits))
    opt = 0x98
    directories = opt + (96 if bits == 32 else 112)
    section = opt + (224 if bits == 32 else 240)
    record = b"RSDS" + _GUID_BYTES + struct.pack("<I", 3) + path + b"\0"
    data[RECORD_AT : RECORD_AT + len(record)] = record
    struct.pack_into("<IIHHIIII", data, 0xA00, 0, 0, 0, 0, 2, len(record), 0x2440, RECORD_AT)
    struct.pack_into("<II", data, directories + 6 * 8, 0x2400, 28)
    blocks = tuple(_block(key, _text(value)) for key, value in strings) + tuple(raw_strings)
    tree = _tree(_version(*blocks))
    raw = tree + b"\0" * (-len(tree) % 0x200)
    struct.pack_into("<H", data, 0x86, 3)
    third = section + 80
    data[third : third + 8] = b".rsrc\0\0\0"
    struct.pack_into("<IIII", data, third + 8, len(tree), 0x3000, len(raw), TREE_AT)
    struct.pack_into("<I", data, third + 36, 0x40000040)
    struct.pack_into("<I", data, opt + 56, 0x3000 + ((len(raw) + 0xFFF) & ~0xFFF))
    struct.pack_into("<II", data, directories + 2 * 8, 0x3000, len(tree))
    data.extend(raw)
    data.extend(before)
    table = _certificate(b"not a real signature") if table is None else table
    if table:
        struct.pack_into("<II", data, directories + 4 * 8, len(data), len(table))
    data.extend(table + after)
    return bytes(data)


def facts(report, kind):
    return [fact for fact in report.evidence if fact.kind == kind]


def parts(report):
    run = next(run for run in report.extractor_runs if run.source == "pe")
    return {part.name: part.status for part in run.components if part.name in PARTS}


def reasons(report):
    return {
        (reason.component, reason.code)
        for reason in (*report.extractor_errors, *report.limitations)
        if reason.component in PARTS
    }


def changed(report, kind, index=0, **changes):
    """The report as JSON with fields of one fact changed, for the validators."""
    document = json.loads(report.model_dump_json())
    fact = [item for item in document["evidence"] if item["kind"] == kind][index]
    for path, value in changes.items():
        target = fact
        *parents, leaf = path.split(".")
        for parent in parents:
            target = target[parent]
        target[leaf] = value
    return json.dumps(document)


@pytest.mark.parametrize("bits", [32, 64])
def test_each_triage_fact_is_published_from_its_own_bytes(bits):
    data = build(bits=bits)
    report = analyze_bytes(data)
    assert set(parts(report).values()) == {"complete"}
    assert not reasons(report)
    (pdb,) = facts(report, "pdb_reference")
    assert pdb.data.guid == "00112233-4455-6677-8899-aabbccddeeff"
    assert (pdb.data.age, pdb.data.path.text) == (3, PDB_PATH.decode())
    assert (pdb.location.offset, pdb.location.length) == (RECORD_AT, 24 + len(PDB_PATH) + 1)
    assert [(s.data.key, s.data.value) for s in facts(report, "version_string")] == [
        ("CompanyName", "Lupa Example"),
        ("OriginalFilename", "demo.exe"),
    ]
    assert {(s.data.language, s.data.codepage) for s in facts(report, "version_string")} == {
        (0x409, 0x4B0)
    }
    (entry,) = facts(report, "certificate_entry")
    assert (entry.data.revision, entry.data.certificate_type, entry.data.padding) == (0x200, 2, 4)
    assert entry.location.length == 8 + len(b"not a real signature")
    first, second = facts(report, "overlay")
    assert data[first.location.offset :][: first.location.length] == b"OVERLAY!"
    assert data[second.location.offset :] == b"tail"
    assert all(fact.confidence == "observed" for kind in KINDS for fact in facts(report, kind))
    verify_triage(report.evidence, data, report.analysis.limits.string_characters)


def _gap_certificate(bits, table):
    pe = _PE(bits)
    struct.pack_into("<H", pe.data, 0x86, 2)
    struct.pack_into("<IIII", pe.data, pe.section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<IIII", pe.data, pe.section + 48, 0x200, 0x2000, 0x200, 0x600)
    pe.data.extend(b"\0" * 0x200 + b"tail")
    pe.data[0x480 : 0x480 + len(table)] = table
    pe.directory(4, 0x480, len(table))
    return pe


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("count", [1, 2])
def test_pipeline_declares_gap_certificates_unpublished_without_changing_the_tail(bits, count):
    pe = _gap_certificate(bits, _certificate(b"invented") * count)
    assert pe.read().certificates.status == "complete"
    data = bytes(pe.data)
    report = analyze_bytes(data, extractors=[PEExtractor()])
    assert not facts(report, "certificate_entry")
    assert parts(report)["certificates"] == "partial"
    assert parts(report)["overlay"] == "complete"
    assert reasons(report) == {("certificates", "triage_unreadable")}
    (overlay,) = facts(report, "overlay")
    assert (overlay.location.offset, overlay.location.length) == (0x800, 4)
    assert overlay.confidence == "observed"
    verify_triage(report.evidence, data, report.analysis.limits.string_characters)


@pytest.mark.parametrize("bits", [32, 64])
def test_saved_gap_report_is_verified_by_the_host(tmp_path, bits):
    data = bytes(_gap_certificate(bits, _certificate(b"invented")).data)
    report = analyze_bytes(data, extractors=[PEExtractor()])
    path = tmp_path / "report.json"
    path.write_text(report.model_dump_json(), encoding="utf-8")
    restored = load_report(path, Limits())
    assert restored == report
    check_against_sample(restored, from_bytes(data, Limits()))
    path.write_text(changed(report, "overlay", **{"data.sha256": "0" * 64}), encoding="utf-8")
    forged = load_report(path, Limits())
    with pytest.raises(LupaBinError) as caught:
        check_against_sample(forged, from_bytes(data, Limits()))
    assert caught.value.code == "report_mismatch"


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("before", [b"", b"PREFIX!!"])
def test_certificates_at_or_after_the_tail_keep_padding_and_table_order(bits, before):
    pe = _PE(bits)
    table = _certificate(b"abc") + _certificate(b"second")
    start = pe.certificate_table(table, before, b"tail")
    data = bytes(pe.data)
    report = analyze_bytes(data, extractors=[PEExtractor()])
    first, second = facts(report, "certificate_entry")
    assert (first.data.index, first.location.offset, first.location.length) == (0, start, 11)
    assert first.data.padding == 5
    assert (second.data.index, second.location.offset, second.location.length) == (
        1,
        start + 16,
        14,
    )
    assert second.data.padding == 2
    assert parts(report)["certificates"] == "complete"
    assert parts(report)["overlay"] == "complete"
    restored = Report.model_validate_json(report.model_dump_json())
    check_against_sample(restored, from_bytes(data, Limits()))
    forged = Report.model_validate_json(
        changed(report, "certificate_entry", **{"data.content_sha256": "0" * 64})
    )
    with pytest.raises(LupaBinError) as caught:
        check_against_sample(forged, from_bytes(data, Limits()))
    assert caught.value.code == "report_mismatch"
    with pytest.raises(ValidationError):
        Report.model_validate_json(
            changed(report, "certificate_entry", index=1, **{"location.offset": start + 8})
        )


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("defect", ["alignment", "padding_missing", "padding_nonzero", "overlap"])
def test_invalid_gap_tables_still_block_overlay_and_publish_no_certificates(bits, defect):
    table = _certificate(b"abc")
    pe = _gap_certificate(bits, table)
    if defect == "alignment":
        pe.directory(4, 0x481, len(table))
    elif defect == "padding_missing":
        pe.directory(4, 0x480, 11)
    elif defect == "padding_nonzero":
        pe.data[0x480 + 11] = 1
    else:
        pe.directory(4, 0x3F8, len(table))
    report = analyze_bytes(bytes(pe.data), extractors=[PEExtractor()])
    assert not facts(report, "certificate_entry")
    assert not facts(report, "overlay")
    assert parts(report)["certificates"] == "partial"
    assert parts(report)["overlay"] == "blocked"
    assert reasons(report) == {
        ("certificates", "triage_unreadable"),
        ("overlay", "dependency_omitted"),
    }


def test_a_file_without_these_data_has_no_fact_and_complete_coverage():
    report = analyze_bytes(build_demo())
    assert not any(facts(report, kind) for kind in KINDS)
    assert set(parts(report).values()) == {"complete"}


def test_every_fact_is_explained_with_its_limit():
    report = analyze_bytes(build())
    explanation = explain(report, GLOSSARY)
    rules = {item.rule: item for item in explanation.items}
    assert {
        "debug.pdb@1",
        "version.strings@1",
        "signature.certificates@1",
        "overlay.data@1",
    } <= set(rules)
    assert "demo.pdb" in rules["debug.pdb@1"].statement
    assert "CompanyName = «Lupa Example»" in rules["version.strings@1"].statement
    assert "no descodifica ni valida" in rules["signature.certificates@1"].not_proven
    assert "12 bytes" in rules["overlay.data@1"].statement
    assert len(validate(explanation, report, GLOSSARY)) == len(explanation.items)


def test_a_record_without_a_path_is_an_identifier_only():
    report = analyze_bytes(build(path=b""))
    (pdb,) = facts(report, "pdb_reference")
    assert pdb.data.path is None
    rules = [item.rule for item in explain(report, GLOSSARY).items]
    assert "debug.pdb_unnamed@1" in rules and "debug.pdb@1" not in rules


def test_a_long_version_table_is_summarised_without_losing_citations():
    strings = tuple((f"Key{index}", "x" * 200) for index in range(14))
    report = analyze_bytes(build(strings=strings))
    assert len(facts(report, "version_string")) == 14
    item = next(i for i in explain(report, GLOSSARY).items if i.rule == "version.strings@1")
    assert len(item.evidence_ids) == 14
    assert "y 2 más" in item.statement and "(200 caracteres)" in item.statement


def test_a_table_that_cannot_be_walked_publishes_no_entry_and_no_overlay():
    broken = struct.pack("<IHH", 4096, 0x200, 2) + b"\0" * 8
    report = analyze_bytes(build(table=broken))
    assert not facts(report, "certificate_entry") and not facts(report, "overlay")
    assert parts(report)["certificates"] == "partial"
    assert parts(report)["overlay"] == "blocked"
    assert reasons(report) == {
        ("certificates", "triage_unreadable"),
        ("overlay", "dependency_omitted"),
    }


def test_an_unterminated_version_value_is_left_out_and_declared():
    bad = _block("Comments", "no terminator".encode("utf-16-le"))
    report = analyze_bytes(build(raw_strings=(bad,)))
    assert [s.data.key for s in facts(report, "version_string")] == [
        "CompanyName",
        "OriginalFilename",
    ]
    assert parts(report)["version_info"] == "partial"
    assert ("version_info", "triage_unreadable") in reasons(report)


def test_a_value_over_the_character_limit_is_left_out_and_declared():
    report = analyze_bytes(build(strings=(("Comments", "x" * 1025), ("ProductName", "Lupa"))))
    assert [s.data.key for s in facts(report, "version_string")] == ["ProductName"]
    assert ("version_info", "triage_limit") in reasons(report)


@pytest.mark.parametrize(
    "kind,changes",
    [
        ("pdb_reference", {"data.guid": "00112233-4455-6677-8899-aabbccddeef0"}),
        ("pdb_reference", {"data.age": 4}),
        ("pdb_reference", {"data.path": None}),
        ("pdb_reference", {"location.length": 20}),
        ("pdb_reference", {"location.rva": 0x2440}),
        ("pdb_reference", {"component": "toolchain"}),
        ("version_string", {"data.value": "Another Company"}),
        ("version_string", {"data.key": "ProductName"}),
        ("version_string", {"provenance.evidence_ids": ["E1"]}),
        ("certificate_entry", {"data.certificate_type": 1}),
        ("certificate_entry", {"data.padding": 0}),
        ("certificate_entry", {"data.index": 1}),
        ("certificate_entry", {"location.offset": 0x100}),
        ("overlay", {"location.offset": 0x400}),
        ("overlay", {"location.length": 64}),
    ],
)
def test_a_report_that_misstates_a_fact_is_rejected(kind, changes):
    report = analyze_bytes(build())
    with pytest.raises(ValidationError):
        Report.model_validate_json(changed(report, kind, **changes))


@pytest.mark.parametrize(
    "kind,changes",
    [
        ("pdb_reference", {"data.debug_index": 1}),
        ("version_string", {"data.language": 0x0C0A}),
        ("version_string", {"data.codepage": 1252}),
        ("certificate_entry", {"data.content_sha256": "0" * 64}),
        ("overlay", {"data.sha256": "0" * 64}),
    ],
)
def test_the_host_rejects_what_the_sample_does_not_hold(kind, changes):
    data = build()
    report = analyze_bytes(data)
    altered = Report.model_validate_json(changed(report, kind, **changes))
    with pytest.raises(ValueError):
        verify_triage(altered.evidence, data, altered.analysis.limits.string_characters)


def test_the_host_rejects_a_report_of_other_bytes():
    data = build()
    report = analyze_bytes(data)
    other = bytearray(data)
    other[-1] ^= 1
    with pytest.raises(ValueError):
        verify_triage(report.evidence, bytes(other), report.analysis.limits.string_characters)
    moved = bytearray(data)
    moved[RECORD_AT + 4] ^= 1
    with pytest.raises(ValueError):
        verify_triage(report.evidence, bytes(moved), report.analysis.limits.string_characters)
