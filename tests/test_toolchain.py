import json
import struct

import pytest
from pydantic import ValidationError

from lupabin.analysis import analyze_bytes
from lupabin.evidence import toolchain
from lupabin.evidence.facts import ToolchainData
from lupabin.evidence.models import Report
from lupabin.evidence.toolchain_checks import verify_markers
from lupabin.explain.engine import explain, validate
from lupabin.glossary.catalog import load_glossary
from tests.fixtures.pe_builder import (
    GCC_IDENT,
    build_demo,
    build_toolchain_demo,
    go_header,
    pyinstaller_cookie,
    rich_header,
)

GLOSSARY = load_glossary()


def markers(report):
    return {fact.data.marker: fact for fact in report.evidence if fact.kind == "toolchain_marker"}


def toolchain_run(report):
    run = next(run for run in report.extractor_runs if run.source == "pe")
    return next(part for part in run.components if part.name == "toolchain")


def tampered(report, marker, **changes):
    """The report as JSON with one marker's fields changed, for the validator."""
    document = json.loads(report.model_dump_json())
    for fact in document["evidence"]:
        if fact["kind"] == "toolchain_marker" and fact["data"]["marker"] == marker:
            for path, value in changes.items():
                target = fact
                *parents, leaf = path.split(".")
                for parent in parents:
                    target = target[parent]
                target[leaf] = value
    return json.dumps(document)


@pytest.mark.parametrize("bits", [32, 64])
def test_each_marker_is_published_where_its_tool_puts_it(bits):
    data = build_toolchain_demo(bits=bits)
    report = analyze_bytes(data)
    found = markers(report)
    assert set(found) == set(toolchain.MARKERS)
    assert found["rich_header"].location.offset == 0x40
    assert found["gcc_ident"].data.text == GCC_IDENT[:-1].decode()
    assert found["go_buildinfo"].data.text == "go1.26.5"
    assert found["go_buildinfo"].location.rva == 0x2600
    assert found["clr_header"].location.rva == 0x2800
    assert found["clr_header"].data.text == "2.5"
    assert found["pyinstaller_cookie"].data.text == "python311.dll"
    assert all(fact.confidence == "observed" for fact in found.values())
    assert toolchain_run(report).status == "complete"
    assert toolchain_run(report).examined == len(toolchain.MARKERS)
    verify_markers(report.evidence, data)


def test_a_plain_file_has_no_marker_and_complete_coverage():
    report = analyze_bytes(build_demo())
    assert not markers(report)
    assert toolchain_run(report).status == "complete"


def test_a_repeated_ident_is_published_once_per_text():
    other = b"GCC: (Rev3, Built by MSYS2 project) 14.1.0\0"
    report = analyze_bytes(build_toolchain_demo(idents=(GCC_IDENT, other, GCC_IDENT)))
    texts = [
        fact.data.text
        for fact in report.evidence
        if fact.kind == "toolchain_marker" and fact.data.marker == "gcc_ident"
    ]
    assert texts == [GCC_IDENT[:-1].decode(), other[:-1].decode()]


def test_more_distinct_idents_than_the_quota_leave_the_component_partial():
    idents = tuple(f"GCC: (GNU) {n}.1.0\0".encode() for n in range(toolchain.GCC_IDENTS + 1))
    data = bytearray(build_toolchain_demo())
    at = 0x1000  # .rdata, after the fixture's own markers
    for ident in idents:
        data[at : at + len(ident)] = ident
        at += 32
    report = analyze_bytes(bytes(data))
    published = [f for f in report.evidence if f.kind == "toolchain_marker"]
    assert sum(f.data.marker == "gcc_ident" for f in published) == toolchain.GCC_IDENTS
    assert toolchain_run(report).status == "partial"
    assert any(r.code == "toolchain_limit" for r in report.limitations)


def test_a_rich_header_with_a_wrong_checksum_is_not_published():
    report = analyze_bytes(build_toolchain_demo(rich_key=0x12345678))
    assert "rich_header" not in markers(report)


def test_a_changed_byte_before_the_rich_header_fails_the_host_check():
    data = build_toolchain_demo()
    report = analyze_bytes(data)
    changed = bytearray(data)
    changed[0x10] ^= 1  # inside the DOS header, covered by the checksum
    with pytest.raises(ValueError, match="checksum"):
        verify_markers(report.evidence, bytes(changed))


def test_e_lfanew_is_not_part_of_the_rich_checksum():
    prefix = bytearray(0x40)
    prefix[:2] = b"MZ"
    pairs = ((0x01045D10, 3),)
    key = toolchain.rich_checksum(bytes(prefix), pairs)
    struct.pack_into("<I", prefix, 0x3C, 0x12345678)
    assert toolchain.rich_checksum(bytes(prefix), pairs) == key
    raw = rich_header(bytes(prefix), pairs)
    assert toolchain.rich_entries(raw) == (key, pairs)


@pytest.mark.parametrize("flags", [0x31, 0x4])
def test_a_go_header_with_unknown_flags_is_not_published(flags):
    data = bytearray(build_toolchain_demo())
    header = go_header(flags=flags)
    data[0xC00 : 0xC00 + len(header)] = header
    assert "go_buildinfo" not in markers(analyze_bytes(bytes(data)))


def test_an_unaligned_go_header_is_not_published():
    data = bytearray(build_toolchain_demo())
    data[0xC00:0xC40] = bytes(0x40)
    header = go_header()
    data[0xC04 : 0xC04 + len(header)] = header  # RVA 0x2604
    assert "go_buildinfo" not in markers(analyze_bytes(bytes(data)))


def test_compiler_strings_outside_the_sections_are_not_published():
    data = build_demo() + GCC_IDENT + b"Mingw-w64 runtime failure:\n\0"
    found = markers(analyze_bytes(data))
    assert "gcc_ident" not in found and "mingw_w64_runtime" not in found


def test_a_pyinstaller_magic_inside_a_section_is_not_a_cookie():
    data = bytearray(build_demo())
    cookie = pyinstaller_cookie(88)
    data[0x1000 : 0x1000 + len(cookie)] = cookie
    assert "pyinstaller_cookie" not in markers(analyze_bytes(bytes(data)))


def test_a_cookie_whose_archive_reaches_into_the_sections_is_not_published():
    data = build_demo() + pyinstaller_cookie(0x400)
    assert "pyinstaller_cookie" not in markers(analyze_bytes(data))


def test_a_clr_directory_that_points_to_a_wrong_size_is_not_published():
    data = bytearray(build_toolchain_demo())
    struct.pack_into("<I", data, 0xE00, 64)
    assert "clr_header" not in markers(analyze_bytes(bytes(data)))


def test_the_host_rejects_bytes_that_differ_from_the_sample():
    data = build_toolchain_demo()
    report = analyze_bytes(data)
    changed = bytearray(data)
    changed[0xC00 + 20] ^= 0xFF  # inside the Go header's padding
    with pytest.raises(ValueError, match="differ"):
        verify_markers(report.evidence, bytes(changed))


def test_the_host_rejects_a_clr_header_the_directory_does_not_point_to():
    data = build_toolchain_demo()
    report = analyze_bytes(data)
    changed = bytearray(data)
    struct.pack_into("<I", changed, 0x98 + 96 + 8 * 14, 0x2900)
    with pytest.raises(ValueError, match="CLR directory"):
        verify_markers(report.evidence, bytes(changed))


@pytest.mark.parametrize(
    ("marker", "changes", "message"),
    [
        ("go_buildinfo", {"location.rva": 0x2608, "location.offset": 0xC08}, "16 bytes"),
        ("gcc_ident", {"location.rva": 0x2400}, "Go and CLR"),
        ("gcc_ident", {"data.text": "GCC: (GNU) 14"}, "text disagrees"),
        ("mingw_w64_runtime", {"location.offset": 0x1200}, "section"),
        ("pyinstaller_cookie", {"location.offset": 0x1000}, "appended"),
        ("clr_header", {"location.rva": 0x2900}, "offset"),
    ],
)
def test_the_report_validator_rejects_misplaced_markers(marker, changes, message):
    report = analyze_bytes(build_toolchain_demo())
    with pytest.raises(ValidationError, match=message):
        Report.model_validate_json(tampered(report, marker, **changes))


def test_a_marker_is_published_once():
    report = analyze_bytes(build_toolchain_demo())
    document = json.loads(report.model_dump_json())
    run = next(run for run in document["extractor_runs"] if run["source"] == "pe")
    part = next(part for part in run["components"] if part["name"] == "toolchain")
    copy = dict(
        next(f for f in document["evidence"] if f["data"].get("marker") == "mingw_w64_runtime")
    )
    copy["id"] = f"E{len(document['evidence']) + 1}"
    document["evidence"].append(copy)
    part["evidence_count"] += 1
    run["evidence_count"] += 1
    with pytest.raises(ValidationError, match="published once"):
        Report.model_validate_json(json.dumps(document))


@pytest.mark.parametrize(
    ("marker", "raw"),
    [
        ("gcc_ident", b"GCC: (GNU) 13\x07\0"),
        ("gcc_ident", b"gcc: (GNU) 13\0"),
        ("mingw_w64_runtime", b"Mingw-w64 runtime failure"),
        ("go_buildinfo", go_header() + b"x"),
        ("go_buildinfo", go_header(version=b"go\x001")),
        ("clr_header", struct.pack("<IHH", 64, 2, 5)),
        ("pyinstaller_cookie", pyinstaller_cookie(88, toc=80)),
        ("pyinstaller_cookie", pyinstaller_cookie(88, library=b"python\x01.dll")),
        ("rich_header", b"Rich" + bytes(20)),
    ],
)
def test_only_the_exact_form_of_a_marker_is_accepted(marker, raw):
    with pytest.raises(ValueError):
        ToolchainData(marker=marker, raw_hex=raw.hex(), text=None)


def test_every_marker_is_explained_with_its_limit():
    for data in (build_toolchain_demo(), build_toolchain_demo(bits=64, go_inline=False)):
        report = analyze_bytes(data)
        explanation = explain(report, GLOSSARY)
        items = validate(explanation, report, GLOSSARY)
        rules = [item.rule for item in items if item.rule.startswith("toolchain.")]
        assert len(rules) == len(toolchain.MARKERS)
        for item in items:
            if item.rule.startswith("toolchain."):
                assert "toolchain.marker" in item.glossary_ids
                assert item.not_proven
