import json
import struct
import time
import zlib

import pytest
from pydantic import ValidationError

from lupabin.analysis import analyze_bytes
from lupabin.evidence import upx
from lupabin.evidence.facts import UpxImageEvidence, UpxImportEvidence
from lupabin.evidence.models import Limits, Report
from lupabin.evidence.primitives import Name
from lupabin.evidence.upx_checks import verify_upx
from lupabin.explain.engine import explain, validate
from lupabin.glossary.catalog import load_glossary
from lupabin.render.document import to_markdown, to_text
from lupabin.web import view
from tests.fixtures.pe_builder import (
    UPX_FUNCTIONS,
    UPX_ORDINAL,
    _NrvWriter,
    build_pe,
    build_upx_demo,
    nrv_literals,
)

GLOSSARY = load_glossary()
CHARACTERS = Limits().string_characters
METHODS = ("nrv2b", "nrv2d", "nrv2e", "lzma")


def upx_facts(report):
    images = [f for f in report.evidence if isinstance(f, UpxImageEvidence)]
    imports = [f for f in report.evidence if isinstance(f, UpxImportEvidence)]
    return images, imports


def component(report):
    run = next(r for r in report.extractor_runs if r.source == "pe")
    return next(part for part in run.components if part.name == "upx")


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("method", METHODS)
def test_every_method_and_width_unpacks_and_the_host_agrees(bits, method):
    data = build_upx_demo(bits=bits, method=method)
    report = analyze_bytes(data)
    Report.model_validate(report.model_dump())
    verify_upx(report.evidence, data, CHARACTERS)
    (image,), imports = upx_facts(report)
    block = image.data
    assert (block.method, block.version, block.format) == (
        method,
        13,
        "win32/pe" if bits == 32 else "win64/pe",
    )
    assert image.location.offset == 0x1200 and image.location.length == 32
    assert block.packed_offset == 0x1220
    assert block.original_entry_rva == 0x1123
    assert block.original_image_base == (0x400000 if bits == 32 else 0x140000000)
    assert [(s.name_text, s.rva, s.virtual_size) for s in block.original_sections] == [
        (".text", 0x1000, 0x180),
        (".data", 0x2000, 0x40),
    ]
    width = bits // 8
    assert [
        (i.data.dll.text, i.data.function and i.data.function.text, i.data.ordinal, i.data.iat_rva)
        for i in imports
    ] == [
        ("kernel32.dll", "ExitProcess", None, 0x1040),
        ("kernel32.dll", "GetTickCount", None, 0x1040 + width),
        ("kernel32.dll", None, UPX_ORDINAL, 0x1040 + 2 * width),
    ]
    assert all(i.provenance.evidence_ids == (image.id,) for i in imports)
    assert block.imports == len(imports)
    assert component(report).status == "complete"


def test_an_unrecognised_tail_publishes_the_verified_block_alone():
    report = analyze_bytes(build_upx_demo(bits=64, method="nrv2e", tail=False))
    (image,), imports = upx_facts(report)
    assert imports == []
    assert image.data.original_sections is None and image.data.imports is None
    assert component(report).status == "partial"
    assert any(issue.code == "upx_layout_unrecognized" for issue in report.limitations)
    rules = {item.rule for item in explain(report, GLOSSARY).items}
    assert "upx.image_plain@1" in rules and "upx.image@1" not in rules


@pytest.mark.parametrize("method", METHODS)
def test_a_block_whose_checksums_fail_publishes_nothing(method):
    report = analyze_bytes(build_upx_demo(method=method, damage=True))
    assert upx_facts(report) == ([], [])
    assert component(report).status == "complete"


def test_files_without_upx_have_no_upx_facts():
    report = analyze_bytes(build_pe())
    assert upx_facts(report) == ([], [])
    assert component(report).examined == 0


@pytest.mark.parametrize(
    ("position", "value"),
    [(4, 12), (5, 43), (6, 3), (6, 15)],  # version, format (ARM64), methods not measured
)
def test_headers_outside_the_measured_values_are_ignored(position, value):
    data = bytearray(build_upx_demo())
    data[0x1200 + position] = value
    assert upx_facts(analyze_bytes(bytes(data))) == ([], [])


def test_a_declared_size_beyond_the_limit_is_not_decompressed():
    data = bytearray(build_upx_demo())
    struct.pack_into("<I", data, 0x1200 + 16, upx.MAX_UNPACKED + 1)
    assert upx.decode_header(bytes(data[0x1200:0x1220])) is None


def test_well_formed_decoy_headers_cost_little_and_lead_to_abstention():
    real = build_upx_demo()
    decoy = real[0x1200:0x1220]
    start = time.perf_counter()
    found = upx.unpack(real[:0x1200] + decoy * 20 + real[0x1200:], [0x200, 0x1200], 0x1000)
    assert found is None  # the tried headers run out before the real one: no claim
    assert time.perf_counter() - start < 5


def test_the_host_rejects_altered_upx_facts():
    data = build_upx_demo()
    report = analyze_bytes(data)
    (image,), imports = upx_facts(report)
    renamed = imports[0].model_copy(
        update={
            "data": imports[0].data.model_copy(update={"function": Name.from_bytes(b"WinExec")})
        }
    )
    altered = tuple(renamed if fact is imports[0] else fact for fact in report.evidence)
    with pytest.raises(ValueError, match="import list"):
        verify_upx(altered, data, CHARACTERS)
    other = image.model_copy(
        update={"data": image.data.model_copy(update={"unpacked_sha256": "0" * 64})}
    )
    altered = tuple(other if fact is image else fact for fact in report.evidence)
    with pytest.raises(ValueError, match="block differs"):
        verify_upx(altered, data, CHARACTERS)
    with pytest.raises(ValueError, match="no UPX block"):
        verify_upx(report.evidence, build_upx_demo(damage=True), CHARACTERS)


def test_the_report_rejects_an_incomplete_list_that_claims_complete_coverage():
    report = analyze_bytes(build_upx_demo())
    dump = report.model_dump(mode="json")
    dump["evidence"] = [f for f in dump["evidence"] if f["id"] != upx_facts(report)[1][-1].id]
    run = next(r for r in dump["extractor_runs"] if r["source"] == "pe")
    run["evidence_count"] -= 1
    next(part for part in run["components"] if part["name"] == "upx")["evidence_count"] -= 1
    with pytest.raises(ValidationError, match="UPX imports disagree"):
        Report.model_validate_json(json.dumps(dump))


def test_upx_fields_must_agree_with_their_header():
    report = analyze_bytes(build_upx_demo())
    dump = report.model_dump(mode="json")
    block = next(f for f in dump["evidence"] if f["kind"] == "upx_image")
    block["data"]["method"] = "nrv2b"
    with pytest.raises(ValidationError, match="disagree with their header"):
        Report.model_validate_json(json.dumps(dump))


@pytest.mark.parametrize("method", ("nrv2b", "nrv2d", "nrv2e"))
def test_nrv_streams_must_end_exactly_where_their_sizes_say(method):
    stream = b"inert practice bytes" * 3
    packed = nrv_literals(stream, method)
    assert upx.nrv(packed, method, len(stream)) == stream
    with pytest.raises(ValueError):
        upx.nrv(packed[:-1], method, len(stream))
    with pytest.raises(ValueError):
        upx.nrv(packed + b"\0", method, len(stream))
    with pytest.raises(ValueError):
        upx.nrv(packed, method, len(stream) - 1)


def test_nrv2b_matches_copy_earlier_output():
    """A literal 'ab', then one match of distance 2 and length 6, then the end marker."""
    writer = _NrvWriter()
    for value in b"ab":
        writer.bit(1)
        writer.byte(value)
    writer.bit(0)
    # offset number 3 (gamma: one digit 1, stop), then the byte: distance (3-3)*256+1+1 = 2
    for value in (1, 1):
        writer.bit(value)
    writer.byte(1)
    # length bits 00, then gamma 3 -> 3 + 2 = 5, copied 5 + 1 = 6 bytes
    for value in (0, 0, 1, 1):
        writer.bit(value)
    writer.bit(0)
    digits = bin(0x1000002)[3:]
    for index, digit in enumerate(digits):
        writer.bit(int(digit))
        writer.bit(int(index == len(digits) - 1))
    writer.byte(0xFF)
    assert upx.nrv(bytes(writer.out), "nrv2b", 8) == b"abababab"


def test_lzma_properties_are_checked():
    good = build_upx_demo()
    block = good[0x1220:]
    size = struct.unpack_from("<I", good, 0x1200 + 16)[0]
    assert zlib.adler32(upx.unlzma(block[: struct.unpack_from("<I", good, 0x1200 + 20)[0]], size))
    with pytest.raises(ValueError):
        upx.unlzma(bytes([0xFF, 0xFF]) + block[2:], size)


def test_explanations_report_line_and_web_view():
    data = build_upx_demo()
    report = analyze_bytes(data)
    explanation = explain(report, GLOSSARY)
    items = validate(explanation, report, GLOSSARY)
    rules = [item.rule for item in items]
    assert "upx.image@1" in rules and rules.count("upx.imports@1") == 1
    imports = next(item for item in items if item.rule == "upx.imports@1")
    assert "ExitProcess, GetTickCount, ordinal 5" in imports.statement
    text = to_text(explanation, items, report, GLOSSARY)
    assert "UPX       método LZMA (X" in text
    assert "**Empaquetado**: UPX, método LZMA" in to_markdown(explanation, items, report, GLOSSARY)
    assert view.build(report, explanation, items, GLOSSARY, None)["packed_with"].startswith(
        "UPX, método LZMA"
    )


def test_long_names_and_long_lists_keep_statements_within_their_limit():
    names = tuple(b"F" * 300 + str(index).encode() for index in range(40))
    data = build_upx_demo(functions=names)
    report = analyze_bytes(data)
    verify_upx(report.evidence, data, CHARACTERS)
    explanation = explain(report, GLOSSARY)
    items = validate(explanation, report, GLOSSARY)
    statement = next(item for item in items if item.rule == "upx.imports@1").statement
    assert "(301 caracteres)" in statement and "y 21 más" in statement


def test_fixture_functions_are_the_documented_ones():
    assert UPX_FUNCTIONS == (b"ExitProcess", b"GetTickCount")


def test_the_rebuilt_image_gives_the_strings_and_the_host_agrees():
    data = build_upx_demo()
    report = analyze_bytes(data)
    verify_upx(report.evidence, data, CHARACTERS)
    texts = [f for f in report.evidence if f.kind == "upx_string"]
    assert len(texts) == 18
    assert texts[0].data.text == "LUPABIN UPX PRACTICE IMAGE"
    assert texts[0].data.rva == 0x1000 and texts[1].data.rva == 0x1000 + 27
    items = validate(explain(report, GLOSSARY), report, GLOSSARY)
    statement = next(item for item in items if item.rule == "upx.strings@1").statement
    assert "18 cadenas de texto (18 ASCII y 0 UTF-16LE)" in statement
    assert "«LUPABIN UPX PRACTICE IMAGE»" in statement and "y 6 más" in statement
    altered = tuple(
        fact.model_copy(update={"data": fact.data.model_copy(update={"rva": 0x1001})})
        if fact is texts[0]
        else fact
        for fact in report.evidence
    )
    with pytest.raises(ValueError, match="strings of the rebuilt image"):
        verify_upx(altered, data, CHARACTERS)


def test_the_jump_filter_is_undone_where_the_marker_byte_says_so():
    image = bytearray(
        b"\x90" * 16 + b"\xe8" + bytes(4) + b"\x0f\x85" + bytes(4) + b"\xe8\x01\x02\x03\x04"
    )
    stored = (5 << 24) + 17 + 0x40  # field at 17, rel32 0x40
    image[17:21] = stored.to_bytes(4, "big")
    image[23:27] = ((5 << 24) + 23 + 0x10).to_bytes(4, "big")
    x86, x64 = bytearray(image), bytearray(image)
    upx._unfilter(x86, 0x26, 5)
    upx._unfilter(x64, 0x49, 5)
    assert x86[17:21] == (0x40).to_bytes(4, "little") == x64[17:21]
    assert x86[23:27] == image[23:27]  # 0x26 leaves conditional jumps alone
    assert x64[23:27] == (0x10).to_bytes(4, "little")
    assert x86[27:] == x64[27:] == b"\xe8\x01\x02\x03\x04"  # no marker byte: unchanged


def test_relocation_streams_follow_the_measured_steps():
    stream = (
        bytes([4, 4, 0xF0, 0x00, 0x10, 0xF3, 0x00, 0xE6, 0xF0, 0, 0])
        + (0x20000).to_bytes(4, "little")
        + b"\0"
    )
    assert upx._relocations(stream, 0, len(stream)) == [
        0,
        4,
        4 + 0x1000,
        4 + 0x1000 + 0x3E600,
        4 + 0x1000 + 0x3E600 + 0x20000,
    ]
    with pytest.raises(ValueError):
        upx._relocations(stream + b"\0", 0, len(stream) + 1)  # must end at the header copy


def test_an_unmeasured_filter_publishes_no_strings():
    data = bytearray(build_upx_demo())
    data[0x1200 + 28] = 0x16  # a filter id that was not measured
    report = analyze_bytes(bytes(data))
    assert [f.kind for f in report.evidence if f.kind.startswith("upx")].count("upx_string") == 0
    assert any(issue.code == "upx_rebuild_unrecognized" for issue in report.limitations)


def test_strings_skip_the_areas_upx_changes():
    sections = (
        upx.Section(b".text\0\0\0", 0x1000, 0x2000, 0x60000020),
        upx.Section(b".rdata\0\0", 0x3000, 0x1000, 0x40000040),
        upx.Section(b".rsrc\0\0\0", 0x4000, 0x800, 0x40000040),
    )
    directories = ((0, 0), (0x3100, 0x28), (0x4000, 0x80), (0, 0), (0, 0), (0, 0), (0x3800, 0x1C))
    tail = upx.Tail(0x14C, 0x1000, 0x400000, sections, (), 0x3800, None, 0x3900, directories)
    assert sorted(upx.excluded(tail, 0x1000)) == [
        (0x2100, 0x2128),  # imports
        (0x2800, 0x281C),  # debug
        (0x3000, 0x3080),  # resource directory
        (0x3000, 0x3800),  # the whole resource section
    ]
