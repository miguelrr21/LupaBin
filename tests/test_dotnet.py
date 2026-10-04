"""The metadata of a .NET assembly: read only in the layout the method knows, derived
again by the host, and explained without saying what the code does."""

import json
import struct

import pytest
from pydantic import ValidationError

from lupabin.analysis import analyze_bytes
from lupabin.evidence import dotnet
from lupabin.evidence.dotnet_checks import verify_dotnet
from lupabin.evidence.models import Limits, Report
from lupabin.explain.engine import ExplanationError, explain, validate
from lupabin.glossary.catalog import load_glossary
from tests.fixtures.pe_builder import (
    DOTNET_NATIVE,
    DOTNET_ROOT,
    DOTNET_URL,
    build_demo,
    build_dotnet_demo,
    build_toolchain_demo,
)

GLOSSARY = load_glossary()
KINDS = ("dotnet_metadata", "dotnet_pinvoke", "dotnet_string", "dotnet_member", "dotnet_type")


def facts(report, kind=None):
    wanted = KINDS if kind is None else (kind,)
    return [fact for fact in report.evidence if fact.kind in wanted]


def component(report):
    run = next(run for run in report.extractor_runs if run.source == "pe")
    return next(part for part in run.components if part.name == "dotnet")


def codes(report):
    return {issue.code for issue in (*report.extractor_errors, *report.limitations)}


def text(value):
    return None if value is None else value.text


@pytest.mark.parametrize("bits", [32, 64])
def test_the_metadata_of_an_assembly_is_published_row_by_row(bits):
    data = build_dotnet_demo(bits=bits)
    report = analyze_bytes(data)
    (root,) = facts(report, "dotnet_metadata")
    assert root.location.offset == DOTNET_ROOT and data[DOTNET_ROOT:][:4] == b"BSJB"
    assert root.data.version == "v4.0.30319" and root.data.entry_point == 0x06000001
    assert [stream.name for stream in root.data.streams] == [
        "#~",
        "#Strings",
        "#US",
        "#GUID",
        "#Blob",
    ]
    assert (root.data.type_defs, root.data.methods, root.data.member_refs) == (2, 2, 2)
    assert (text(root.data.assembly.name), root.data.assembly.version) == ("training", (1, 2, 3, 4))
    assert [(text(a.name), a.version) for a in root.data.references] == [("mscorlib", (4, 0, 0, 0))]
    assert root.data.unreadable == 0

    (native,) = facts(report, "dotnet_pinvoke")
    assert text(native.data.module) == "user32.dll"
    assert text(native.data.function) == DOTNET_NATIVE.decode()
    assert text(native.data.method) == "ShowMessage"

    method, field = facts(report, "dotnet_member")
    assert (method.data.parent, method.data.member) == ("type_ref", "method")
    assert [text(n) for n in (method.data.assembly, method.data.namespace, method.data.type)] == [
        "mscorlib",
        "System.Net",
        "WebClient",
    ]
    assert text(method.data.name) == "DownloadString"
    assert (text(field.data.type), text(field.data.name), field.data.member) == (
        "String",
        "Empty",
        "field",
    )

    module, program = facts(report, "dotnet_type")
    assert (text(module.data.name), module.data.namespace, module.data.methods) == (
        "<Module>",
        None,
        0,
    )
    assert (text(program.data.namespace), text(program.data.name), program.data.methods) == (
        "LupaBin.Training",
        "Program",
        2,
    )
    for fact in facts(report):
        assert fact.confidence == "observed"
        assert fact.location.offset + fact.location.length <= len(data)
        if fact is not root:
            assert fact.provenance.evidence_ids == (root.id,)
    (literal,) = facts(report, "dotnet_string")
    assert (literal.data.text, literal.data.encoding) == (DOTNET_URL, "utf-16-le")
    assert data[literal.location.offset :][: literal.location.length] == DOTNET_URL.encode(
        "utf-16-le"
    )
    assert root.data.user_strings == 1 and literal.data.index == 1  # the token 0x70000001
    assert [fact.kind for fact in facts(report)] == [
        "dotnet_metadata",
        "dotnet_pinvoke",
        "dotnet_string",
        "dotnet_member",
        "dotnet_member",
        "dotnet_type",
        "dotnet_type",
    ]
    assert component(report).status == "complete" and component(report).examined == 7
    verify_dotnet(report.evidence, data, 1024)


def test_a_native_program_has_no_metadata_and_complete_coverage():
    report = analyze_bytes(build_demo())
    assert not facts(report)
    assert component(report).status == "complete" and component(report).examined == 0


def test_a_cli_header_without_metadata_is_declared_and_nothing_is_published():
    # the toolchain fixture has a CLI header whose metadata fields are zero
    report = analyze_bytes(build_toolchain_demo())
    assert not facts(report)
    assert component(report).status == "blocked"
    assert "dotnet_unsupported_layout" in codes(report)


@pytest.mark.parametrize(
    "changes",
    [
        {"stream": b"#-"},  # the unoptimized layout
        {"heap_sizes": 0x40},  # extra data after the row counts
        {"heap_sizes": 0x01},  # wide #Strings indexes the rows do not have
    ],
)
def test_metadata_in_another_layout_is_not_read(changes):
    report = analyze_bytes(build_dotnet_demo(**changes))
    assert not facts(report)
    assert component(report).status == "blocked"
    assert "dotnet_unsupported_layout" in codes(report)


def patched(data, at, raw):
    changed = bytearray(data)
    changed[at : at + len(raw)] = raw
    return bytes(changed)


@pytest.mark.parametrize(
    "mutation",
    ["signature", "duplicate", "pointer_table", "portable_pdb_table", "stream_outside"],
)
def test_forms_the_standard_does_not_fix_are_left_unread(mutation):
    data = build_dotnet_demo()
    metadata = dotnet.read(data)
    tables = next(stream for stream in metadata.streams if stream.name == "#~")
    if mutation == "signature":
        data = patched(data, DOTNET_ROOT, b"BSJX")
    elif mutation == "duplicate":  # two streams with one name
        at = data.index(b"#GUID\0", DOTNET_ROOT)
        data = patched(data, at, b"#Blob\0")
    elif mutation == "pointer_table":  # FieldPtr declared in place of TypeDef
        valid = struct.unpack_from("<Q", data, tables.offset + 8)[0]
        data = patched(data, tables.offset + 8, struct.pack("<Q", valid ^ 0b1100))
    elif mutation == "portable_pdb_table":
        valid = struct.unpack_from("<Q", data, tables.offset + 8)[0]
        data = patched(data, tables.offset + 8, struct.pack("<Q", valid | 1 << 48))
    else:
        at = data.index(b"#Blob\0", DOTNET_ROOT) - 4
        data = patched(data, at, struct.pack("<I", 0x10000))
    with pytest.raises(ValueError):
        dotnet.read(data)
    report = analyze_bytes(data)
    assert not facts(report) and "dotnet_unsupported_layout" in codes(report)


def test_a_row_whose_name_cannot_be_read_is_left_out_and_counted():
    data = build_dotnet_demo()
    metadata = dotnet.read(data)
    member = metadata.members[0]
    # MemberRef 1: its name index now points outside #Strings
    data = patched(data, member.offset + 2, struct.pack("<H", 0x7FFF))
    report = analyze_bytes(data)
    (root,) = facts(report, "dotnet_metadata")
    assert root.data.unreadable == 1 and root.data.member_refs == 2
    assert [text(fact.data.name) for fact in facts(report, "dotnet_member")] == ["Empty"]
    assert component(report).status == "partial"
    assert "dotnet_unreadable_rows" in codes(report)
    verify_dotnet(report.evidence, data, 1024)


def test_an_empty_library_name_is_published_as_missing_not_invented():
    data = build_dotnet_demo(library=b"", native=b"")
    report = analyze_bytes(data)
    (native,) = facts(report, "dotnet_pinvoke")
    assert native.data.module is None and native.data.function is None
    assert text(native.data.method) == "ShowMessage"
    items = [item for item in explain(report, GLOSSARY).items if item.rule.startswith("dotnet.pin")]
    assert [item.rule for item in items] == ["dotnet.pinvoke_unnamed@1"]
    assert items[0].slots["functions"] == ("(sin nombre) (método ShowMessage)",)


def test_a_member_of_the_assembly_itself_names_no_other_assembly():
    report = analyze_bytes(build_dotnet_demo(own_field=True))
    _, field = facts(report, "dotnet_member")
    assert (field.data.parent, field.data.assembly) == ("type_def", None)
    assert (text(field.data.namespace), text(field.data.type)) == ("LupaBin.Training", "Program")
    rules = [i.rule for i in explain(report, GLOSSARY).items if i.rule.startswith("dotnet.mem")]
    assert rules == ["dotnet.members@1", "dotnet.members_local@1"]


def test_only_printable_literals_of_four_characters_are_published():
    texts = ("abc", "caf\u00e9 con leche", "Software\\LupaBin\\Training", "", "x" * 40)
    report = analyze_bytes(build_dotnet_demo(user_strings=texts))
    (root,) = facts(report, "dotnet_metadata")
    assert root.data.user_strings == 5  # every entry, the empty literal included
    assert [fact.data.text for fact in facts(report, "dotnet_string")] == [
        "Software\\LupaBin\\Training",
        "x" * 40,
    ]
    assert component(report).status == "complete"


def test_a_long_literal_is_published_up_to_the_character_limit():
    data = build_dotnet_demo(user_strings=("y" * 60,))
    report = analyze_bytes(data, Limits(string_characters=16))
    (literal,) = facts(report, "dotnet_string")
    assert (literal.data.text, literal.data.complete) == ("y" * 16, False)
    assert literal.data.total_characters == 60 and literal.location.length == 32
    verify_dotnet(report.evidence, data, 16)
    with pytest.raises(ValueError, match="differs from the sample"):
        verify_dotnet(report.evidence, data, 1024)


def test_an_entry_that_does_not_fit_ends_the_reading_of_literals():
    data = build_dotnet_demo(user_strings=("first literal", "second literal"))
    first, second = dotnet.read(data).user_strings
    # the length of the second entry now reaches beyond the stream
    broken = patched(data, second.offset - 1, b"\x7f")
    metadata = dotnet.read(broken)
    assert [item.raw.decode("utf-16-le") for item in metadata.user_strings] == ["first literal"]
    assert not metadata.user_complete
    report = analyze_bytes(broken)
    assert component(report).status == "partial" and "dotnet_limit" in codes(report)


def test_the_host_derives_every_fact_again_from_the_sample():
    data = build_dotnet_demo()
    report = analyze_bytes(data)
    verify_dotnet(report.evidence, data, 1024)
    other = build_dotnet_demo(native=b"MessageBoxA")
    with pytest.raises(ValueError, match="differs from the sample"):
        verify_dotnet(report.evidence, other, 1024)
    with pytest.raises(ValueError, match="no .NET metadata"):
        verify_dotnet(report.evidence, build_demo(), 1024)
    verify_dotnet(analyze_bytes(build_demo()).evidence, build_demo(), 1024)  # nothing to check


def tampered(report, kind, **changes):
    document = json.loads(report.model_dump_json())
    fact = next(fact for fact in document["evidence"] if fact["kind"] == kind)
    for path, value in changes.items():
        target = fact
        *parents, leaf = path.split(".")
        for parent in parents:
            target = target[parent]
        target[leaf] = value
    return json.dumps(document), fact


def test_the_host_rejects_a_changed_name_or_place():
    data = build_dotnet_demo()
    report = analyze_bytes(data)
    name = {"raw_hex": b"VirtualAlloc".hex(), "text": "VirtualAlloc"}
    changed, _ = tampered(report, "dotnet_pinvoke", **{"data.function": name})
    with pytest.raises(ValueError, match="differs from the sample"):
        verify_dotnet(Report.model_validate_json(changed).evidence, data, 1024)
    changed, fact = tampered(report, "dotnet_type", **{"location.offset": 0x400})
    with pytest.raises(ValueError, match="differs from the sample"):
        verify_dotnet(Report.model_validate_json(changed).evidence, data, 1024)


@pytest.mark.parametrize(
    ("kind", "changes", "message"),
    [
        ("dotnet_member", {"provenance.evidence_ids": []}, "cites its metadata root"),
        ("dotnet_member", {"provenance.evidence_ids": ["E1"]}, "cites the metadata root"),
        ("dotnet_member", {"data.row": 3}, "outside the table"),
        ("dotnet_member", {"data.parent": "type_spec"}, "resolves to another assembly"),
        ("dotnet_type", {"component": "toolchain"}, "disagrees"),
        ("dotnet_metadata", {"data.assembly_refs": 0}, "more assembly references"),
        ("dotnet_metadata", {"provenance.evidence_ids": ["E1"]}, "cites nothing"),
    ],
)
def test_the_report_validator_rejects_inconsistent_facts(kind, changes, message):
    changed, _ = tampered(analyze_bytes(build_dotnet_demo()), kind, **changes)
    with pytest.raises(ValidationError, match=message):
        Report.model_validate_json(changed)


def test_the_reader_is_bounded_on_declared_sizes():
    data = build_dotnet_demo()
    tables = next(s for s in dotnet.read(data).streams if s.name == "#~")
    # the first row count (Module) raised beyond what the stream can hold
    huge = patched(data, tables.offset + 24, struct.pack("<I", dotnet.ROWS_MAX))
    with pytest.raises(ValueError, match="do not fit"):
        dotnet.read(huge)
    with pytest.raises(ValueError, match="more rows than a token"):
        dotnet.read(patched(data, tables.offset + 24, struct.pack("<I", dotnet.ROWS_MAX + 1)))
    for cut in range(DOTNET_ROOT, len(data), 37):
        try:  # a truncated file is never anything but unread
            dotnet.read(data[:cut])
        except ValueError:
            pass


def test_every_fact_is_explained_with_its_limit():
    report = analyze_bytes(build_dotnet_demo())
    explanation = explain(report, GLOSSARY)
    items = {item.rule: item for item in explanation.items if item.rule.startswith("dotnet.")}
    assert list(items) == [
        "dotnet.metadata@1",
        "dotnet.pinvoke@1",
        "dotnet.members@1",
        "dotnet.types@1",
        "dotnet.user_strings@1",
    ]
    assert "«training 1.2.3.4»" in items["dotnet.metadata@1"].statement
    assert items["dotnet.metadata@1"].slots["references"] == ("mscorlib 4.0.0.0",)
    assert "1 función de código nativo de «user32.dll»" in items["dotnet.pinvoke@1"].statement
    assert items["dotnet.pinvoke@1"].slots["functions"] == ("MessageBoxW (método ShowMessage)",)
    assert items["dotnet.members@1"].slots["members"] == (
        "System.Net.WebClient::DownloadString",
        "System.String::Empty (campo)",
    )
    assert items["dotnet.types@1"].slots["types"] == (
        "<Module> (0 métodos)",
        "LupaBin.Training.Program (2 métodos)",
    )
    assert items["dotnet.user_strings@1"].slots["texts"] == (DOTNET_URL,)
    valid = {item.id for item in validate(explanation, report, GLOSSARY)}
    for item in items.values():
        assert item.level == "observed"
        assert item.not_proven and "demuestra" not in item.statement
        assert item.id in valid
    cited = {ref for item in items.values() for ref in item.evidence_ids}
    assert {fact.id for fact in facts(report)} <= cited


def test_an_explanation_must_cite_its_whole_group():
    report = analyze_bytes(build_dotnet_demo())
    explanation = explain(report, GLOSSARY)
    item = next(i for i in explanation.items if i.rule == "dotnet.members@1")
    partial = item.model_copy(update={"evidence_ids": item.evidence_ids[:1]})
    changed = explanation.model_copy(
        update={"items": tuple(partial if i is item else i for i in explanation.items)}
    )
    assert item.id in {i.id for i in validate(explanation, report, GLOSSARY)}
    with pytest.raises(ExplanationError):  # the member left out is no longer explained
        validate(changed, report, GLOSSARY)
