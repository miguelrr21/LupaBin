"""Independent metadata comparisons use bytes, row ordinals and explicit coverage."""

import argparse
import copy
import hashlib
import json
from types import SimpleNamespace as NS

import pytest

from lupabin.evidence import dotnet
from tests import dotnet_eval as evaluation
from tests.fixtures.pe_builder import build_dotnet_demo


def metadata():
    return dotnet.read(build_dotnet_demo())


def expected_for(found):
    return evaluation.Snapshot(
        root=evaluation.metadata_root(found),
        rows={
            group: {row.row: row._asdict() for row in getattr(found, group)}
            for group in ("pinvokes", "members", "types")
        }
        | {"literals": {row.entry: row._asdict() for row in found.user_strings}},
    )


@pytest.mark.parametrize(
    ("group", "field", "changed"),
    [
        ("pinvokes", "flags", 17),
        ("pinvokes", "module", b"other.dll"),
        ("pinvokes", "function", b"Other"),
        ("pinvokes", "method", None),
        ("pinvokes", "offset", 1),
        ("pinvokes", "length", 1),
        ("members", "parent", "type_spec"),
        ("members", "assembly", None),
        ("members", "namespace", b"Other"),
        ("members", "type", b"Other"),
        ("members", "name", b"Other"),
        ("members", "member", "field"),
        ("members", "offset", 1),
        ("members", "length", 1),
        ("types", "flags", 17),
        ("types", "namespace", b"Other"),
        ("types", "name", b"Other"),
        ("types", "methods", 17),
        ("types", "offset", 1),
        ("types", "length", 1),
        ("literals", "raw", b"x\x00"),
        ("literals", "characters", 17),
        ("literals", "offset", 1),
    ],
)
def test_each_published_row_field_is_compared(group, field, changed):
    found = metadata()
    expected = expected_for(found)
    number = next(iter(expected.rows[group]))
    expected.rows[group][number][field] = changed
    result = evaluation.differences(found, expected)
    assert f"{group}.{number}.{field}" in result.wrong
    assert result.compared > 0


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("offset", 1),
        ("length", 1),
        ("version", "v9"),
        ("flags", 17),
        ("entry_point", 0),
        ("streams", ()),
        ("rows", (0,) * 45),
        ("assembly", (b"other", (1, 2, 3, 4))),
        ("assembly", (b"training", (9, 2, 3, 4))),
        ("assembly", None),
        ("assembly_refs", ((b"other", (4, 0, 0, 0)),)),
        ("assembly_refs", ((b"mscorlib", (9, 0, 0, 0)),)),
        ("assembly_refs_total", 0),
        ("user_entries", 0),
        ("user_complete", False),
    ],
)
def test_each_root_field_is_compared(field, changed):
    found = metadata()
    expected = expected_for(found)
    expected.root[field] = changed
    assert f"root.{field}" in evaluation.differences(found, expected).wrong


@pytest.mark.parametrize("side", ["reader", "reference"])
def test_missing_is_not_equal_to_a_known_value(side):
    found = metadata()
    expected = expected_for(found)
    if side == "reader":
        found = found._replace(members=(found.members[0]._replace(assembly=None),))
    else:
        expected.rows["members"][1]["assembly"] = None
    assert "members.1.assembly" in evaluation.differences(found, expected).wrong


def test_unreadable_reference_is_counted_not_treated_as_equal():
    found = metadata()
    expected = expected_for(found)
    expected.rows["members"][1]["assembly"] = evaluation.Unavailable("invalid scope")
    result = evaluation.differences(found, expected)
    assert not result.wrong
    assert result.unavailable == {"members.1.assembly": "invalid scope"}
    assert result.compared == evaluation.differences(found, expected_for(found)).compared - 1


def test_omitted_row_keeps_its_ordinal_and_is_not_counted_as_compared():
    found = metadata()
    expected = expected_for(found)
    expected.rows["members"][1] = evaluation.Unavailable("unreadable row")
    found = found._replace(members=(found.members[1],), unreadable=1)
    result = evaluation.differences(found, expected)
    assert not result.wrong
    assert result.omitted["members"] == [1]
    assert result.unavailable["members.1"] == "unreadable row"
    expected.rows["members"][2]["name"] = b"wrong"
    assert "members.2.name" in evaluation.differences(found, expected).wrong


def test_different_invalid_utf8_bytes_never_compare_equal():
    found = metadata()
    expected = expected_for(found)
    found = found._replace(types=(found.types[0]._replace(name=b"\xff"),))
    expected.rows["types"][1]["name"] = b"\xfe"
    assert "types.1.name" in evaluation.differences(found, expected).wrong


def args(tmp_path, **changes):
    values = dict(
        dirs=[str(tmp_path)],
        recursive=False,
        ext=".dll",
        stride=1,
        limit=0,
        out=str(tmp_path / "results.jsonl"),
        progress=1,
    )
    return argparse.Namespace(**(values | changes))


def test_output_is_exclusive_before_reading_any_sample(tmp_path, monkeypatch):
    target = tmp_path / "results.jsonl"
    target.write_text("keep", encoding="utf-8")
    monkeypatch.setattr(evaluation.dotnet, "read", lambda _: pytest.fail("reader called"))
    assert evaluation.corpus(args(tmp_path)) == 2
    assert target.read_text(encoding="utf-8") == "keep"


@pytest.mark.parametrize("failure", ["different", "reference", "reader", "derive", "unavailable"])
def test_corpus_reports_nonzero_for_real_failures(tmp_path, monkeypatch, capsys, failure):
    data = build_dotnet_demo()
    (tmp_path / "fixture.dll").write_bytes(data)
    expected = expected_for(metadata())
    if failure == "different":
        expected.root["flags"] = 999
    if failure == "unavailable":
        expected.root["flags"] = evaluation.Unavailable("unreadable flags")
    monkeypatch.setattr(evaluation, "reference", lambda *_args, **_kw: expected)

    def broken(*_args, **_kw):
        raise RuntimeError("synthetic failure")

    if failure == "reference":
        monkeypatch.setattr(evaluation, "reference", broken)
    elif failure == "reader":
        monkeypatch.setattr(evaluation.dotnet, "read", broken)
    elif failure == "derive":
        monkeypatch.setattr(evaluation, "derive", broken)
    assert evaluation.corpus(args(tmp_path)) == (2 if failure == "unavailable" else 1)
    records = [json.loads(line) for line in (tmp_path / "results.jsonl").read_text().splitlines()]
    assert records[0]["event"] == "start"
    assert records[-1]["event"] == "summary"
    assert records[-1]["status"] != "passed"
    assert any(record.get("sha256") for record in records)
    assert "progress" in capsys.readouterr().out


def test_empty_run_cannot_claim_a_successful_comparison(tmp_path):
    assert evaluation.corpus(args(tmp_path)) == 2


@pytest.mark.parametrize(
    "option,value", [("--stride", "0"), ("--limit", "-1"), ("--progress", "0")]
)
def test_invalid_numeric_arguments_fail_before_running(option, value, monkeypatch):
    monkeypatch.setattr(
        "sys.argv", ["dotnet_eval", "corpus", ".", "--out", "unused.jsonl", option, value]
    )
    with pytest.raises(SystemExit) as caught:
        evaluation.main()
    assert caught.value.code == 2


@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize(
    "options",
    [
        {},
        {"own_field": True},
        {"library": b"", "native": b""},
        {"user_strings": ("x" * 60, "abc", "caf\u00e9", "")},
    ],
)
def test_real_dnfile_mapping_on_synthetic_bytes(bits, options):
    pytest.importorskip("dnfile")
    data = build_dotnet_demo(bits=bits, **options)
    found = dotnet.read(data, characters=16)
    expected = evaluation.reference(data, characters=16)
    result = evaluation.differences(found, expected)
    assert not result.wrong
    assert not result.unavailable
    assert result.compared == 55
    assert not evaluation.derived_differences(found, evaluation.derive(data, 16)).wrong


def fake_row(**fields):
    return NS(
        struct=NS(get_file_offset=lambda: 500, sizeof=lambda: 14, **fields),
        Flags=object(),
        MappingFlags=object(),
    )


def fake_pe():
    table = NS(
        num_rows=2,
        rows=[fake_row(Flags=9, MethodList_Index=1), fake_row(Flags=10, MethodList_Index=2)],
    )
    tables = NS(
        TypeDef=table,
        MethodDef=NS(num_rows=3),
        MemberRef=None,
        ImplMap=None,
        Assembly=None,
        AssemblyRef=None,
        tables={2: table},
    )
    root = NS(get_file_offset=lambda: 300, sizeof=lambda: 32, Version=b"v4\0")
    net = NS(
        mdtables=tables,
        metadata=NS(struct=root, streams_list=[]),
        user_strings=None,
        struct=NS(Flags=1, EntryPointTokenOrRva=0x06000001),
    )
    return NS(net=net)


def test_reference_flags_use_struct_and_do_not_coerce_dnfile_flag_objects(monkeypatch):
    net = fake_pe().net
    monkeypatch.setattr(evaluation, "name", lambda *_args: b"Name")
    row = evaluation.reference_row(net, "types", 1)
    assert (row["flags"], row["methods"], row["offset"], row["length"]) == (9, 1, 500, 14)
    net.mdtables.ImplMap = NS(
        num_rows=1,
        rows=[fake_row(MappingFlags=123, ImportScope_Index=1, MemberForwarded_CodedIndex=3)],
    )
    net.mdtables.ModuleRef = NS(num_rows=1, rows=[fake_row()])
    monkeypatch.setattr(evaluation, "target", lambda *_args: ("MethodDef", fake_row()))
    assert evaluation.reference_row(net, "pinvokes", 1)["flags"] == 123


def test_reference_row_bound_preserves_declared_counts_and_records_exclusion(monkeypatch):
    pe = fake_pe()
    monkeypatch.setattr(evaluation, "name", lambda *_args: b"Name")
    monkeypatch.setitem(evaluation.ROW_LIMITS, "types", ("TypeDef", 1))
    result = evaluation.reference_from_pe(pe)
    assert result.root["rows"][2] == 2
    assert list(result.rows["types"]) == [1]
    assert result.excluded["types"] == 1


def test_unreadable_reference_row_does_not_shift_following_ordinals(monkeypatch):
    pe = fake_pe()
    pe.net.mdtables.TypeDef.rows[0] = None
    monkeypatch.setattr(evaluation, "name", lambda *_args: b"Name")
    result = evaluation.reference_from_pe(pe)
    assert isinstance(result.rows["types"][1], evaluation.Unavailable)
    assert result.rows["types"][2]["row"] == 2
    assert result.rows["types"][2]["flags"] == 10


def test_unreadable_assembly_reference_has_explicit_alignment_exclusion(monkeypatch):
    pe = fake_pe()
    pe.net.mdtables.AssemblyRef = NS(num_rows=2, rows=[None, fake_row()])
    monkeypatch.setattr(evaluation, "name", lambda *_args: b"Name")
    monkeypatch.setattr(evaluation, "assembly", lambda *_args: (b"A", (1, 0, 0, 0)))
    result = evaluation.reference_from_pe(pe)
    assert isinstance(result.root["assembly_refs"], evaluation.Unavailable)
    assert result.root["assembly_refs_total"] == 2
    assert "references.1" in result.notices
    assert "[1]" in result.root["assembly_refs"].reason


@pytest.mark.parametrize("cycle", [False, True])
def test_reference_scopes_are_bounded_and_unavailability_is_explicit(monkeypatch, cycle):
    current = fake_row(ResolutionScope_CodedIndex=1)
    calls = []

    def resolve(_net, _kind, value):
        calls.append(value)
        return "TypeRef", fake_row(ResolutionScope_CodedIndex=value if cycle else value + 1)

    monkeypatch.setattr(evaluation, "target", resolve)
    result = evaluation.capture(lambda: evaluation.scope_assembly(NS(), current))
    assert isinstance(result, evaluation.Unavailable)
    assert len(calls) == (1 if cycle else evaluation.SCOPE_LIMIT)
    assert ("cyclic" if cycle else "depth bound") in result.reason


@pytest.mark.parametrize("parent", ["TypeRef", "TypeDef", "ModuleRef", "MethodDef", "TypeSpec"])
def test_all_parent_kinds_have_the_published_scope_not_invented_origins(monkeypatch, parent):
    monkeypatch.setattr(evaluation, "target", lambda *_args: (parent, fake_row()))
    monkeypatch.setattr(evaluation, "name", lambda _net, _row, column, *_args: column.encode())
    monkeypatch.setattr(evaluation, "scope_assembly", lambda *_args: b"External")
    result = evaluation.member_origin(NS(), fake_row(Class_CodedIndex=1))
    assert (
        result["parent"]
        == {
            "TypeRef": "type_ref",
            "TypeDef": "type_def",
            "ModuleRef": "module_ref",
            "MethodDef": "method_def",
            "TypeSpec": "type_spec",
        }[parent]
    )
    assert result["assembly"] == (b"External" if parent == "TypeRef" else None)
    assert result["namespace"] == (b"TypeNamespace" if parent in ("TypeRef", "TypeDef") else None)
    assert result["type"] == (
        b"TypeName"
        if parent in ("TypeRef", "TypeDef")
        else b"Name"
        if parent == "ModuleRef"
        else None
    )


@pytest.mark.parametrize(
    "raw,size,kind",
    [(b"\x06", 1, "field"), (b"\x00", 1, "method"), (b"\x06", 3, None), (b"", 0, None)],
)
def test_signature_kind_requires_a_complete_nonempty_blob(raw, size, kind):
    net = NS(blobs=NS(get=lambda _: NS(value_bytes=lambda: raw, item_size=size)))
    result = evaluation.capture(
        lambda: evaluation.member_kind(net, fake_row(Signature_BlobIndex=1))
    )
    assert isinstance(result, evaluation.Unavailable) if kind is None else result == kind


@pytest.mark.parametrize(
    "raw,terminated,optional,index",
    [
        (b"\xff", True, False, 1),
        (b"", True, True, 0),
        (b"", True, False, 1),
        (b"x", False, False, 1),
        (b"x" * 513, True, False, 1),
    ],
)
def test_reference_names_are_raw_bounded_and_missing_only_for_zero_index(
    raw, terminated, optional, index
):
    item = NS(value_bytes=lambda: raw, rva=100)
    heap = NS(
        get=lambda *_args, **_kw: item, get_data_at_rva=lambda *_args: b"\0" if terminated else b"x"
    )
    result = evaluation.capture(
        lambda: evaluation.name(
            NS(strings=heap), fake_row(Name_StringIndex=index), "Name", optional
        )
    )
    if optional and index == 0:
        assert result is None
    elif raw and len(raw) <= 512 and terminated:
        assert result == raw
    else:
        assert isinstance(result, evaluation.Unavailable)


def test_full_derive_projection_detects_changed_payload_and_location():
    data = build_dotnet_demo()
    found = dotnet.read(data)
    original = evaluation.derive(data, 1024)
    assert not evaluation.derived_differences(found, original).wrong
    changed = copy.deepcopy(original)
    key, payload, location = changed[1][1]
    changed[1][1] = (
        key,
        payload.model_copy(update={"flags": 9}),
        location.model_copy(update={"offset": 9}),
    )
    result = evaluation.derived_differences(found, changed)
    assert f"derive.{key}.flags" in result.wrong
    assert f"derive.{key}.offset" in result.wrong


def test_derive_missing_duplicate_and_reordered_facts_are_not_hidden_by_counts():
    data = build_dotnet_demo()
    found = dotnet.read(data)
    original = evaluation.derive(data, 1024)
    for rows in (original[1][:-1], original[1][::-1], [original[1][0]] * len(original[1])):
        assert "derive.keys" in evaluation.derived_differences(found, (found, rows)).wrong


def test_success_log_has_comparison_counts_and_no_false_failure(tmp_path, monkeypatch):
    (tmp_path / "fixture.dll").write_bytes(build_dotnet_demo())
    monkeypatch.setattr(evaluation, "reference", lambda *_args: expected_for(metadata()))
    assert evaluation.corpus(args(tmp_path)) == 0
    records = [json.loads(line) for line in (tmp_path / "results.jsonl").read_text().splitlines()]
    assert records[-1]["status"] == "passed"
    assert records[-1]["counts"]["reference_fields_compared"] == 55
    assert records[-1]["counts"]["derive_fields_compared"] > 55
    assert next(row for row in records if row["event"] == "file")["status"] == "compared"


def test_row_omission_is_logged_as_incomplete_even_with_no_differences(tmp_path, monkeypatch):
    (tmp_path / "fixture.dll").write_bytes(build_dotnet_demo())
    found = metadata()
    expected = expected_for(found)
    missing = found._replace(members=found.members[1:], unreadable=1)
    monkeypatch.setattr(evaluation.dotnet, "read", lambda *_args: missing)
    monkeypatch.setattr(evaluation, "reference", lambda *_args: expected)
    assert evaluation.corpus(args(tmp_path)) == 2
    summary = json.loads((tmp_path / "results.jsonl").read_text().splitlines()[-1])
    assert summary["counts"]["reader_omitted_members"] == 1
    assert summary["counts"]["reference_differences"] == 0


@pytest.mark.parametrize("mutation", ["unreadable_member", "truncated_literal", "invalid_utf8"])
def test_real_dnfile_negative_mapping_keeps_bytes_and_omission_reasons(mutation):
    pytest.importorskip("dnfile")
    original = build_dotnet_demo()
    found = dotnet.read(original)
    data = bytearray(original)
    if mutation == "unreadable_member":
        at = found.members[0].offset + 2
        data[at : at + 2] = b"\xff\x7f"
    elif mutation == "truncated_literal":
        data[found.user_strings[0].offset - 1] = 127
    else:
        at = data.index(b"DownloadString")
        data[at] = 255
    found = dotnet.read(bytes(data))
    result = evaluation.differences(found, evaluation.reference(bytes(data)))
    assert not result.wrong
    if mutation == "unreadable_member":
        assert result.omitted["members"] == [1]
        assert "members.1.name" in result.unavailable
    elif mutation == "truncated_literal":
        assert not found.user_complete
        assert "literals.tail" in result.unavailable
    else:
        assert found.members[0].name.startswith(b"\xff")
        assert not result.unavailable


class HeapLength(int):
    raw_size = 1


@pytest.mark.parametrize("bound", ["LITERAL_STEPS", "LITERAL_LIMIT"])
def test_literal_traversal_is_bounded_and_truncates_only_the_published_prefix(monkeypatch, bound):
    calls = []

    def get(index):
        calls.append(index)
        return NS(
            item_size=HeapLength(9),
            raw_size=10,
            rva=1000 + index,
            value_bytes=lambda: b"a\x00b\x00c\x00d\x00",
        )

    heap = NS(struct=NS(Size=1000), get=get, get_file_offset=lambda rva: rva - 1000 + 200)
    monkeypatch.setattr(evaluation, bound, 2)
    rows, entries, complete = evaluation.reference_literals(NS(user_strings=heap), 2)
    assert calls == [1, 11]
    assert list(rows) == [1, 11]
    assert rows[1] == dict(entry=1, offset=202, characters=4, raw=b"a\x00b\x00")
    assert entries == 2 and not complete


def test_truncated_literal_is_not_accepted_from_dnfile_partial_bytes():
    item = NS(item_size=HeapLength(9), raw_size=4, value_bytes=lambda: b"a\x00")
    heap = NS(struct=NS(Size=5), get=lambda _: item)
    assert evaluation.reference_literals(NS(user_strings=heap), 1024) == ({}, 0, False)


@pytest.mark.parametrize("field", ["offset", "size", "name"])
def test_each_stream_attribute_is_compared(field):
    found = metadata()
    expected = expected_for(found)
    stream = found.streams[0]._replace(**{field: "other" if field == "name" else 17})
    expected.root["streams"] = (stream, *found.streams[1:])
    assert "root.streams" in evaluation.differences(found, expected).wrong


@pytest.mark.parametrize("index", range(45))
def test_every_declared_table_counter_is_compared(index):
    found = metadata()
    expected = expected_for(found)
    counts = list(found.rows)
    counts[index] += 1
    expected.root["rows"] = tuple(counts)
    assert "root.rows" in evaluation.differences(found, expected).wrong


def test_missing_location_api_does_not_hide_readable_reference_fields(monkeypatch):
    net = fake_pe().net
    del net.mdtables.TypeDef.rows[0].struct.get_file_offset
    monkeypatch.setattr(evaluation, "name", lambda *_args: b"Name")
    result = evaluation.reference_row(net, "types", 1)
    assert isinstance(result["offset"], evaluation.Unavailable)
    assert result["flags"] == 9 and result["length"] == 14


def test_interrupted_run_is_incomplete_even_after_a_successful_file(tmp_path, monkeypatch):
    path = tmp_path / "fixture.dll"
    path.write_bytes(build_dotnet_demo())

    def interrupted(*_args):
        yield path
        raise KeyboardInterrupt

    monkeypatch.setattr(evaluation, "files", interrupted)
    monkeypatch.setattr(evaluation, "reference", lambda *_args: expected_for(metadata()))
    assert evaluation.corpus(args(tmp_path)) == 2
    rows = [json.loads(line) for line in (tmp_path / "results.jsonl").read_text().splitlines()]
    assert rows[-2]["event"] == "interrupted"
    assert rows[-1]["counts"]["interrupted"] == 1


def test_recursive_selection_applies_stride_across_directories_not_to_each_directory(tmp_path):
    for folder in ("a", "b"):
        (tmp_path / folder).mkdir()
        for filename in ("1.dll", "2.dll", "3.txt"):
            (tmp_path / folder / filename).write_bytes(b"synthetic")
    selected = list(evaluation.files([tmp_path], True, (".dll",), 3))
    assert [path.relative_to(tmp_path).as_posix() for path in selected] == ["a/1.dll", "b/2.dll"]


@pytest.mark.parametrize("changed", ["evaluator", "reader", "dotnet_checks", "facts"])
def test_start_fingerprints_follow_each_source_file_bytes(tmp_path, monkeypatch, changed):
    from lupabin.evidence import dotnet_checks, facts

    modules = dict(evaluator=evaluation, reader=dotnet, dotnet_checks=dotnet_checks, facts=facts)
    sources = {}
    for label, module in modules.items():
        path = tmp_path / f"{label}.py"
        path.write_bytes(label.encode("ascii"))
        sources[label] = path
        monkeypatch.setattr(module, "__file__", str(path))
    monkeypatch.setattr(
        evaluation, "version", {"dnfile": "0.17.0", "pefile": "2024.8.26"}.__getitem__
    )
    starts = []
    for run in range(2):
        output = tmp_path / f"fingerprints-{run}.jsonl"
        assert evaluation.corpus(args(tmp_path, out=str(output))) == 2
        starts.append(json.loads(output.read_text().splitlines()[0]))
        for label, path in sources.items():
            assert starts[-1][label + "_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert starts[-1]["dnfile"] == "0.17.0"
        assert starts[-1]["pefile"] == "2024.8.26"
        if run == 0:
            sources[changed].write_bytes(b"changed bytes, never executed")
    for label in modules:
        assert (starts[0][label + "_sha256"] != starts[1][label + "_sha256"]) == (label == changed)


@pytest.mark.parametrize("missing", ["dnfile", "pefile"])
def test_start_reports_each_unavailable_parser_version(tmp_path, monkeypatch, missing):
    def installed(package):
        if package == missing:
            raise evaluation.PackageNotFoundError(package)
        return "available"

    monkeypatch.setattr(evaluation, "version", installed)
    assert evaluation.corpus(args(tmp_path)) == 2
    start = json.loads((tmp_path / "results.jsonl").read_text().splitlines()[0])
    assert start[missing] == "not installed"
    assert start["pefile" if missing == "dnfile" else "dnfile"] == "available"


@pytest.mark.parametrize("outcome", ["success", "unread", "failure"])
def test_slowest_read_times_the_reader_even_when_it_raises(tmp_path, monkeypatch, outcome):
    data = build_dotnet_demo()
    (tmp_path / "fixture.dll").write_bytes(data)
    found = metadata()
    derived = evaluation.derive(data, 1024)
    clock = [10.0]
    monkeypatch.setattr(evaluation.time, "perf_counter", lambda: clock[0])

    def read(_data):
        clock[0] += 2.5
        if outcome == "unread":
            raise ValueError("synthetic unsupported layout")
        if outcome == "failure":
            raise RuntimeError("synthetic reader failure")
        return found

    def derive(*_args):
        clock[0] += 100.0
        return derived

    def reference(*_args):
        clock[0] += 1000.0
        return expected_for(found)

    monkeypatch.setattr(evaluation.dotnet, "read", read)
    monkeypatch.setattr(evaluation, "derive", derive)
    monkeypatch.setattr(evaluation, "reference", reference)
    assert evaluation.corpus(args(tmp_path)) == {"success": 0, "unread": 2, "failure": 1}[outcome]
    summary = json.loads((tmp_path / "results.jsonl").read_text().splitlines()[-1])
    assert summary["slowest_read_seconds"] == 2.5
    assert clock[0] == (1112.5 if outcome == "success" else 12.5)


def test_file_symlink_filter_precedes_file_selection_without_os_privileges(tmp_path, monkeypatch):
    for filename in ("a.dll", "b.dll"):
        (tmp_path / filename).write_bytes(b"synthetic")
    monkeypatch.setattr(type(tmp_path), "is_symlink", lambda path: path.name == "a.dll")
    assert list(evaluation.files([tmp_path], True, (".dll",), 2)) == [tmp_path / "b.dll"]


@pytest.mark.parametrize("directory", [False, True])
def test_selection_excludes_file_and_directory_symlinks_before_stride(tmp_path, directory):
    root = tmp_path / "corpus"
    root.mkdir()
    (root / "b.dll").write_bytes(b"synthetic regular file")
    target = tmp_path / "target"
    if directory:
        target.mkdir()
        (target / "fixture.dll").write_bytes(b"synthetic linked directory file")
    else:
        target.write_bytes(b"synthetic linked file")
    try:
        (root / "a.dll").symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError) as problem:
        pytest.skip(f"symlinks unavailable: {problem}")
    assert list(evaluation.files([root], True, (".dll",), 2)) == [root / "b.dll"]


def test_difference_log_counts_details_omitted_without_claiming_only_twenty(tmp_path, monkeypatch):
    (tmp_path / "fixture.dll").write_bytes(build_dotnet_demo())
    expected = expected_for(metadata())
    for rows in expected.rows.values():
        for row in rows.values():
            for key in row:
                row[key] = None
    monkeypatch.setattr(evaluation, "reference", lambda *_args: expected)
    assert evaluation.corpus(args(tmp_path)) == 1
    records = [json.loads(line) for line in (tmp_path / "results.jsonl").read_text().splitlines()]
    result = next(row for row in records if row["event"] == "file")["reference"]
    assert len(result["differences"]) == 20
    assert result["difference_count"] > 20
    assert result["difference_details_omitted"] == result["difference_count"] - 20


def test_no_reference_data_is_an_explicit_incomplete_comparison(tmp_path, monkeypatch):
    (tmp_path / "fixture.dll").write_bytes(build_dotnet_demo())
    monkeypatch.setattr(evaluation, "reference", lambda *_args: None)
    assert evaluation.corpus(args(tmp_path)) == 2
    records = [json.loads(line) for line in (tmp_path / "results.jsonl").read_text().splitlines()]
    assert records[-1]["counts"]["reference_fields_compared"] == 0
    assert records[-1]["reasons"]["reference has no metadata"] == 1


def test_reference_does_not_call_reader_or_force_dnfile_full_table_resolution(monkeypatch):
    dnfile = pytest.importorskip("dnfile")
    data = build_dotnet_demo()
    pe = dnfile.dnPE(data=data, clr_lazy_load=True)
    try:

        def forbidden(*_args, **_kw):
            pytest.fail("reference forced full table resolution or used LupaBin's reader")

        monkeypatch.setattr(evaluation.dotnet, "read", forbidden)
        for table in pe.net.mdtables.tables.values():
            for row in table.rows:
                row._full_loader = forbidden
        result = evaluation.reference_from_pe(pe)
        assert result.rows["members"][1]["assembly"] == b"mscorlib"
        assert result.rows["types"][2]["methods"] == 2
    finally:
        pe.close()
