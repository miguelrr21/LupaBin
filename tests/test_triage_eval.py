import copy
import hashlib
import json
import struct
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from lupabin.evidence import pe_triage as triage
from tests import triage_eval as evaluation
from tests.test_pe_resources import TEST_LIMITS
from tests.test_pe_triage import _BUDGETS, _PE, _certificate, _rsds

CONFIG = evaluation.Config(_BUDGETS, TEST_LIMITS, max_details=2, max_detail_bytes=32)


def snapshot() -> evaluation.Snapshot:
    value = {key: evaluation.Observation([]) for key in evaluation.GROUPS}
    value["layout"] = evaluation.Observation(dict(bits=32, headers=512, image=12288))
    value["sections"] = evaluation.Observation([dict(raw_offset=512), dict(raw_offset=1024)])
    return value


def test_complete_comparison_with_doubles_and_fingerprint() -> None:
    result = evaluation.evaluate(
        b"invented", CONFIG, reader=lambda *_: snapshot(), reference=lambda *_: snapshot()
    )
    assert result["exit_code"] == 0
    assert result["compared"] > 0
    assert result["sha256"] == hashlib.sha256(b"invented").hexdigest()
    assert result["differences"] == 0


@pytest.mark.parametrize("value", [None, 0, 511, "512"])
def test_altered_observed_field_is_not_a_match(value: object) -> None:
    mine, theirs = snapshot(), snapshot()
    theirs["sections"].value[0]["raw_offset"] = value
    result = evaluation.compare(mine, theirs, CONFIG)
    assert result["exit_code"] == 1
    assert result["groups"]["sections"]["differences"] == 1
    assert (
        result["groups"]["sections"]["fields"]["[0].raw_offset".replace("[0]", "[]")]["differences"]
        == 1
    )


def test_none_is_a_value_not_a_wildcard_inside_rows() -> None:
    mine, theirs = snapshot(), snapshot()
    mine["resources"] = evaluation.Observation([dict(id=None, name=b"named")])
    theirs["resources"] = evaluation.Observation([dict(id=1, name=b"named")])
    assert evaluation.compare(mine, theirs, CONFIG)["exit_code"] == 1
    theirs["resources"].value[0]["id"] = None
    assert evaluation.compare(mine, theirs, CONFIG)["exit_code"] == 0


def test_order_and_missing_rows_are_compared() -> None:
    mine, theirs = snapshot(), snapshot()
    theirs["sections"].value.reverse()
    assert evaluation.compare(mine, theirs, CONFIG)["differences"] == 2
    theirs["sections"].value.pop()
    result = evaluation.compare(mine, theirs, CONFIG)
    assert result["exit_code"] == 1
    assert result["groups"]["sections"]["reader_rows"] == 2
    assert result["groups"]["sections"]["reference_rows"] == 1


@pytest.mark.parametrize(
    "missing",
    [None, evaluation.Observation(None), evaluation.Observation([], "unavailable", ("no_oracle",))],
)
def test_missing_reference_is_not_green(missing: evaluation.Observation | None) -> None:
    mine, theirs = snapshot(), snapshot()
    if missing is None:
        theirs.pop("certificate_oracle")
    else:
        theirs["certificate_oracle"] = missing
    result = evaluation.compare(mine, theirs, CONFIG)
    assert result["exit_code"] == 2
    assert result["groups"]["certificate_oracle"]["compared"] == 0
    assert result["groups"]["certificate_oracle"]["status"] == "unavailable"


def test_empty_snapshots_have_no_comparison() -> None:
    result = evaluation.compare({}, {}, CONFIG)
    assert result["exit_code"] == 2
    assert result["compared"] == 0
    assert set(result["groups"]) == set(evaluation.GROUPS)


def test_reader_limit_cannot_be_a_complete_prefix() -> None:
    mine, theirs = snapshot(), snapshot()
    mine["sections"] = evaluation.Observation(
        mine["sections"].value[:1], "incomplete", ("sections_limit",)
    )
    result = evaluation.compare(mine, theirs, CONFIG)
    assert result["exit_code"] == 2
    assert result["groups"]["sections"]["compared"] == 0
    assert result["groups"]["sections"]["reasons_total"] == 1


def test_failure_and_difference_take_precedence_over_incomplete() -> None:
    mine, theirs = snapshot(), snapshot()
    mine["overlay"] = evaluation.Observation(None, "incomplete", ("hash_limit",))
    theirs["sections"].value[0]["raw_offset"] = 9
    assert evaluation.compare(mine, theirs, CONFIG)["exit_code"] == 1
    mine["sections"] = evaluation.Observation(None, "failed", ("reader_exception",))
    assert evaluation.compare(mine, theirs, CONFIG)["exit_code"] == 1


def test_detail_limit_keeps_total_differences_and_reasons() -> None:
    mine, theirs = snapshot(), snapshot()
    mine["sections"] = evaluation.Observation([dict(raw_offset=i) for i in range(10)])
    theirs["sections"] = evaluation.Observation([dict(raw_offset=i + 1) for i in range(10)])
    theirs["overlay"] = evaluation.Observation(None, "unavailable", ("one", "two", "three"))
    result = evaluation.compare(mine, theirs, CONFIG)
    row = result["groups"]["sections"]
    assert row["differences"] == 10
    assert len(row["details"]) == 2
    assert row["details_omitted"] == 8
    assert result["groups"]["overlay"]["reasons_total"] == 3
    assert result["groups"]["overlay"]["reasons_omitted"] == 1


def test_hostile_detail_is_bounded_without_losing_digest() -> None:
    raw = b"<script>\xff\x1b" * 100
    value = evaluation.detail(raw, 4)
    assert value["hex"] == raw[:4].hex()
    assert value["size"] == len(raw)
    assert value["sha256"] == hashlib.sha256(raw).hexdigest()


def test_oversize_input_does_not_call_either_parser() -> None:
    def forbidden(*_):
        pytest.fail("parser called for oversized input")

    config = replace(CONFIG, triage=replace(_BUDGETS, max_input_bytes=2))
    result = evaluation.evaluate(b"three", config, reader=forbidden, reference=forbidden)
    assert result["exit_code"] == 2
    assert result["sha256"] is None
    assert result["compared"] == 0


def test_parser_exception_is_failure_not_unavailability() -> None:
    def broken(*_):
        raise RuntimeError("invented")

    result = evaluation.evaluate(b"bytes", CONFIG, reader=broken, reference=lambda *_: snapshot())
    assert result["exit_code"] == 1
    assert all(g["status"] == "failed" for g in result["groups"].values())


@pytest.mark.parametrize("bits", [32, 64])
def test_original_resource_directory_and_raw_size_mapping(bits: int) -> None:
    pe = _PE(bits)
    struct.pack_into("<I", pe.data, pe.section + 8, 0x100)
    pe.directory(2, 0x1300, 16)
    raw = bytes(pe.data)
    result = triage.read(raw, budgets=_BUDGETS)
    assert result.layout is not None
    assert evaluation.original_directory(raw, result.layout, 2) == (0x1300, 16)
    parsed = evaluation.read_resources(raw, result, TEST_LIMITS)
    assert parsed is not None and parsed.state == "complete"
    assert parsed.directories[0].location.file_offset == 0x500


def test_layout_nonnull_with_issues_never_means_absent_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = bytes(_PE().data)
    result = triage.read(raw, budgets=_BUDGETS)
    incomplete = replace(result, layout_issues=(triage.Issue("limit", "sections"),))
    assert incomplete.layout is not None
    assert evaluation.read_resources(raw, incomplete, TEST_LIMITS) is None
    monkeypatch.setattr(evaluation.triage, "read", lambda *_a, **_k: incomplete)
    assert evaluation.reader_snapshot(raw, CONFIG)["resources"].status == "unavailable"


def test_resource_header_boundary_is_revalidated() -> None:
    raw = bytes(_PE().data)
    result = triage.read(raw, budgets=_BUDGETS)
    assert result.layout is not None
    with pytest.raises(evaluation.NotComparable, match="byte_range"):
        evaluation.original_directory(raw[:0x100], result.layout, 2)


def test_reader_resource_omission_keeps_base_and_status() -> None:
    pe = _PE()
    pe.directory(2, 0x1300, 16)
    config = replace(CONFIG, resources=replace(TEST_LIMITS, directories=0))
    value = evaluation.reader_snapshot(bytes(pe.data), config)["resources"]
    assert value.status == "incomplete"
    assert value.reasons == ("resource_directory:0:directories_limit",)


def test_mutated_projection_of_real_reader_is_detected_by_double() -> None:
    pe = _PE()
    pe.debug(_rsds())
    mine = evaluation.reader_snapshot(bytes(pe.data), CONFIG)
    theirs = copy.deepcopy(mine)
    theirs["codeview"].value[0]["age"] += 1
    assert evaluation.compare(mine, theirs, CONFIG)["exit_code"] == 1


def test_reference_dictionary_loss_is_unavailable_not_a_comparison() -> None:
    table = SimpleNamespace(
        get_file_offset=lambda: 100,
        Length=100,
        LangID=b"040904b0",
        entries={b"K": b"last"},
        entries_offsets={b"K": (126, 140)},
    )
    pe = SimpleNamespace(__structures__=[], FileInfo=[])

    def parse(_leaf):
        pe.__structures__.extend(
            [
                SimpleNamespace(name="String", get_file_offset=lambda: 120),
                SimpleNamespace(name="String", get_file_offset=lambda: 150),
            ]
        )
        pe.FileInfo.append([SimpleNamespace(StringTable=[table])])

    pe.parse_version_information = parse
    rows = [dict(path=[dict(id=16), dict(id=7), dict(id=0x409)])]
    with pytest.raises(evaluation.NotComparable, match="dictionary_loss"):
        evaluation.reference_strings(pe, rows, [SimpleNamespace(Size=100)], CONFIG)


def test_reference_versions_visit_each_resource_name_and_language() -> None:
    pe = SimpleNamespace(__structures__=[], FileInfo=[])

    def parse(leaf):
        at = leaf.at
        pe.__structures__.append(SimpleNamespace(name="String", get_file_offset=lambda: at + 30))
        table = SimpleNamespace(
            get_file_offset=lambda: at,
            Length=100,
            LangID=leaf.language,
            entries={b"K": b"value"},
            entries_offsets={b"K": (at + 36, at + 40)},
        )
        pe.FileInfo.append([SimpleNamespace(StringTable=[table])])

    pe.parse_version_information = parse
    rows = [
        dict(path=[dict(id=16), dict(id=name), dict(id=language)])
        for name, language in ((1, 0x409), (7, 0xC0A))
    ]
    leaves = [
        SimpleNamespace(Size=100, at=100, language=b"040904b0"),
        SimpleNamespace(Size=100, at=200, language=b"0c0a04e4"),
    ]
    values = evaluation.reference_strings(pe, rows, leaves, CONFIG)
    assert [v["resource_index"] for v in values] == [0, 1]
    assert [v["language"] for v in values] == [0x409, 0xC0A]
    assert [v["table_offset"] for v in values] == [100, 200]


def test_structural_certificate_and_overlay_are_not_a_certificate_oracle() -> None:
    pe = _PE()
    pe.certificate_table(_certificate(b"raw"), b"12345678", b"tail")
    data = bytes(pe.data)
    mine = evaluation.reader_snapshot(data, CONFIG)
    reference = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(
            SizeOfHeaders=512,
            NumberOfRvaAndSizes=16,
            DATA_DIRECTORY=[SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(16)],
        )
    )
    reference.OPTIONAL_HEADER.DATA_DIRECTORY[4] = SimpleNamespace(VirtualAddress=0x608, Size=16)
    certificates, overlay = evaluation.structural_tail(
        data, reference, mine["sections"].value, CONFIG
    )
    assert certificates == mine["certificate_structure"].value
    assert overlay == mine["overlay"].value
    theirs = copy.deepcopy(mine)
    theirs["certificate_oracle"] = evaluation.Observation(None, "unavailable", ("no_parser",))
    assert evaluation.compare(mine, theirs, CONFIG)["exit_code"] == 2


def test_output_is_exclusive_even_before_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "existing.jsonl"
    output.write_bytes(b"keep")

    def forbidden(*_):
        pytest.fail("provenance called before exclusive open")

    monkeypatch.setattr(evaluation, "provenance", forbidden)
    with pytest.raises(FileExistsError):
        evaluation.run([tmp_path / "benign.bin"], output, CONFIG)
    assert output.read_bytes() == b"keep"


def test_output_selection_failure_and_oversize_are_not_omitted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    benign, oversized, absent = (
        tmp_path / n for n in ("benign.bin", "oversized.bin", "absent.bin")
    )
    benign.write_bytes(b"benign")
    oversized.write_bytes(b"x" * (_BUDGETS.max_input_bytes + 1))
    calls = []

    def fake(data, _config):
        calls.append(data)
        return dict(exit_code=0, sha256=hashlib.sha256(data).hexdigest(), compared=1, differences=0)

    monkeypatch.setattr(evaluation, "evaluate", fake)
    output = tmp_path / "new.jsonl"
    assert evaluation.run([benign, oversized, absent], output, CONFIG) == 1
    records = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert [r["type"] for r in records] == ["config", "file", "file", "file", "summary"]
    assert [r["exit_code"] for r in records[1:4]] == [0, 2, 1]
    assert records[2]["sha256"] is None
    assert calls == [b"benign"]
    assert records[0]["budgets_measured"] is False
    assert set(records[0]["fingerprints"]) == {"triage", "resources", "reference", "evaluator"}
    assert records[-1]["files"] == 3


def test_cli_requires_all_explicit_budgets() -> None:
    with pytest.raises(SystemExit) as error:
        evaluation.main(["--files", "benign.bin", "--output", "new.jsonl"])
    assert error.value.code == 2


def test_no_files_or_output_as_input_are_rejected(tmp_path: Path) -> None:
    output = tmp_path / "new.jsonl"
    with pytest.raises(ValueError):
        evaluation.run([], output, CONFIG)
    with pytest.raises(ValueError):
        evaluation.run([output], output, CONFIG)
    assert not output.exists()
