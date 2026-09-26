import asyncio
import json
import struct
import subprocess
import sys

import pytest

from lupabin.analysis import analyze_bytes
from lupabin.errors import LupaBinError
from lupabin.evidence.code import verify_calls
from lupabin.evidence.collector import Collector, Progress
from lupabin.evidence.models import Limits, Report
from lupabin.evidence.primitives import CodeLimits
from lupabin.extractors.code import CodeExtractor
from lupabin.extractors.pe import PEExtractor
from lupabin.ingest.reader import from_bytes
from lupabin.runner import run_isolated
from lupabin.saved_report import check_against_sample
from tests.fixtures.pe_builder import build_code_demo, build_code_pe, build_pe, with_load_config
from tests.test_runner import FakeDocker


def calls(report):
    return [fact for fact in report.evidence if fact.kind == "api_call"]


def code_parts(report):
    run = next(run for run in report.extractor_runs if run.source == "code")
    return {part.name: part for part in run.components}


def code_reasons(report):
    return {
        (reason.component, reason.code)
        for reason in report.extractor_errors + report.limitations
        if reason.source == "code"
    }


@pytest.mark.parametrize("bits", [32, 64])
def test_each_canonical_form_is_published_and_cites_its_import(bits):
    data = build_code_demo(bits=bits)
    report = analyze_bytes(data)
    assert report.analysis.status == "completed"
    facts = {fact.id: fact for fact in report.evidence}
    found = calls(report)
    assert [fact.data.via for fact in found] == ["direct", "thunk", "register"]
    for fact in found:
        cited = facts[fact.provenance.evidence_ids[0]]
        assert cited.kind == "import" and cited.data.function.text == "ExitProcess"
        assert fact.confidence == "observed" and fact.location.section.text == ".text"
        start = fact.location.offset
        assert data[start : start + fact.location.length].hex() == fact.data.raw_hex
    parts = code_parts(report)
    assert parts["disassembly"].examined == 6  # three calls, mov, ret and the thunk's jmp
    assert parts["api_calls"].evidence_count == 3
    verify_calls(report.evidence, data)


def test_code_outside_executable_sections_is_not_walked():
    report = analyze_bytes(build_pe())  # its entry point lies in a non-executable .idata
    parts = code_parts(report)
    assert parts["disassembly"].status == "complete" and parts["disassembly"].examined == 0
    assert calls(report) == []


def test_non_pe_input_blocks_code_analysis():
    report = analyze_bytes(b"not a portable executable" * 4)
    assert {part.status for part in code_parts(report).values()} == {"blocked"}
    assert ("disassembly", "unsupported_format") in code_reasons(report)


def test_other_architectures_are_blocked_not_guessed():
    data = bytearray(build_code_demo(bits=32))
    struct.pack_into("<H", data, 0x84, 0x1C0)  # ARM
    report = analyze_bytes(bytes(data))
    assert {part.status for part in code_parts(report).values()} == {"blocked"}
    assert ("api_calls", "unsupported_architecture") in code_reasons(report)
    assert any(fact.kind == "import" for fact in report.evidence)  # the PE facts remain


def test_instruction_budget_leaves_both_components_partial():
    report = analyze_bytes(build_code_demo(), Limits(code=CodeLimits(instructions=2)))
    parts = code_parts(report)
    assert parts["disassembly"].status == parts["api_calls"].status == "partial"
    assert parts["disassembly"].examined == 2
    assert ("api_calls", "code_instruction_limit") in code_reasons(report)
    assert report.analysis.status == "partial"


def test_call_quota_keeps_a_prefix_and_says_so():
    report = analyze_bytes(build_code_demo(), Limits(code=CodeLimits(calls=1)))
    assert [fact.data.via for fact in calls(report)] == ["direct"]
    assert ("api_calls", "api_call_limit") in code_reasons(report)


def test_incomplete_imports_make_calls_partial():
    data = build_code_demo()
    collector = Collector(Limits())
    PEExtractor().extract(data, collector, Progress("pe", "test"))
    collector.coverage[("pe", "imports_normal")] = "partial"
    progress = Progress("code", "test")
    CodeExtractor().extract(data, collector, progress)
    assert progress.states["api_calls"] == "partial"
    assert progress.states["disassembly"] == "complete"
    # arguments of calls that could not be published cannot be cited either
    assert progress.states["call_arguments"] == "partial"
    assert [(reason.component, reason.code) for reason in progress.limitations] == [
        ("api_calls", "dependency_omitted"),
        ("call_arguments", "dependency_omitted"),
        ("string_references", "dependency_omitted"),
    ]


# --- the contract re-derives each call from its own bytes ----------------------


def payload(bits=32):
    return json.loads(analyze_bytes(build_code_demo(bits=bits)).model_dump_json())


def via(data, name):
    return next(
        f for f in data["evidence"] if f.get("kind") == "api_call" and f["data"]["via"] == name
    )


def other_slot(data):
    raw = bytes.fromhex(via(data, "direct")["data"]["raw_hex"])
    return raw[:2].hex() + struct.pack("<I", int.from_bytes(raw[2:], "little") + 4).hex()


@pytest.mark.parametrize(
    "tamper,reason",
    [
        (
            lambda d: via(d, "direct")["data"].update(raw_hex=other_slot(d)),
            "do not reach the slot of the cited import",
        ),
        (
            lambda d: via(d, "direct").update(provenance={"evidence_ids": ["E1"]}),
            "must cite an import",  # E1 is the PE header
        ),
        (
            lambda d: via(d, "direct")["location"].update(offset=4609),
            "offset disagrees with its section mapping",
        ),
        (
            lambda d: via(d, "direct")["location"].update(rva=0x1000, offset=0x200),
            "exactly one executable section",  # .idata is not executable
        ),
        (
            lambda d: via(d, "direct")["location"].update(section=None),
            "section name disagrees",
        ),
        (
            lambda d: via(d, "thunk")["data"]["helper"].update(rva=0x2021, offset=0x1221),
            "do not reach the slot of the cited import",
        ),
        (
            lambda d: via(d, "register")["data"].update(raw_hex="ffd7"),  # call edi, not esi
            "do not reach the slot of the cited import",
        ),
        (
            lambda d: via(d, "register")["data"]["helper"].update(rva=0x200A, offset=0x120A),
            "right before the call",
        ),
        (
            lambda d: via(d, "direct")["data"].update(via="thunk"),
            "only thunk and register calls rest on a helper",
        ),
        (
            lambda d: d["analysis"]["limits"]["code"].update(calls=2),
            "evidence exceeds effective quota",
        ),
    ],
)
def test_report_rejects_calls_its_bytes_do_not_support(tamper, reason):
    data = payload()
    tamper(data)
    with pytest.raises(ValueError, match=reason):
        Report.model_validate_json(json.dumps(data))


def test_x64_call_moved_by_one_byte_no_longer_reaches_the_slot():
    data = payload(bits=64)
    fact = via(data, "direct")
    fact["location"].update(rva=fact["location"]["rva"] + 1, offset=fact["location"]["offset"] + 1)
    with pytest.raises(ValueError, match="do not reach the slot"):
        Report.model_validate_json(json.dumps(data))


def test_complete_calls_require_a_complete_walk():
    data = payload()
    run = next(r for r in data["extractor_runs"] if r["source"] == "code")
    run["components"][0]["status"] = "partial"
    run["status"] = "partial"
    data["analysis"]["status"] = "partial"
    data["limitations"].append(
        {"source": "code", "component": "disassembly", "code": "code_instruction_limit"}
    )
    with pytest.raises(ValueError, match="complete call coverage needs a complete walk"):
        Report.model_validate_json(json.dumps(data))


# --- the host compares every cited byte with the sample ------------------------


def forged_thunk(data):
    """A coherent thunk call whose cited bytes are not the sample's: only the bytes tell."""
    via(data, "thunk")["data"].update(
        raw_hex="e8f5000000",  # call rel32 from 0x2006 to 0x2100
        helper={"offset": 0x1300, "rva": 0x2100, "raw_hex": "ff2540114000"},
    )
    return Report.model_validate_json(json.dumps(data))  # still a valid report...


def test_host_rejects_calls_whose_bytes_are_not_in_the_sample():
    sample = build_code_demo()
    report = forged_thunk(payload())
    with pytest.raises(ValueError, match="code evidence bytes differ from the sample"):
        verify_calls(report.evidence, sample)
    with pytest.raises(LupaBinError) as caught:
        check_against_sample(report, from_bytes(sample, Limits()))
    assert caught.value.code == "report_mismatch"
    docker = FakeDocker(output=report.model_dump_json().encode())
    with pytest.raises(LupaBinError) as caught:
        asyncio.run(run_isolated(sample, Limits(), docker))
    assert caught.value.code == "invalid_worker_output"


def test_runner_accepts_genuine_calls():
    report = asyncio.run(run_isolated(build_code_demo(bits=64), Limits(), FakeDocker()))
    assert len(calls(report)) == 3


def test_the_host_process_never_loads_the_disassembler():
    probe = (
        "import sys, lupabin.cli, lupabin.runner, lupabin.saved_report;"
        "print('capstone' in sys.modules)"
    )
    result = subprocess.run(  # noqa: S603 - fixed argv: this interpreter and a constant probe
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "False"


# --- entry points the toolchain writes: Control Flow Guard and SafeSEH ----------


def hidden_function(bits):
    """Entry point `ret`; at 0x2100 a function calling the import that nothing jumps to."""
    code = bytearray(b"\xc3" + b"\xcc" * 0x1FF)
    if bits == 32:
        call = b"\xff\x15" + struct.pack("<I", 0x400000 + 0x1140)
    else:
        call = b"\xff\x15" + struct.pack("<i", 0x1140 - (0x2100 + 6))
    code[0x100 : 0x100 + len(call) + 1] = call + b"\xc3"
    return build_code_pe(bytes(code), bits=bits)


def called_from(data):
    return [fact.location.rva for fact in calls(analyze_bytes(data))]


@pytest.mark.parametrize("bits", [32, 64])
def test_guard_table_targets_are_walked(bits):
    assert called_from(hidden_function(bits)) == []
    assert called_from(with_load_config(hidden_function(bits), bits=bits, guard=(0x2100,))) == [
        0x2100
    ]


def test_guard_entries_with_metadata_bytes_use_their_stride():
    flags = 0x400 | (1 << 28)  # one metadata byte after each RVA
    data = with_load_config(hidden_function(32), guard=(0x2000, 0x2100), flags=flags)
    assert called_from(data) == [0x2100]


def test_safe_seh_handlers_are_walked_in_x86():
    assert called_from(with_load_config(hidden_function(32), seh=(0x2100,))) == [0x2100]


@pytest.mark.parametrize(
    "options",
    [
        {"flags": 0},  # the table-present flag is not set
        {"size": 0x54},  # the declared structure ends before GuardFlags
        {"count": 0xFFFFFFFF},  # a count the file cannot hold
    ],
)
def test_unusable_guard_tables_add_no_entries(options):
    data = with_load_config(hidden_function(32), guard=(0x2100,), **options)
    report = analyze_bytes(data)
    assert calls(report) == [] and report.analysis.status == "completed"


def test_the_walk_stops_at_its_deadline_and_says_so():
    data = build_code_demo()
    collector = Collector(Limits())
    PEExtractor().extract(data, collector, Progress("pe", "test"))
    for table in ("imports_normal", "imports_delay"):
        collector.coverage[("pe", table)] = "complete"
    collector.started -= 3600  # the analysis began an hour ago: no time is left
    progress = Progress("code", "test")
    CodeExtractor().extract(data, collector, progress)
    assert progress.states == {
        "disassembly": "partial",
        "api_calls": "partial",
        "call_arguments": "partial",
        "string_references": "partial",
        "main_function": "partial",
    }
    assert {(reason.component, reason.code) for reason in progress.limitations} == {
        ("disassembly", "code_time_limit"),
        ("api_calls", "code_time_limit"),
        ("call_arguments", "dependency_omitted"),
        ("string_references", "dependency_omitted"),
        ("main_function", "dependency_omitted"),
    }
