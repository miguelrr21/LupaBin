"""Indirect jumps: tail calls to imports, bounded jump tables, and relocated fields that
stop a walk that strays into data."""

import json
import struct

import pytest

from lupabin.analysis import analyze_bytes
from lupabin.evidence.facts import ApiCallEvidence, CallArgumentEvidence
from lupabin.evidence.models import Limits, Report
from lupabin.extractors.code_calls import CallFinder
from lupabin.extractors.code_disasm import Region, walk
from lupabin.extractors.code_entries import relocations
from lupabin.extractors.pe_layout import parse_layout
from tests.fixtures.pe_builder import (
    CODE_RVA,
    HKCU32,
    build_args_demo,
    build_code_pe,
    switch_x64_code,
    switch_x86_code,
    with_pdata,
    with_relocations,
)
from tests.test_code_engine import BASE32, IAT, reader, rel32


def jumps_in(code, bits, entries=(0x1000,)):
    regions = [Region(0x1000, bytearray(code))]
    base = BASE32 if bits == 32 else 0x140000000
    finder = CallFinder(reader(regions), bits, base, {IAT}, 4096)
    walk(regions, list(entries), bits, 10_000, finder.visit, 1000, jumped=finder.jumped)
    return [(c.via, c.rva, c.slot, c.helper) for c in finder.calls()]


def calls(report: Report) -> list[ApiCallEvidence]:
    return [fact for fact in report.evidence if isinstance(fact, ApiCallEvidence)]


# --- tail calls --------------------------------------------------------------------


def test_x64_tail_jump_to_an_import_is_a_call():
    code = bytes.fromhex("4883c428") + b"\xff\x25" + rel32(0x1004, IAT, 6)  # add rsp; jmp
    assert jumps_in(code, 64) == [("tail", 0x1004, IAT, None)]


def test_x86_tail_jump_to_an_import_is_a_call():
    code = b"\x5e" + b"\xff\x25" + struct.pack("<I", BASE32 + IAT)  # pop esi; jmp [slot]
    assert jumps_in(code, 32) == [("tail", 0x1001, IAT, None)]


def test_a_thunk_is_not_counted_as_a_tail_call():
    """A run that starts with `jmp [slot]` is an import thunk: the calls that reach it
    are published with it as their helper."""
    code = bytearray(b"\xcc" * 0x20)
    code[0:5] = b"\xe8" + rel32(0x1000, 0x1010)
    code[5] = 0xC3
    code[0x10:0x16] = b"\xff\x25" + rel32(0x1010, IAT, 6)
    assert jumps_in(bytes(code), 64) == [("thunk", 0x1000, IAT, (0x1010, 6))]


def test_a_tail_jump_elsewhere_is_not_a_call():
    code = bytes.fromhex("4883c428") + b"\xff\x25" + rel32(0x1004, IAT + 8, 6)
    assert jumps_in(code, 64) == []


def test_tail_calls_are_published_and_validated():
    code = bytes.fromhex("4883c428") + b"\xff\x25" + rel32(CODE_RVA + 4, 0x1140, 6)
    report = analyze_bytes(build_code_pe(code, bits=64), Limits())
    found = calls(report)
    assert [(c.data.via, c.location.rva) for c in found] == [("tail", CODE_RVA + 4)]
    Report.model_validate_json(report.model_dump_json())


def test_an_x86_tail_call_cannot_carry_an_argument():
    """At a tail jump the caller's return address is already on the stack: x86 pushes
    before it are not the callee's arguments, and the model rejects one."""
    dumped = analyze_bytes(build_args_demo(bits=32), Limits()).model_dump(mode="json")
    call = next(f for f in dumped["evidence"] if f["kind"] == "api_call")
    raw = bytes.fromhex(call["data"]["raw_hex"])
    assert call["data"]["via"] == "direct" and raw[:2] == b"\xff\x15"
    call["data"]["raw_hex"] = (b"\xff\x25" + raw[2:]).hex()  # the same slot, as a jmp
    call["data"]["via"] = "tail"
    assert any(f["kind"] == "call_argument" for f in dumped["evidence"])
    with pytest.raises(ValueError, match="tail call"):
        Report.model_validate_json(json.dumps(dumped))


# --- relocated fields ---------------------------------------------------------------


def test_a_run_stops_where_it_would_cut_a_relocated_field():
    """`mov eax, imm32` whose immediate is relocated at +1 decodes; the same bytes one
    byte later would start inside the field and are not code."""
    code = b"\xb8" + struct.pack("<I", BASE32 + 0x1000) + b"\xc3"
    fields = bytearray(len(code))
    fields[2:5] = b"\1\1\1"  # the field at +1 covers +1..+4; all but its first byte
    region = Region(0x1000, bytearray(code), fields)
    good = walk([region], [0x1000], 32, 100, lambda *a: None, 10)
    assert good.instructions == 2
    bad = walk([region], [0x1002], 32, 100, lambda *a: None, 10)
    assert bad.instructions == 0


def test_relocations_are_read_from_the_directory():
    data = with_relocations(build_code_pe(b"\xc3"), [CODE_RVA + 1, 0x1234], bits=32)
    assert list(relocations(parse_layout(data, Limits())) or []) == [0x1234, CODE_RVA + 1]


# --- jump tables ----------------------------------------------------------------------


def switch_x86(entries=3, bound=2, relocate=True, drop=None):
    code, fields = switch_x86_code(entries, bound)
    data = build_code_pe(code, bits=32)
    if relocate:
        data = with_relocations(data, [f for f in fields if f != drop], bits=32)
    return data


def test_x86_bounded_jump_table_is_followed():
    report = analyze_bytes(switch_x86(), Limits())
    assert len(calls(report)) == 3  # one call in each case block


def test_x86_table_without_relocations_is_not_followed():
    assert calls(analyze_bytes(switch_x86(relocate=False), Limits())) == []


def test_x86_table_with_an_entry_the_linker_did_not_relocate_is_not_followed():
    code, fields = switch_x86_code()
    table_entries = [f for f in fields if f >= CODE_RVA + 0x100]
    report = analyze_bytes(switch_x86(drop=table_entries[1]), Limits())
    assert calls(report) == []


def test_x86_table_reads_only_the_entries_its_bound_allows():
    """cmp eax, 1 allows two entries: the third case block is never walked."""
    report = analyze_bytes(switch_x86(bound=1), Limits())
    assert len(calls(report)) == 2


def switch_x64(outside=False, pdata=True):
    code, end = switch_x64_code(outside=outside)
    data = build_code_pe(code, bits=64)
    if pdata:
        data = with_pdata(data, [(CODE_RVA, end)])
    return data


def test_x64_bounded_jump_table_is_followed():
    report = analyze_bytes(switch_x64(), Limits())
    assert len(calls(report)) == 3


def test_x64_table_with_a_target_outside_the_function_is_not_followed():
    assert calls(analyze_bytes(switch_x64(outside=True), Limits())) == []


def test_x64_table_without_pdata_is_not_followed():
    assert calls(analyze_bytes(switch_x64(pdata=False), Limits())) == []


def test_arguments_are_not_read_across_a_tail_jump_in_x86():
    code = HKCU32 + b"\xff\x25" + struct.pack("<I", 0x400000 + 0x1140)  # push; jmp [slot]
    data = build_code_pe(code, bits=32, dll=b"advapi32.dll", function=b"RegOpenKeyExW")
    report = analyze_bytes(data, Limits())
    assert [c.data.via for c in calls(report)] == ["tail"]
    assert not any(isinstance(f, CallArgumentEvidence) for f in report.evidence)
