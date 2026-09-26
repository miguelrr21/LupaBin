import struct

import pytest

from lupabin.evidence import call_forms
from lupabin.extractors.code_calls import CallFinder
from lupabin.extractors.code_disasm import Region, walk

BASE32 = 0x400000
IAT = 0x2000


def rel32(source, target, size=5):
    return struct.pack("<i", target - (source + size))


def reader(regions):
    def read(rva, size):
        for region in regions:
            if region.rva <= rva and rva + size <= region.end:
                return bytes(region.data[rva - region.rva : rva - region.rva + size])
        return None

    return read


def calls_in(
    code, bits, slots=(IAT,), entries=(0x1000,), budget=10_000, quota=4096, call_budget=1000
):
    regions = [Region(0x1000, bytearray(code))]
    base = BASE32 if bits == 32 else 0x140000000
    finder = CallFinder(reader(regions), bits, base, set(slots), quota)
    result = walk(regions, list(entries), bits, budget, finder.visit, call_budget)
    return result, finder.calls()


# --- canonical forms -------------------------------------------------------------


def test_x86_direct_call_uses_the_absolute_slot_address():
    raw = b"\xff\x15" + struct.pack("<I", BASE32 + IAT)
    assert call_forms.memory_slot(raw, 0x1000, 32, BASE32, call_forms.CALL) == IAT
    assert call_forms.memory_slot(raw, 0x1000, 32, BASE32, call_forms.JMP) is None


@pytest.mark.parametrize("prefix", [b"", b"\x48"])
def test_x64_direct_call_is_relative_to_the_next_instruction(prefix):
    size = 6 + len(prefix)
    raw = prefix + b"\xff\x15" + rel32(0x1000, IAT, size)
    assert call_forms.memory_slot(raw, 0x1000, 64, 0, call_forms.CALL) == IAT


@pytest.mark.parametrize(
    "raw",
    [
        b"\x3e\xff\x15\x00\x20\x40\x00",  # a prefix is not a canonical form
        b"\xff\x14\x25\x00\x20\x40\x00",  # SIB addressing
        b"\xff\x15\x00\x00\x00\x00",  # below the image base
    ],
)
def test_non_canonical_x86_memory_calls_abstain(raw):
    assert call_forms.memory_slot(raw, 0x1000, 32, BASE32, call_forms.CALL) is None


def test_x64_rex_other_than_w_is_not_canonical():
    raw = b"\x41\xff\x15" + rel32(0x1000, IAT, 7)
    assert call_forms.memory_slot(raw, 0x1000, 64, 0, call_forms.CALL) is None


def test_register_forms_and_their_register_numbers():
    assert call_forms.register_load(b"\xa1" + struct.pack("<I", BASE32 + IAT), 0, 32, BASE32) == (
        0,
        IAT,
    )
    assert call_forms.register_load(
        b"\x8b\x35" + struct.pack("<I", BASE32 + IAT), 0, 32, BASE32
    ) == (6, IAT)
    load = b"\x4c\x8b\x1d" + rel32(0x1000, IAT, 7)  # mov r11, [rip+disp]
    assert call_forms.register_load(load, 0x1000, 64, 0) == (11, IAT)
    assert call_forms.register_call(b"\xff\xd6", 32) == 6
    assert call_forms.register_call(b"\x41\xff\xd3", 64) == 11
    assert call_forms.register_call(b"\x41\xff\xd3", 32) is None


def test_register_forms_reject_partial_loads_and_the_stack_pointer():
    assert call_forms.register_load(b"\x8b\x05" + rel32(0, IAT, 6), 0, 64, 0) is None  # 32-bit
    assert (
        call_forms.register_load(b"\x8b\x25" + struct.pack("<I", BASE32 + IAT), 0, 32, BASE32)
        is None
    )
    assert call_forms.register_load(b"\x8b\x45\x08", 0, 32, BASE32) is None  # [ebp+8]
    assert call_forms.register_call(b"\xff\xd4", 32) is None


# --- walk and classification -----------------------------------------------------


def test_x86_direct_call_found_from_the_entry_point():
    code = b"\x6a\x00" + b"\xff\x15" + struct.pack("<I", BASE32 + IAT) + b"\xc3"
    result, calls = calls_in(code, 32)
    assert result.instructions == 3 and not result.limit
    assert [(c.via, c.rva, c.size, c.slot, c.helper) for c in calls] == [
        ("direct", 0x1002, 6, IAT, None)
    ]


def test_x64_call_through_a_thunk():
    thunk = 0x1010
    code = bytearray(b"\xcc" * 0x20)
    code[0:5] = b"\xe8" + rel32(0x1000, thunk)
    code[5] = 0xC3
    code[0x10:0x16] = b"\xff\x25" + rel32(thunk, IAT, 6)
    _, calls = calls_in(bytes(code), 64)
    assert [(c.via, c.rva, c.slot, c.helper) for c in calls] == [("thunk", 0x1000, IAT, (thunk, 6))]


def test_x86_call_through_a_register_loaded_just_before():
    code = b"\x8b\x35" + struct.pack("<I", BASE32 + IAT) + b"\xff\xd6\xc3"
    _, calls = calls_in(code, 32)
    assert [(c.via, c.rva, c.helper) for c in calls] == [("register", 0x1006, (0x1000, 6))]


def test_register_call_after_another_instruction_abstains():
    # the load is not adjacent: something in between could have changed esi
    code = b"\x8b\x35" + struct.pack("<I", BASE32 + IAT) + b"\x90\xff\xd6\xc3"
    assert calls_in(code, 32)[1] == []


def test_register_call_with_a_different_register_abstains():
    code = b"\x8b\x35" + struct.pack("<I", BASE32 + IAT) + b"\xff\xd7\xc3"
    assert calls_in(code, 32)[1] == []


def test_register_call_at_a_block_start_has_no_previous_instruction():
    load = b"\x8b\x35" + struct.pack("<I", BASE32 + IAT)
    code = load + b"\xff\xd6\xc3"
    assert calls_in(code, 32, entries=(0x1000 + len(load),))[1] == []


def test_calls_to_slots_that_are_not_imports_are_not_published():
    code = b"\xff\x15" + struct.pack("<I", BASE32 + IAT + 4) + b"\xc3"
    assert calls_in(code, 32)[1] == []


def test_bytes_that_are_never_reached_are_not_decoded():
    call = b"\xff\x15" + struct.pack("<I", BASE32 + IAT)
    result, calls = calls_in(b"\xc3" + call, 32)
    assert result.instructions == 1 and calls == []


def test_branch_targets_are_followed_but_indirect_jumps_are_not():
    call = b"\xff\x15" + struct.pack("<I", BASE32 + IAT)
    # jz +2 ; ret ; ret ; call [slot] ; jmp eax ; call [slot] (never reached)
    code = b"\x74\x02\xc3\xc3" + call + b"\xff\xe0" + call
    _, calls = calls_in(code, 32)
    assert [c.rva for c in calls] == [0x1004]


def test_the_instruction_budget_stops_the_walk_and_says_so():
    code = b"\x90" * 50 + b"\xc3"
    result, _ = calls_in(code, 32, budget=10)
    assert result.instructions == 10 and result.limit


def test_entries_outside_executable_regions_are_ignored():
    result, calls = calls_in(b"\xc3", 32, entries=(0x0FFF, 0x5000, 0x1000))
    assert result.instructions == 1 and calls == []


def test_undecodable_bytes_end_the_run():
    # 06 (push es) does not exist in 64-bit mode: nothing after it is decoded
    call = b"\xff\x15" + rel32(0x1001, IAT, 6)
    result, calls = calls_in(b"\x06" + call, 64)
    assert result.instructions == 0 and calls == []


def test_quota_keeps_each_import_first_then_repeats_in_order():
    first, second = IAT, IAT + 4
    call = lambda slot: b"\xff\x15" + struct.pack("<I", BASE32 + slot)  # noqa: E731
    code = call(first) * 3 + call(second) + b"\xc3"
    result, calls = calls_in(code, 32, slots=(first, second), quota=3)
    assert result.calls == 4
    assert [(c.slot, c.rva) for c in calls] == [(first, 0x1000), (second, 0x1012), (first, 0x1006)]


def test_far_jumps_end_the_run():
    call = b"\xff\x15" + struct.pack("<I", BASE32 + IAT)
    # ljmp 0x10:0x1000 is never followed, nor does execution fall through it
    code = b"\xea\x00\x10\x00\x00\x10\x00" + call
    result, calls = calls_in(code, 32)
    assert result.instructions == 1 and calls == []


def test_the_call_budget_stops_the_walk_and_says_so():
    call = b"\xff\x15" + struct.pack("<I", BASE32 + IAT)
    result, calls = calls_in(call * 5 + b"\xc3", 32, call_budget=2)
    assert result.call_limit and not result.limit
    assert result.calls == 2 and len(calls) == 2


# --- entries into the walked code and linear stretches (for call arguments) -------


def stretches(code, entries=(0x1000,), budget=10_000):
    regions = [Region(0x1000, bytearray(code))]
    seen = []
    visitor = lambda data, offset, rva, size, previous, start: seen.append((rva, start))  # noqa: E731
    return walk(regions, list(entries), 32, budget, visitor, 1000), seen


def test_a_stretch_starts_at_the_run_or_after_the_previous_call():
    call = b"\xff\x15" + struct.pack("<I", BASE32 + IAT)
    # nop ; call [slot] ; jz 0x100f ; call [slot] ; ret
    code = b"\x90" + call + b"\x74\x06" + call + b"\xc3"
    result, seen = stretches(code)
    # a conditional branch does not end the stretch; a call does
    assert seen == [(0x1001, 0x1000), (0x1009, 0x1007)]
    assert result.targets.last(0x1000, 0x100F) == 0x100F  # the branch target
    assert result.targets.last(0x1007, 0x1009) is None
    assert result.targets.marks[0][0] == 1  # the entry point


def test_a_run_that_reaches_decoded_code_marks_where_it_joins():
    # from 0x1002: nop ; nop ; nop ; ret. From 0x1000: mov eax, 0x90909090 ends at 0x1005,
    # inside code already decoded, without a branch to it.
    code = b"\xb8\x90\x90\x90\x90\xc3"
    result, _ = stretches(code, entries=(0x1002, 0x1000))
    assert result.targets.last(0x1002, 0x1005) == 0x1005


def test_targets_left_pending_by_a_budget_are_marked():
    code = b"\xe8" + rel32(0x1000, 0x1100) + b"\x90" * 0x200
    result, seen = stretches(code, budget=1)
    assert result.limit and seen == [(0x1000, 0x1000)]
    assert result.targets.last(0x1000, 0x1100) == 0x1100


def test_code_after_a_jump_to_the_next_instruction_is_walked():
    """jmp +0 ends its run but lands on the next instruction, which must be walked."""
    code = b"\xeb\x00" + b"\xff\x15" + struct.pack("<I", BASE32 + IAT) + b"\xc3"
    _, calls = calls_in(code, 32)
    assert [(c.via, c.rva) for c in calls] == [("direct", 0x1002)]
