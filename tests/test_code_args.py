import struct

import pytest
from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from lupabin.extractors import code_args
from lupabin.extractors.code_args import ArgumentFinder, Budget
from lupabin.extractors.code_disasm import Region, Targets

BASE32 = 0x400000
CALL32 = b"\xff\x15" + struct.pack("<I", BASE32 + 0x2000)
CALL64 = b"\xff\x15\x00\x00\x00\x00"
HKCU64 = b"\x48\xc7\xc1\x01\x00\x00\x80"  # mov rcx, 0xffffffff80000001


def find(code, bits, start=0x1000, entries=(), budget=10_000):
    """Constants for the call that ends `code`, with the stretch starting at `start`."""
    call = 0x1000 + len(code) - (6 if bits == 32 else len(CALL64))
    region = Region(0x1000, bytearray(code))
    marks = bytearray(len(code))
    for entry in entries:
        marks[entry - 0x1000] = 1
    limit = Budget(budget)
    finder = ArgumentFinder([region], Targets([0x1000], [marks]), bits, limit)
    found = finder.constants(start, call)
    if found is None:
        return None, limit
    return {position: (f.setting.value, f.setter[0]) for position, f in found.items()}, limit


# --- which register writes capstone reports, for the trusted instructions --------


@pytest.mark.parametrize(
    ("raw", "positions"),
    [
        ("b101", {0}),  # mov cl, 1
        ("b501", {0}),  # mov ch, 1
        ("6641b90100", {3}),  # mov r9w, 1
        ("4891", {0}),  # xchg rcx, rax
        ("99", {1}),  # cdq writes edx
        ("4899", {1}),  # cqo writes rdx
        ("48f7e9", {1}),  # imul rcx (one operand) writes rdx:rax
        ("5a", {1}),  # pop rdx
        ("660f7ec1", {0}),  # movd ecx, xmm0
        ("66480f7ec2", {1}),  # movq rdx, xmm0
        ("440f44c0", {2}),  # cmove r8d, eax
        ("0f95c1", {0}),  # setne cl
        ("4c8d4c2408", {3}),  # lea r9, [rsp + 8]
        ("4863c8", {0}),  # movsxd rcx, eax
        ("0fb610", {1}),  # movzx edx, byte ptr [rax]
        ("488911", set()),  # mov [rcx], rdx only reads them
        ("0f1f00", set()),  # nop dword ptr [rax]
    ],
)
def test_trusted_instructions_report_their_argument_register_writes(raw, positions):
    engine = Cs(CS_ARCH_X86, CS_MODE_64)
    engine.detail = True
    insn = next(engine.disasm(bytes.fromhex(raw), 0x1000))
    written = code_args._written(insn)
    assert written is not None
    registers = {code_args._FAMILY[r] for r in written if r in code_args._FAMILY}
    assert {code_args._ARGUMENTS[r] for r in registers if r in code_args._ARGUMENTS} == positions


@pytest.mark.parametrize("raw", ["0f05", "0f01ee", "f3480f1ec9", "cd2e", "e800000000"])
def test_instructions_capstone_underreports_are_not_trusted(raw):
    # syscall (rcx), rdpkru (edx), rdsspq rcx, int 0x2e, call
    engine = Cs(CS_ARCH_X86, CS_MODE_64)
    engine.detail = True
    assert code_args._written(next(engine.disasm(bytes.fromhex(raw), 0x1000))) is None


# --- x64 --------------------------------------------------------------------------


def test_x64_registers_set_in_the_stretch_are_recovered():
    code = (
        b"\x48\x8d\x15\x00\x01\x00\x00"  # lea rdx, [rip+0x100] -> 0x1107
        + HKCU64  # 0x1007
        + b"\x41\xb9\x19\x00\x02\x00"  # mov r9d, 0x20019 (0x100e)
        + b"\x45\x33\xc0"  # xor r8d, r8d (0x1014)
        + CALL64
    )
    found, _ = find(code, 64)
    assert found == {
        0: (0xFFFFFFFF80000001, 0x1007),
        1: (0x1107, 0x1000),
        2: (0, 0x1014),
        3: (0x20019, 0x100E),
    }


@pytest.mark.parametrize(
    "between",
    [
        b"\xb1\x02",  # mov cl, 2: a subregister
        b"\x48\x91",  # xchg rcx, rax
        b"\x0f\x05",  # syscall: not trusted, forgets everything
        b"\x48\x8b\x08",  # mov rcx, [rax]: not a constant
    ],
)
def test_x64_a_later_write_forgets_the_constant(between):
    found, _ = find(HKCU64 + between + CALL64, 64)
    assert 0 not in found


def test_x64_an_implicit_write_forgets_the_constant():
    found, _ = find(b"\xba\x05\x00\x00\x00" + b"\x99" + CALL64, 64)  # mov edx, 5 ; cdq
    assert found == {}


def test_x64_a_conditional_branch_does_not_end_the_stretch():
    found, _ = find(HKCU64 + b"\x74\x00" + CALL64, 64)  # jz to the next instruction
    assert found == {0: (0xFFFFFFFF80000001, 0x1000)}


def test_x64_another_entry_after_the_setter_forgets_it():
    # 0x1007 is a branch target: a path that enters there brings its own rcx
    code = HKCU64 + b"\x90" + CALL64
    found, _ = find(code, 64, entries=(0x1007,))
    assert found == {}
    # an entry before the setter changes nothing
    found, _ = find(b"\x90" + code, 64, entries=(0x1001,))
    assert found == {0: (0xFFFFFFFF80000001, 0x1001)}


def test_an_entry_at_the_call_itself_leaves_nothing_known():
    code = HKCU64 + CALL64
    found, _ = find(code, 64, entries=(0x1007,))
    assert found == {}


def test_a_stream_that_does_not_land_on_the_call_claims_nothing():
    # decoding from 0x1001 reads 48 c7 c1 ... out of alignment and overshoots
    code = b"\xb8" + HKCU64 + CALL64
    found, _ = find(code, 64, start=0x1000)
    assert found == {}


def test_the_budget_stops_before_claiming_anything():
    found, budget = find(b"\x90" * 20 + HKCU64 + CALL64, 64, budget=5)
    assert found is None and budget.exhausted


# --- x86 --------------------------------------------------------------------------


def push32(value):
    return b"\x68" + struct.pack("<I", value)


REG_OPEN_X86 = (
    b"\x50"  # push eax (&hKey: not a constant)
    + push32(0x20019)  # samDesired
    + b"\x6a\x00"  # ulOptions
    + push32(BASE32 + 0x3000)  # lpSubKey
    + push32(0x80000002)  # hKey
)


def test_x86_pushes_count_back_from_the_call():
    found, _ = find(REG_OPEN_X86 + CALL32, 32)
    assert found == {
        0: (0x80000002, 0x100D),
        1: (BASE32 + 0x3000, 0x1008),
        2: (0, 0x1006),
        3: (0x20019, 0x1001),
    }


@pytest.mark.parametrize(
    "between",
    [
        b"\x83\xc4\x04",  # add esp, 4
        b"\x59",  # pop ecx
        b"\x89\x04\x24",  # mov [esp], eax
        b"\x66\x6a\x05",  # push word 5: moves esp by 2
        b"\x9c",  # pushfd: not trusted
    ],
)
def test_x86_other_stack_changes_forget_every_push(between):
    found, _ = find(REG_OPEN_X86 + between + CALL32, 32)
    assert found == {}


def test_x86_a_push_that_is_not_constant_still_takes_its_place():
    found, _ = find(push32(0x80000001) + b"\x56" + CALL32, 32)  # push esi last
    assert found == {1: (0x80000001, 0x1000)}


def test_x86_register_writes_do_not_touch_pushed_values():
    found, _ = find(push32(0x80000001) + b"\x31\xc0\x8b\x4d\x08" + CALL32, 32)
    assert found == {0: (0x80000001, 0x1000)}


def test_x86_a_32_bit_decoder_is_used():
    # 48 is `dec eax` in 32-bit mode, not a REX prefix
    found, _ = find(b"\x48" + push32(0x80000001) + CALL32, 32)
    assert found == {0: (0x80000001, 0x1001)}


@pytest.mark.parametrize(
    "between",
    [
        b"\x0f\x11\x04\x24",  # movups [esp], xmm0: capstone calls the destination a read
        b"\x66\x0f\xd6\x04\x24",  # movq [esp], xmm0: likewise
        b"\x0f\x29\x04\x24",  # movaps [esp], xmm0
        b"\x87\x04\x24",  # xchg [esp], eax
    ],
)
def test_x86_sse_and_exchange_stores_to_the_stack_forget_every_push(between):
    found, _ = find(REG_OPEN_X86 + between + CALL32, 32)
    assert found == {}


def test_x86_a_push_from_stack_memory_is_an_unknown_argument_not_a_reset():
    # push dword ptr [esp+8] only reads the stack; it still takes its place
    found, _ = find(push32(0x80000001) + b"\xff\x74\x24\x08" + CALL32, 32)
    assert found == {1: (0x80000001, 0x1000)}


# --- x64 stack slots (design section 11) -----------------------------------------

SLOT5_IMM = b"\xc7\x44\x24\x28\x06\x00\x02\x00"  # mov dword ptr [rsp+0x28], 0x20006
SLOT4_ZERO = b"\x83\x64\x24\x20\x00"  # and dword ptr [rsp+0x20], 0
ESI_ONE = b"\xbe\x01\x00\x00\x00"  # mov esi, 1
SLOT4_ESI = b"\x89\x74\x24\x20"  # mov dword ptr [rsp+0x20], esi


def stack(code):
    found, _ = find(code + CALL64, 64)
    return {position: value for position, (value, _) in found.items()}


def constants64(code):
    """The finder's own records for the call that ends `code`."""
    code += CALL64
    region = Region(0x1000, bytearray(code))
    targets = Targets([0x1000], [bytearray(len(code))])
    finder = ArgumentFinder([region], targets, 64, Budget(10_000))
    return finder.constants(0x1000, 0x1000 + len(code) - len(CALL64))


def test_x64_stack_slots_hold_immediates_and_zeros():
    assert stack(SLOT5_IMM + SLOT4_ZERO) == {5: 0x20006, 4: 0}


def test_x64_a_register_stored_to_its_slot_carries_its_constant():
    code = ESI_ONE + SLOT4_ESI
    found = constants64(code)
    assert found[4].setting.value == 1 and found[4].method == "stack-slot-v1"
    assert found[4].source == (0x1000, 5) and found[4].setter == (0x1005, 4)
    # the register may change once it is stored
    assert stack(code + b"\x31\xf6") == {4: 1}  # xor esi, esi afterwards


@pytest.mark.parametrize(
    "between",
    [
        b"\x8b\x30",  # mov esi, [rax]: the register is no longer the constant
        b"\x40\xb6\x02",  # mov sil, 2: a subregister
    ],
)
def test_x64_a_register_changed_before_its_store_is_not_a_constant(between):
    assert stack(ESI_ONE + between + SLOT4_ESI) == {}


@pytest.mark.parametrize(
    ("after", "left"),
    [
        (b"\x48\x83\xec\x08", {}),  # sub rsp, 8: every slot moves
        (b"\x50", {}),  # push rax
        (b"\xc6\x44\x24\x29\x00", {4: 0}),  # mov byte ptr [rsp+0x29], 0: slot 5 only
        (b"\x0f\x11\x44\x24\x20", {}),  # movups [rsp+0x20], xmm0: slots 4 and 5
        (b"\x4c\x89\x33", {}),  # mov [rbx], r14: rbx may point into the frame
        (b"\x89\x45\xf8", {}),  # mov [rbp-8], eax
        (b"\x89\x05\x00\x10\x00\x00", {4: 0, 5: 0x20006}),  # mov [rip+x], eax: the image
        (b"\x48\x8b\x44\x24\x30", {4: 0, 5: 0x20006}),  # mov rax, [rsp+0x30]: a read
        (b"\xf3\xaa", {}),  # rep stosb: not trusted
    ],
)
def test_x64_what_forgets_a_stack_slot(after, left):
    assert stack(SLOT5_IMM + SLOT4_ZERO + after) == left


def test_x64_the_low_half_of_an_address_is_not_stored():
    lea = b"\x48\x8d\x05\x00\x10\x00\x00"  # lea rax, [rip+0x1000]
    assert stack(lea + b"\x89\x44\x24\x38") == {}  # mov dword ptr [rsp+0x38], eax
    found = constants64(lea + b"\x48\x89\x44\x24\x38")  # the whole qword
    assert found[7].setting.kind == "address" and found[7].setting.value == 0x2007
