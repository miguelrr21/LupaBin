"""Constant arguments of calls to catalog functions.

Only the end of the linear stretch that leads to the call is decoded, in capstone's
detail mode: from the stretch start the walk reported, or from the last point after
it where another path can enter (code_disasm.Targets), whichever is later. Nothing
is executed: an argument is known only when an instruction of a canonical form
(evidence/argument_forms.py) sets it and no later instruction can change it.

- x64 (rcx, rdx, r8, r9): any write of the register or of a subregister, explicit
  or implicit, forgets it. From the fifth argument on, the stack slot [rsp + 8*i]
  holds it: a canonical store of an immediate, or of a register
  that a canonical form set earlier, fills the slot; a write of rsp, a store that
  overlaps it, or a memory write through any other base forgets it.
- x86 (stack): the i-th 32-bit `push` counting back from the call is argument i. Any
  other write of esp, or any write to memory addressed from esp, forgets every push.

capstone's list of written registers is incomplete for some instructions (it omits
the rcx that `syscall` overwrites, for one), so it is trusted only for the reviewed
instructions in _TRUSTED; any other instruction forgets everything tracked.

If decoding from that point does not land exactly on the call, the call is not on
the same instruction stream and nothing is claimed.
"""

import time
from dataclasses import dataclass

import capstone
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs, CsError
from capstone import x86_const as x86

from lupabin.evidence import argument_forms
from lupabin.evidence.argument_forms import Setting
from lupabin.extractors.code_disasm import Region, Targets

# Instructions whose register writes capstone 5.0.9 reports completely (checked by
# tests/test_code_args.py). Conditional jumps are here because the stretch runs on
# through them: their target, marked as an entry, is where another path comes in.
_TRUSTED = frozenset(
    getattr(x86, f"X86_INS_{name}")
    for name in (
        "MOV MOVABS MOVZX MOVSX MOVSXD LEA XOR AND OR ADD SUB ADC SBB INC DEC NEG NOT"
        " TEST CMP SHL SHR SAR ROL ROR BT IMUL PUSH POP NOP XCHG CDQ CQO"
        " SETA SETAE SETB SETBE SETE SETG SETGE SETL SETLE SETNE SETNO SETNP SETNS"
        " SETO SETP SETS CMOVA CMOVAE CMOVB CMOVBE CMOVE CMOVG CMOVGE CMOVL CMOVLE"
        " CMOVNE CMOVNO CMOVNP CMOVNS CMOVO CMOVP CMOVS"
        " MOVUPS MOVAPS MOVDQU MOVDQA MOVQ MOVD XORPS PXOR"
        " JA JAE JB JBE JE JG JGE JL JLE JNE JNO JNP JNS JO JP JS"
    ).split()
)
# capstone register id -> x64 general register number (0 rax ... 15 r15), for the
# register and every subregister
_NAMES = (
    ("RAX", "EAX", "AX", "AL", "AH"),
    ("RCX", "ECX", "CX", "CL", "CH"),
    ("RDX", "EDX", "DX", "DL", "DH"),
    ("RBX", "EBX", "BX", "BL", "BH"),
    ("RSP", "ESP", "SP", "SPL"),
    ("RBP", "EBP", "BP", "BPL"),
    ("RSI", "ESI", "SI", "SIL"),
    ("RDI", "EDI", "DI", "DIL"),
    *((f"R{n}", f"R{n}D", f"R{n}W", f"R{n}B") for n in range(8, 16)),
)
_FAMILY = {
    getattr(x86, f"X86_REG_{name}"): number for number, names in enumerate(_NAMES) for name in names
}
_ARGUMENTS = {1: 0, 2: 1, 8: 2, 9: 3}  # rcx, rdx, r8, r9 -> argument index
_RSP = 4
_STACK = frozenset((x86.X86_REG_ESP, x86.X86_REG_SP))
_CLOCK_EVERY = 256


@dataclass(frozen=True)
class Found:
    """A constant that an instruction sets for argument `position`."""

    position: int
    setting: Setting
    setter: tuple[int, int]  # (rva, size): for a stack slot, the store
    # a stack slot: bytes the store wrote, and the instruction
    # that set the register it copies, if any
    width: int = 8
    source: tuple[int, int] | None = None
    method: str = "block-constant-v1"


@dataclass
class Budget:
    instructions: int  # detail-mode instructions allowed across all calls
    deadline: float = float("inf")
    used: int = 0
    exhausted: bool = False
    timed_out: bool = False


class ArgumentFinder:
    def __init__(self, regions: list[Region], targets: Targets, bits: int, budget: Budget):
        self.regions = sorted(regions, key=lambda region: region.rva)
        self.targets = targets
        self.bits = bits
        self.budget = budget
        self.engine = Cs(CS_ARCH_X86, CS_MODE_32 if bits == 32 else CS_MODE_64)
        self.engine.detail = True

    def constants(self, start: int, call: int) -> dict[int, Found] | None:
        """Argument position -> constant for the call at `call`, whose linear stretch
        starts at `start`. None when the budget or the deadline ran out first."""
        region = next((r for r in self.regions if r.rva <= start and call < r.end), None)
        if region is None or start > call:
            return {}
        entry = self.targets.last(start, call)
        if entry == call:
            return {}  # another path reaches the call itself
        if entry is not None:
            start = entry
        window = bytes(region.data[start - region.rva : call - region.rva])
        registers: dict[int, Found] = {}  # x64 general register number -> constant
        slots: dict[int, Found] = {}  # x64 argument position (4..15) -> constant
        pushes: list[Found | None] = []
        budget, address = self.budget, start
        for insn in self.engine.disasm(window, start):
            if budget.used >= budget.instructions:
                budget.exhausted = True
                return None
            if not budget.used % _CLOCK_EVERY and time.monotonic() > budget.deadline:
                budget.timed_out = True
                return None
            budget.used += 1
            if insn.address != address:
                return {}
            address += insn.size
            if self.bits == 64:
                _track_registers(insn, registers, slots)
            else:
                _track_pushes(insn, pushes)
        if address != call:
            return {}  # undecodable bytes, or the call is on another instruction stream
        if self.bits == 32:
            return {
                position: Found(position, pushed.setting, pushed.setter)
                for position, pushed in enumerate(reversed(pushes))
                if pushed is not None
            }
        tracked = {
            _ARGUMENTS[register]: Found(
                _ARGUMENTS[register],
                found.setting._replace(target=_ARGUMENTS[register]),
                found.setter,
            )
            for register, found in registers.items()
            if register in _ARGUMENTS
        }
        return tracked | slots


def _track_registers(
    insn: capstone.CsInsn, registers: dict[int, Found], slots: dict[int, Found]
) -> None:
    written = _written(insn)
    if written is None:
        registers.clear()
        slots.clear()
        return
    for register in written:
        number = _FAMILY.get(register)
        registers.pop(-1 if number is None else number, None)
        if number == _RSP:
            slots.clear()  # every slot moves with rsp
    for operand in _written_memory(insn):
        memory = operand.mem
        if memory.base == x86.X86_REG_RIP and memory.index == x86.X86_REG_INVALID:
            continue  # the image, not the stack
        if memory.base == x86.X86_REG_RSP and memory.index == x86.X86_REG_INVALID:
            low, high = memory.disp, memory.disp + operand.size
            for position in [p for p in slots if low < 8 * p + 8 and 8 * p < high]:
                del slots[position]
        else:
            slots.clear()  # another register may point into the frame
    raw, where = bytes(insn.bytes), (insn.address, insn.size)
    found = argument_forms.x64_register(raw, insn.address)
    if found is not None:
        registers[found[0]] = Found(found[0], found[1], where)
    store = argument_forms.x64_stack_store(raw)
    if store is None:
        return
    source: Found | None = None
    if store.value is not None:
        setting = Setting(store.position, "immediate", store.value)
    else:
        source = None if store.register is None else registers.get(store.register)
        if source is None:
            return  # the slot holds a value that is not constant
        kind, value = source.setting.kind, source.setting.value
        if store.width == 4:
            if kind == "address":
                return  # the low half of an address is not the address
            value &= 0xFFFFFFFF
        setting = Setting(store.position, kind, value)
    slots[store.position] = Found(
        store.position,
        setting,
        where,
        store.width,
        None if source is None else source.setter,
        "stack-slot-v1",
    )


def _track_pushes(insn: capstone.CsInsn, pushes: list[Found | None]) -> None:
    written = _written(insn)
    if written is None or _writes_stack_memory(insn):
        pushes.clear()
    elif insn.id == x86.X86_INS_PUSH and insn.operands and insn.operands[0].size == 4:
        setting = argument_forms.x86_push(bytes(insn.bytes))
        # numbered from the call once the stretch ends; a non-constant push still
        # takes its place
        pushes.append(None if setting is None else Found(-1, setting, (insn.address, insn.size)))
    elif _STACK & written:
        pushes.clear()


def _written(insn: capstone.CsInsn) -> set[int] | None:
    """Registers the instruction writes, or None when capstone is not trusted for it."""
    if insn.id not in _TRUSTED:
        return None
    try:
        _, written = insn.regs_access()
    except CsError:
        return None
    return set(written)


def _written_memory(insn: capstone.CsInsn) -> list[capstone.x86.X86Op]:
    """Memory operands the instruction may write, by x86 semantics rather than capstone's
    access flags, which call the destination of `movups [mem], xmm` or `movq [mem], xmm`
    a read. In Intel order the destination is the first operand; `xchg` writes both.
    A `cmp` or `test` of memory counts too: a lost argument, never a wrong one. `push`
    only reads its memory operand; its own stack write is the push rule."""
    operands = insn.operands
    if insn.id == x86.X86_INS_XCHG:
        return [operand for operand in operands if operand.type == x86.X86_OP_MEM]
    if insn.id != x86.X86_INS_PUSH and operands and operands[0].type == x86.X86_OP_MEM:
        return [operands[0]]
    return []


def _writes_stack_memory(insn: capstone.CsInsn) -> bool:
    return any(operand.mem.base in _STACK for operand in _written_memory(insn))
