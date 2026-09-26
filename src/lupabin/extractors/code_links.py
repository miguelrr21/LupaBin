"""A handle that one call writes into a local variable and a later call reads from it.

`RegOpenKeyEx(..., &key)` stores the key it opens through its last argument, the
address of a local variable; `RegSetValueEx(key, ...)` later passes that variable's
value. When both name the same frame slot (local_forms.py) the worker links them, but
only if the path between them keeps the slot:

- the reader instruction is reached from the writer call by falling through, with no
  other entry in between (Targets): every path to the reader comes through the writer;
- no instruction in between writes the frame register, stores into the slot, takes
  the slot's address again or transfers control unconditionally; a `call` is allowed
  (x86 callees restore `ebp`; in x64 `rsp` is the same after the call returns);
- every instruction in between is one whose writes capstone reports completely
  (code_args._TRUSTED), or a call.

Nothing is executed. What cannot be proved without running the code is that the
writer call succeeded: that stays in the statement's limit.
"""

from dataclasses import dataclass

import capstone
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from capstone import x86_const as x86

from lupabin.evidence import argument_forms, local_forms
from lupabin.evidence.local_forms import MAX_DISTANCE, Slot
from lupabin.extractors.code_args import (
    _FAMILY,
    _STACK,
    Budget,
    _writes_stack_memory,
    _written,
    _written_memory,
)
from lupabin.extractors.code_disasm import Region, Targets

_ARGUMENT_REGISTERS = {1: 0, 2: 1, 8: 2, 9: 3}  # rcx, rdx, r8, r9 -> position
_FRAME_REGISTER = {"ebp": 5, "rbp": 5, "rsp": 4}
_ENDS = frozenset(
    getattr(x86, f"X86_INS_{name}")
    for name in "JMP RET RETF INT3 HLT UD2 LJMP IRET IRETD IRETQ".split()
)


@dataclass(frozen=True)
class Passed:
    """How a call receives a slot: its address (with the lea that took it and, when
    it went through a push or a stack store, that instruction) or its value."""

    kind: str  # "address" or "value"
    slot: Slot
    instruction: tuple[int, int]  # (rva, size): the push, the store or the load
    source: tuple[int, int] | None = None  # the lea, when `instruction` passes a register


class SlotFinder:
    def __init__(self, regions: list[Region], targets: Targets, bits: int, budget: Budget):
        self.regions = sorted(regions, key=lambda region: region.rva)
        self.targets = targets
        self.bits = bits
        self.budget = budget
        self.engine = Cs(CS_ARCH_X86, CS_MODE_32 if bits == 32 else CS_MODE_64)
        self.engine.detail = True

    def _region(self, start: int, end: int) -> Region | None:
        return next((r for r in self.regions if r.rva <= start and end <= r.end), None)

    def _decode(self, start: int, end: int) -> list[capstone.CsInsn] | None:
        """The instructions of [start, end) on one stream, or None if they do not land
        on `end`, or the budget ran out."""
        region = self._region(start, end)
        if region is None or start > end:
            return None
        found, address = [], start
        for insn in self.engine.disasm(
            bytes(region.data[start - region.rva : end - region.rva]), start
        ):
            if self.budget.used >= self.budget.instructions:
                self.budget.exhausted = True
                return None
            self.budget.used += 1
            if insn.address != address:
                return None
            address += insn.size
            found.append(insn)
        return found if address == end else None

    def passed(self, start: int, call: int) -> dict[int, Passed]:
        """Argument position -> slot passed to the call at `call`, whose stretch starts
        at `start` (or at the last entry after it)."""
        entry = self.targets.last(start, call)
        if entry == call:
            return {}
        insns = self._decode(start if entry is None else entry, call)
        if insns is None:
            return {}
        return self._x86(insns) if self.bits == 32 else self._x64(insns)

    def _x86(self, insns: list[capstone.CsInsn]) -> dict[int, Passed]:
        registers: dict[int, tuple[Slot, tuple[int, int]]] = {}  # register -> address
        pushes: list[Passed | None] = []
        for insn in insns:
            raw, where = bytes(insn.bytes), (insn.address, insn.size)
            written = _written(insn)
            if written is None or _writes_stack_memory(insn):
                registers.clear()
                pushes.clear()
                continue
            if insn.id == x86.X86_INS_PUSH and insn.operands and insn.operands[0].size == 4:
                value = local_forms.x86_push_value(raw)
                register = local_forms.x86_push_register(raw)
                if value is not None:
                    pushes.append(Passed("value", value.slot, where))
                elif register is not None and register in registers:
                    slot, taken = registers[register]
                    pushes.append(Passed("address", slot, where, taken))
                else:
                    pushes.append(None)
                continue
            if _STACK & written:
                pushes.clear()
            numbers = {_FAMILY.get(register, -1) for register in written}
            if 5 in numbers:  # ebp: every slot named so far moves with it
                registers.clear()
                pushes = [None for _ in pushes]  # their slots were named with the old ebp
            for number in numbers:
                registers.pop(number, None)
            lea = local_forms.x86_lea(raw)
            if lea is not None and lea.register is not None:
                registers[lea.register] = (lea.slot, where)
        return {position: p for position, p in enumerate(reversed(pushes)) if p is not None}

    def _x64(self, insns: list[capstone.CsInsn]) -> dict[int, Passed]:
        registers: dict[int, Passed] = {}  # register -> address or value of a slot
        slots: dict[int, Passed] = {}  # stack argument position -> address of a slot
        for insn in insns:
            raw, where = bytes(insn.bytes), (insn.address, insn.size)
            written = _written(insn)
            if written is None:
                registers.clear()
                slots.clear()
                continue
            numbers = {_FAMILY.get(register, -1) for register in written}
            for number in numbers:
                registers.pop(number, None)
            for frame, number in (("rsp", 4), ("rbp", 5)):
                if number in numbers:
                    registers = {r: p for r, p in registers.items() if p.slot.frame != frame}
                    if frame == "rsp":
                        slots.clear()
            for operand in _written_memory(insn):
                memory = operand.mem
                if memory.base == x86.X86_REG_RSP and memory.index == x86.X86_REG_INVALID:
                    low, high = memory.disp, memory.disp + operand.size
                    for position in [p for p in slots if low < 8 * p + 8 and 8 * p < high]:
                        del slots[position]
                elif memory.base != x86.X86_REG_RIP:
                    slots.clear()
            lea, load = local_forms.x64_lea(raw), local_forms.x64_load(raw)
            if lea is not None and lea.register is not None:
                registers[lea.register] = Passed("address", lea.slot, where, where)
            elif load is not None and load.register is not None:
                registers[load.register] = Passed("value", load.slot, where)
            store = _stack_store(raw)
            if store is not None:
                position, register = store
                held = registers.get(register)
                if held is not None and held.kind == "address":
                    slots[position] = Passed("address", held.slot, where, held.source)
        passed = {
            _ARGUMENT_REGISTERS[register]: held
            for register, held in registers.items()
            if register in _ARGUMENT_REGISTERS
        }
        return passed | slots

    def keeps(self, after_writer: int, reader: int, slot: Slot) -> bool:
        """Whether every path to `reader` comes from `after_writer` by falling through
        and nothing in between can change `slot`."""
        if not 0 <= reader - after_writer <= MAX_DISTANCE:
            return False
        if not local_forms.keeps_across_calls(slot):
            return False
        if self.targets.last(after_writer - 1, reader) is not None:
            return False  # another path enters in between
        insns = self._decode(after_writer, reader)
        if insns is None:
            return False
        frame = _FRAME_REGISTER[slot.frame]
        for insn in insns:
            if insn.id in _ENDS:
                return False
            if insn.id == x86.X86_INS_CALL:
                continue
            written = _written(insn)
            if written is None:
                return False
            if frame in {_FAMILY.get(register, -1) for register in written}:
                return False
            raw = bytes(insn.bytes)
            named = local_forms.x86_lea(raw) if self.bits == 32 else local_forms.x64_lea(raw)
            if named is not None and named.slot == slot:
                return False  # its address is taken again
            for operand in _written_memory(insn):
                if _overlaps(operand, slot, self.bits):
                    return False
        return True


def _overlaps(operand: capstone.x86.X86Op, slot: Slot, bits: int) -> bool:
    """A memory write that may touch the slot.

    Through the slot's own frame register: when the displacements overlap (any index
    makes it unknown). Through the other stack register (`esp` for an `ebp` slot;
    `rbp` or `rsp` in x64), both point into the same frame at an offset the code does
    not state, so the write always counts as touching it. (The x64 parameter area at
    the bottom of the frame is only as large as the largest call needs, so a store near
    [rsp] can be a local variable: no exception is made for it.) Writes through other
    registers could only reach the slot through an address taken again, which `keeps`
    rejects."""
    memory = operand.mem
    frames = {"ebp": x86.X86_REG_EBP, "rbp": x86.X86_REG_RBP, "rsp": x86.X86_REG_RSP}
    frame = frames[slot.frame]
    others = {x86.X86_REG_ESP} if bits == 32 else {x86.X86_REG_RSP, x86.X86_REG_RBP} - {frame}
    if memory.base in others:
        return True
    if memory.base != frame:
        return False
    if memory.index != x86.X86_REG_INVALID:
        return True
    width = 4 if bits == 32 else 8
    low, high = int(memory.disp), int(memory.disp) + int(operand.size)
    return low < slot.displacement + width and slot.displacement < high


def _stack_store(raw: bytes) -> tuple[int, int] | None:
    """mov qword ptr [rsp + 8*position], r64 (position 4..15): (position, register)."""
    store = argument_forms.x64_stack_store(raw)
    if store is None or store.register is None or store.width != 8:
        return None
    return store.position, store.register
