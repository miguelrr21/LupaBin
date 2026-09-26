"""Recursive-descent walk over a sample's executable sections.

capstone only decodes: it turns bytes into an instruction's identity, length and
operand text. The walk follows constant branch and call targets from known entry
points and never keeps registers, memory or a notion of which branch is taken, so
nothing is executed or emulated. An indirect jump goes to a visitor, which may return
the targets it can prove from the bytes (a bounded jump table); nothing else about it
is guessed.

The walk calls capstone's `cs_disasm` itself (pinned capstone 5.0.9) and reads only
each instruction's id and size, plus the operand text of branches: the public
`disasm_lite` converts every mnemonic and operand to text, which doubled the cost of
an adversarial 20 MiB input.
"""

import bisect
import ctypes
import struct
import time
from array import array
from collections.abc import Callable
from dataclasses import dataclass, field

import capstone
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from capstone import x86_const as x86

# Instruction ids by control-flow role.
_CALL, _JUMP, _BRANCH, _END = 1, 2, 3, 4
_FLOW: dict[int, int] = {x86.X86_INS_CALL: _CALL, x86.X86_INS_JMP: _JUMP}
_FLOW |= dict.fromkeys(
    (
        getattr(x86, f"X86_INS_{name}")
        for name in (
            "JA JAE JB JBE JCXZ JE JECXZ JG JGE JL JLE JNE JNO JNP JNS JO JP JRCXZ JS"
            " LOOP LOOPE LOOPNE"
        ).split()
    ),
    _BRANCH,
)
_FLOW |= dict.fromkeys(
    (
        getattr(x86, f"X86_INS_{name}")
        for name in "RET RETF RETFQ IRET IRETD IRETQ INT3 HLT UD0 UD1 UD2 LJMP".split()
    ),
    _END,
)
# capstone decodes at most this many instructions per request; 15 bytes is the
# longest x86 instruction, so a window of _BATCH * 15 bytes never truncates a batch.
_BATCH = 32
_LIMIT = 0xFFFFFFFF
_CLOCK_EVERY = 4096

# visit(region bytes, offset of the call, its RVA, its size, size of the instruction
# right before it in the same run or 0, RVA where the call's linear stretch starts)
Visitor = Callable[[bytearray, int, int, int, int, int], None]
# jumped(region bytes, offset of a jmp without a constant target, its RVA, its size,
# size of the instruction right before it in the same run or 0, RVA where its linear
# stretch starts, offsets of up to _HISTORY instructions before it in the same run,
# oldest first) -> targets to walk
JumpVisitor = Callable[[bytearray, int, int, int, int, int, list[int]], list[int]]
_HISTORY = 12
_RING = 16  # a power of two above _HISTORY


@dataclass(frozen=True)
class Region:
    """An executable section's bytes on disk, addressed by RVA.

    `fields`, when the image has base relocations, holds 1 on every byte of a relocated
    field except its first: a real instruction never starts inside such a field and
    never ends inside one, so a decode that does has left the code (the bytes after a
    call that never returns, a jump table) and its run stops there.
    """

    rva: int
    data: bytearray
    fields: bytearray | None = None

    @property
    def end(self) -> int:
        return self.rva + len(self.data)


@dataclass(frozen=True)
class Targets:
    """Where another path can enter the walked code, one byte per byte of each region.

    Marked: every entry point, every constant branch or call target, including those
    still pending when a budget stopped the walk, and every point where a run reached
    code another run had already decoded. Code the walk never reached, or reaches only
    through indirection, can enter elsewhere: that is a limit of the walk.
    """

    starts: list[int]
    marks: list[bytearray]

    def last(self, start: int, end: int) -> int | None:
        """The last marked RVA in (start, end], within the region holding `start`."""
        index = bisect.bisect_right(self.starts, start) - 1
        if index < 0:
            return None
        base, marks = self.starts[index], self.marks[index]
        found = marks.rfind(1, max(0, start - base + 1), max(0, end - base + 1))
        return None if found < 0 else base + found


@dataclass
class Walk:
    instructions: int = 0
    calls: int = 0
    limit: bool = False  # the instruction budget stopped the walk
    call_limit: bool = False  # the call budget stopped the walk
    time_limit: bool = False  # the deadline stopped the walk
    targets: Targets = field(default_factory=lambda: Targets([], []))
    # one byte per byte of each region: 1 where the walk decoded an instruction start
    decoded: list[bytearray] = field(default_factory=list)


def _target(operand: bytes) -> int | None:
    """A constant target as capstone prints it (0x...); memory or register operands
    contain spaces, brackets or letters beyond hex and are not followed."""
    if operand.startswith(b"0x") and operand[2:].isalnum():
        try:
            return int(operand, 16)
        except ValueError:
            return None
    return None


# capstone's cs_insn layout (5.0.9): a batch is copied out once and only the id and
# size are unpacked per instruction; ctypes field access cost more than decoding.
_RECORD = ctypes.sizeof(capstone._cs_insn)
_HEAD = struct.Struct("<I12xH")
_OPERAND = capstone._cs_insn.op_str.offset


def walk(
    regions: list[Region],
    entries: list[int],
    bits: int,
    budget: int,
    visit: Visitor,
    call_budget: int,
    deadline: float = float("inf"),
    jumped: JumpVisitor | None = None,
    avoid: frozenset[int] = frozenset(),
) -> Walk:
    """Decode every instruction reachable from `entries`.

    Every `call` is passed to `visit` with the start of its linear stretch: the start
    of the run, or the instruction after the run's previous call, since a call leaves
    no argument register or stack slot known. Its target, when constant, is walked too.
    Stops after `budget` instructions or `call_budget` calls, whichever comes first:
    classifying a call costs several times more than decoding an instruction.
    Also stops when `time.monotonic()` passes `deadline`, checked every
    _CLOCK_EVERY instructions. A `jmp` without a constant target goes to `jumped`, and
    the targets it returns are walked like constant ones. Constant targets in `avoid`
    are not walked (the startup's walk stops at `main`).
    """
    engine = Cs(CS_ARCH_X86, CS_MODE_32 if bits == 32 else CS_MODE_64)
    disasm = capstone._cs.cs_disasm
    release = capstone._cs.cs_free
    head = _HEAD.unpack_from
    flow = _FLOW.get
    regions = sorted(regions, key=lambda region: region.rva)
    starts = [region.rva for region in regions]
    ends = [region.end for region in regions]
    decoded = [bytearray(len(region.data)) for region in regions]
    entered = [bytearray(len(region.data)) for region in regions]
    bases = [
        ctypes.addressof((ctypes.c_char * len(region.data)).from_buffer(region.data))
        if region.data
        else 0
        for region in regions
    ]
    result = Walk(targets=Targets(starts, entered), decoded=decoded)
    instructions = calls = 0
    recent = array("I", bytes(4 * _RING))  # offsets of the last instructions decoded
    pending = array("I", reversed([entry for entry in entries if 0 <= entry < _LIMIT]))
    insn = ctypes.POINTER(capstone._cs_insn)()
    pointer = ctypes.POINTER(ctypes.c_char)
    while pending:
        address = pending.pop()
        index = bisect.bisect_right(starts, address) - 1
        if index < 0 or address >= ends[index]:
            continue
        region, marks, base = regions[index], decoded[index], bases[index]
        joins = entered[index]
        rva, data, length = region.rva, region.data, len(region.data)
        fields = region.fields
        position = address - rva
        joins[position] = 1
        if marks[position]:
            continue
        previous = 0
        stretch = address
        first = instructions  # the ordinal of this run's first instruction
        running = True
        while running and position < length:
            count = disasm(
                engine.csh,
                ctypes.cast(base + position, pointer),
                min(_BATCH * 15, length - position),
                rva + position,
                _BATCH,
                ctypes.byref(insn),
            )
            if not count:
                break  # an undecodable byte
            try:
                batch = ctypes.string_at(insn, count * _RECORD)
            finally:
                release(insn, count)
            for record in range(0, count * _RECORD, _RECORD):
                if marks[position]:
                    joins[position] = 1  # this run enters code decoded by another
                    running = False
                    break
                if instructions >= budget:
                    result.instructions, result.calls, result.limit = instructions, calls, True
                    return _drained(result, pending, entered)
                if not instructions % _CLOCK_EVERY and time.monotonic() > deadline:
                    result.instructions, result.calls = instructions, calls
                    result.time_limit = True
                    return _drained(result, pending, entered)
                ident, size = head(batch, record)
                if fields is not None and (
                    fields[position] or (position + size < length and fields[position + size])
                ):
                    running = False  # it cuts a relocated field: these bytes are not code
                    break
                marks[position] = 1
                recent[instructions & (_RING - 1)] = position
                instructions += 1
                role = flow(ident)
                if role is not None:
                    if role != _END:
                        start = record + _OPERAND
                        target = _target(batch[start : batch.index(b"\0", start)])
                        # a branch or call to the next instruction adds nothing: this run
                        # decodes it anyway. A jmp there ends this run, so it is walked.
                        if target is not None and target < _LIMIT:
                            if target in avoid:
                                pass
                            elif target != rva + position + size or role == _JUMP:
                                pending.append(target)
                        elif role == _JUMP and jumped is not None:
                            earlier = range(
                                max(first, instructions - 1 - _HISTORY), instructions - 1
                            )
                            history = [recent[i & (_RING - 1)] for i in earlier]
                            for found in jumped(
                                data, position, rva + position, size, previous, stretch, history
                            ):
                                if 0 <= found < _LIMIT:
                                    pending.append(found)
                    if role == _CALL:
                        if calls >= call_budget:
                            result.instructions, result.calls = instructions, calls
                            result.call_limit = True
                            return _drained(result, pending, entered)
                        calls += 1
                        visit(data, position, rva + position, size, previous, stretch)
                        stretch = rva + position + size
                    elif role != _BRANCH:
                        running = False
                        break
                previous = size
                position += size
            else:
                if count < _BATCH:
                    running = False  # an undecodable byte or the end of the section
    result.instructions, result.calls = instructions, calls
    return result


def _drained(result: Walk, pending: array[int], entered: list[bytearray]) -> Walk:
    """Marks the targets a budget left pending: they are entries all the same."""
    starts = result.targets.starts
    for address in pending:
        index = bisect.bisect_right(starts, address) - 1
        if index >= 0 and address - starts[index] < len(entered[index]):
            entered[index][address - starts[index]] = 1
    return result
