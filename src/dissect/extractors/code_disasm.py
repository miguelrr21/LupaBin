"""Recursive-descent walk over a sample's executable sections (design section 3.1).

capstone only decodes: it turns bytes into an instruction's length, mnemonic and
operand text. The walk follows constant branch and call targets from known entry
points and never keeps registers, memory or a notion of which branch is taken, so
nothing is executed or emulated. Indirect jumps are not resolved.
"""

import bisect
from dataclasses import dataclass, field

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

# Instructions after which execution does not fall through to the next one.
_STOP = frozenset({"ret", "retf", "iret", "iretd", "iretq", "int3", "hlt", "ud2", "jmp"})
_CONDITIONAL = frozenset({"loop", "loope", "loopne", "jecxz", "jrcxz", "jcxz"})
# capstone decodes at most this many instructions per request; 15 bytes is the
# longest x86 instruction, so a window of _BATCH * 15 bytes never truncates a batch.
_BATCH = 32


@dataclass(frozen=True)
class Region:
    """An executable section's bytes on disk, addressed by RVA."""

    rva: int
    data: bytearray

    @property
    def end(self) -> int:
        return self.rva + len(self.data)


@dataclass(frozen=True)
class Site:
    """An instruction the call classifier examines, with the one right before it."""

    rva: int
    size: int
    previous: tuple[int, int] | None  # (rva, size) of the preceding instruction


@dataclass
class Walk:
    instructions: int = 0
    limit: bool = False
    sites: list[Site] = field(default_factory=list)


def _target(operand: str) -> int | None:
    if operand.startswith("0x"):
        try:
            return int(operand, 16)
        except ValueError:
            return None
    return int(operand) if operand.isdecimal() else None


def walk(regions: list[Region], entries: list[int], bits: int, budget: int) -> Walk:
    """Decode every instruction reachable from `entries` without resolving indirection.

    Calls are recorded as sites: those through memory or a register, and relative
    calls (their target may be a thunk). Stops after `budget` instructions.
    """
    engine = Cs(CS_ARCH_X86, CS_MODE_32 if bits == 32 else CS_MODE_64)
    regions = sorted(regions, key=lambda region: region.rva)
    starts = [region.rva for region in regions]
    decoded = [bytearray(len(region.data)) for region in regions]
    views = [memoryview(region.data) for region in regions]
    result = Walk()
    pending = list(reversed(entries))
    while pending:
        address = pending.pop()
        index = bisect.bisect_right(starts, address) - 1
        if index < 0 or address >= regions[index].end:
            continue
        region, marks, view = regions[index], decoded[index], views[index]
        position = address - region.rva
        if marks[position]:
            continue
        previous: tuple[int, int] | None = None
        running = True
        while running and position < len(region.data):
            window = view[position : position + _BATCH * 15]
            count = 0
            for rva, size, mnemonic, operand in engine.disasm_lite(
                window, region.rva + position, _BATCH
            ):
                count += 1
                offset = rva - region.rva
                if marks[offset]:
                    running = False  # the rest of this run was already decoded
                    break
                if result.instructions >= budget:
                    result.limit = True
                    return result
                marks[offset] = 1
                result.instructions += 1
                position = offset + size
                if mnemonic == "call":
                    target = _target(operand)
                    if target is not None:
                        pending.append(target)
                    result.sites.append(Site(rva, size, previous))
                elif mnemonic == "jmp" or mnemonic.startswith("j") or mnemonic in _CONDITIONAL:
                    target = _target(operand)
                    if target is not None:
                        pending.append(target)
                if mnemonic in _STOP:
                    running = False
                    break
                previous = (rva, size)
            else:
                if count < _BATCH:
                    running = False  # an undecodable byte or the end of the section
    return result
