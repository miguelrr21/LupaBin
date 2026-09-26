"""The call through which the compiler's startup enters `main` (evidence/main_forms.py).

A call to `__getmainargs` or `__wgetmainargs` (msvcrt.dll) passes the addresses of three
variables; the startup then calls `main` with the values of those three variables. Found
when exactly one direct call in the walked code receives, as its first three arguments,
loads of exactly those addresses, each set by a canonical form in the call's linear
stretch and not changed before the call (the same rule as the constant arguments,
code_args.py). Two candidates, or none, and nothing is claimed.
"""

import time
from array import array
from dataclasses import dataclass

import capstone
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from capstone import x86_const as x86

from lupabin.evidence import main_forms
from lupabin.extractors.code_args import _FAMILY, Budget, _written, _written_memory
from lupabin.extractors.code_calls import Call
from lupabin.extractors.code_disasm import Region, Targets

_X64_POSITIONS = {1: 0, 2: 1, 8: 2}  # rcx, rdx, r8
_STACK = frozenset((x86.X86_REG_ESP, x86.X86_REG_SP))
# the opcode and ModRM of each x64 load form: mov ecx/rcx, mov edx/rdx, mov r8d/r8
_X64_OPCODES = (b"\x8b\x0d", b"\x8b\x15", b"\x8b\x05")
_CLOCK_EVERY = 4096


@dataclass(frozen=True)
class MainCall:
    rva: int  # the direct call
    size: int
    target: int  # main
    anchor: Call  # the call to __getmainargs
    setters: tuple[tuple[int, int], ...]  # (rva, size) passing each address, argc first
    loads: tuple[tuple[int, int], ...]  # (rva, size) loading each value, argc first


class MainFinder:
    def __init__(self, regions: list[Region], bits: int, image_base: int):
        self.regions = sorted(regions, key=lambda region: region.rva)
        self.bits = bits
        self.image_base = image_base
        self.engine = Cs(CS_ARCH_X86, CS_MODE_32 if bits == 32 else CS_MODE_64)
        self.engine.detail = True
        # every direct call the walk decoded: its RVA and the start of its linear stretch
        self.sites = array("I")
        self.stretches = array("I")

    def visit(
        self, data: bytearray, offset: int, rva: int, size: int, previous: int, start: int
    ) -> None:
        if size == 5 and data[offset] == 0xE8:
            self.sites.append(rva)
            self.stretches.append(start)

    def find(
        self,
        anchors: list[tuple[Call, dict[int, tuple[int, tuple[int, int]]]]],
        targets: Targets,
        budget: Budget,
    ) -> MainCall | None:
        """`anchors`: each call to __getmainargs with the address its first three
        arguments pass, by position: (RVA, setter span). The one direct call that loads
        exactly those three addresses, or None (also when the budget ran out)."""
        found: list[MainCall] = []
        for anchor, passed in anchors:
            addresses = tuple(passed[position][0] for position in range(main_forms.ARGUMENTS))
            if len(set(addresses)) != main_forms.ARGUMENTS:
                continue
            for index, (site, start) in enumerate(zip(self.sites, self.stretches, strict=True)):
                if not index % _CLOCK_EVERY and time.monotonic() > budget.deadline:
                    budget.timed_out = True
                    return None
                if not self._mentions(start, site, addresses):
                    continue
                loads = self._loads(start, site, targets, budget)
                if loads is None:
                    return None  # the budget or the deadline ran out
                if tuple(loads.get(p, (None,))[0] for p in range(3)) != addresses:
                    continue
                target = main_forms.direct_call(self._read(site, 5) or b"", site)
                if target is None or self._region(target) is None:
                    continue
                found.append(
                    MainCall(
                        site,
                        5,
                        target,
                        anchor,
                        tuple(passed[p][1] for p in range(3)),
                        tuple(loads[p][1] for p in range(3)),
                    )
                )
        sites = {main.rva for main in found}
        return found[0] if len(sites) == 1 else None

    def _region(self, rva: int) -> Region | None:
        for region in self.regions:
            if region.rva <= rva < region.end:
                return region
        return None

    def _read(self, rva: int, size: int) -> bytes | None:
        region = self._region(rva)
        if region is None or rva + size > region.end:
            return None
        return bytes(region.data[rva - region.rva : rva - region.rva + size])

    def _mentions(self, start: int, call: int, addresses: tuple[int, ...]) -> bool:
        """A byte-level filter before decoding: every address is referenced somewhere
        in the stretch (x86: its absolute value; x64: a RIP-relative displacement)."""
        window = self._read(start, call - start) if start <= call else None
        if not window:
            return False
        if self.bits == 64 and not all(opcode in window for opcode in _X64_OPCODES):
            return False
        if self.bits == 32:
            return all(
                (address + self.image_base).to_bytes(4, "little") in window for address in addresses
            )
        wanted = set(addresses)
        seen: set[int] = set()
        for index in range(len(window) - 3):
            # disp32 ending at `index + 4`; an instruction ends there or later
            disp = int.from_bytes(window[index : index + 4], "little", signed=True)
            end = start + index + 4
            if end + disp in wanted:
                seen.add(end + disp)
        return seen == wanted

    def _loads(
        self, start: int, call: int, targets: Targets, budget: Budget
    ) -> dict[int, tuple[int, tuple[int, int]]] | None:
        """Argument position -> (address loaded, load span) for the call at `call`;
        None when the budget or the deadline ran out."""
        entry = targets.last(start, call)
        if entry == call:
            return {}
        if entry is not None:
            start = entry
        window = self._read(start, call - start)
        if window is None:
            return {}
        registers: dict[int, tuple[int, tuple[int, int]]] = {}
        pushes: list[tuple[int, tuple[int, int]] | None] = []
        address = start
        for insn in self.engine.disasm(window, start):
            if budget.used >= budget.instructions:
                budget.exhausted = True
                return None
            budget.used += 1
            if insn.address != address:
                return {}
            address += insn.size
            if self.bits == 64:
                self._track_registers(insn, registers)
            else:
                self._track_pushes(insn, pushes)
        if address != call:
            return {}
        if self.bits == 32:
            return {
                position: pushed
                for position, pushed in enumerate(reversed(pushes))
                if pushed is not None
            }
        return {_X64_POSITIONS[r]: loaded for r, loaded in registers.items() if r in _X64_POSITIONS}

    def _track_registers(
        self, insn: capstone.CsInsn, registers: dict[int, tuple[int, tuple[int, int]]]
    ) -> None:
        written = _written(insn)
        if written is None:
            registers.clear()
            return
        for register in written:
            registers.pop(_FAMILY.get(register, -1), None)
        loaded = main_forms.load(bytes(insn.bytes), insn.address, 64, self.image_base)
        if loaded is not None:
            position, address = loaded
            register = [r for r, p in _X64_POSITIONS.items() if p == position][0]
            registers[register] = (address, (insn.address, insn.size))

    def _track_pushes(
        self, insn: capstone.CsInsn, pushes: list[tuple[int, tuple[int, int]] | None]
    ) -> None:
        written = _written(insn)
        if written is None or any(operand.mem.base in _STACK for operand in _written_memory(insn)):
            pushes.clear()
        elif insn.id == x86.X86_INS_PUSH and insn.operands and insn.operands[0].size == 4:
            loaded = main_forms.load(bytes(insn.bytes), insn.address, 32, self.image_base)
            pushes.append(None if loaded is None else (loaded[1], (insn.address, insn.size)))
        elif _STACK & written:
            pushes.clear()
