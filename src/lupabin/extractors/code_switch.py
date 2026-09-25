"""Jump tables of compiled `switch` statements, resolved from the bytes only.

An indirect `jmp` is followed only when the instructions right before it have one of
the forms MSVC emits for a bounded jump table, so the number of entries is written in
the code, and every entry passes a check the file itself provides:

- x86: `cmp r, imm; ja; [movzx i, byte ptr [r + index]]; jmp dword ptr [i*4 + table]`.
  The table holds absolute addresses, so the linker lists every entry as a HIGHLOW
  base relocation; an entry without one is not a code pointer and the table is
  rejected (an image without relocations gets no tables).
- x64: `cmp r, imm; ja; ...; mov t32, dword ptr [b + i*4 + table]; add t, b; jmp t`,
  where `b` holds the image base (`lea b, [rip + ...]` reaching RVA 0) and the table
  holds RVAs. Every target must lie in the same `.pdata` function as the jump.

Between the bound and the jump only the instructions of the form are accepted
(extending the index, loading the base, the byte index of a two-level table), and
every entry must land in the executable section that holds the jump. Anything else
is not followed: the walk abstains rather than guess where a jump goes.
"""

import bisect
import struct
from array import array

import capstone
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
from capstone import x86_const as x86

from lupabin.extractors.code_disasm import Region
from lupabin.extractors.code_entries import FunctionRanges, relocations
from lupabin.extractors.pe_layout import InvalidTable, Layout

# A method parameter: tables with more entries are not followed.
MAX_ENTRIES = 1024
# Instructions before the jump that the forms can use: x86 cmp, ja, movzx; x64 also the
# extension of the index, the image-base lea (possibly right before the cmp), mov, add.
_WINDOW_X86 = 4
_WINDOW_X64 = 10

_FAMILIES = {
    name: family
    for family, names in {
        "a": "rax eax ax al",
        "b": "rbx ebx bx bl",
        "c": "rcx ecx cx cl",
        "d": "rdx edx dx dl",
        "si": "rsi esi si sil",
        "di": "rdi edi di dil",
        "bp": "rbp ebp bp bpl",
        "sp": "rsp esp sp spl",
        **{str(n): f"r{n} r{n}d r{n}w r{n}b" for n in range(8, 16)},
    }.items()
    for name in names.split()
}


class SwitchTables:
    """Called by the walk for every jmp without a constant target."""

    def __init__(self, layout: Layout, regions: list[Region], functions: FunctionRanges | None):
        self.layout = layout
        self.bits = layout.bits
        self.base = layout.header.image_base
        self.regions = sorted(regions, key=lambda region: region.rva)
        self.starts = [region.rva for region in self.regions]
        self.functions = functions
        self.engine = Cs(CS_ARCH_X86, CS_MODE_32 if self.bits == 32 else CS_MODE_64)
        self.engine.detail = True
        self._relocations: array[int] | None | bool = False  # read on first use
        self.tables = 0
        self.targets = 0

    def jumped(
        self,
        data: bytearray,
        offset: int,
        rva: int,
        size: int,
        previous: int,
        stretch: int,
        history: list[int],
    ) -> list[int]:
        raw = bytes(data[offset : offset + size])
        if not _candidate(raw, self.bits) or len(history) < 2:
            return []
        window = history[-(_WINDOW_X86 if self.bits == 32 else _WINDOW_X64) :]
        decoded = list(
            self.engine.disasm(bytes(data[window[0] : offset + size]), rva - offset + window[0])
        )
        # one pass over the same bytes must land on the walk's own instructions
        if [insn.address - rva + offset for insn in decoded] != window + [offset]:
            return []
        found = self._x86(decoded) if self.bits == 32 else self._x64(decoded)
        if not found:
            return []
        self.tables += 1
        self.targets += len(found)
        return found

    # --- x86 -------------------------------------------------------------------------

    def _x86(self, insns: list[capstone.CsInsn]) -> list[int]:
        jump = insns[-1]
        memory = _memory(jump, 0)
        if memory is None or memory.base or not memory.index or memory.scale != 4:
            return []
        index, rest = memory.index, insns[:-1]
        byte_table: tuple[int, int] | None = None  # (VA of the byte index, its register)
        if rest and rest[-1].id == x86.X86_INS_MOVZX:
            source = _memory(rest[-1], 1)
            if (
                _register(rest[-1], 0) != index
                or source is None
                or source.index
                or not source.base
                or source.size != 1
            ):
                return []
            byte_table, index, rest = (source.disp, source.base), source.base, rest[:-1]
        count = _bound(rest, index)
        if count is None:
            return []
        if byte_table is not None:
            count = self._byte_index((byte_table[0] & 0xFFFFFFFF) - self.base, count)
            if count is None:
                return []
        table = (memory.disp & 0xFFFFFFFF) - self.base
        entries = self._read(table, 4 * count)
        if entries is None or not self._relocated(table, count):
            return []
        targets = [value - self.base for (value,) in struct.iter_unpack("<I", entries)]
        return targets if self._inside(jump.address, targets) else []

    def _relocated(self, table: int, count: int) -> bool:
        if self._relocations is False:
            self._relocations = relocations(self.layout)
        known = self._relocations
        if not isinstance(known, array):
            return False
        at = bisect.bisect_left(known, table)
        wanted = [table + 4 * index for index in range(count)]
        return list(known[at : at + count]) == wanted

    # --- x64 -------------------------------------------------------------------------

    def _x64(self, insns: list[capstone.CsInsn]) -> list[int]:
        jump, rest = insns[-1], insns[:-1]
        target = _register(jump, 0)
        if target is None or len(rest) < 3:
            return []
        add, load = rest[-1], rest[-2]
        if add.id != x86.X86_INS_ADD or _register(add, 0) != target:
            return []
        base = _register(add, 1)
        memory = _memory(load, 1)
        if (
            base is None
            or load.id != x86.X86_INS_MOV
            or memory is None
            or memory.base != base
            or memory.scale != 4
            or not memory.index
            or _family(load, _register(load, 0)) != _family(jump, target)
            or load.operands[0].size != 4
        ):
            return []
        index, rest = memory.index, rest[:-2]
        table, byte_index = memory.disp, None
        if rest and rest[-1].id == x86.X86_INS_MOVZX:
            source = _memory(rest[-1], 1)
            if (
                source is None
                or source.base != base
                or not source.index
                or source.scale != 1
                or source.size != 1
                or _family(rest[-1], _register(rest[-1], 0)) != _family(load, index)
            ):
                return []
            byte_index, index, rest = source.disp, source.index, rest[:-1]
        count, base_set = self._x64_bound(rest, index, base, load)
        if count is None or not base_set:
            return []
        if byte_index is not None:
            count = self._byte_index(byte_index, count)
            if count is None:
                return []
        entries = self._read(table, 4 * count)
        if entries is None:
            return []
        targets = [value for (value,) in struct.iter_unpack("<I", entries)]
        if not self._inside(jump.address, targets):
            return []
        function = self.functions.holding(jump.address) if self.functions else None
        if function is None or not all(function[0] <= t < function[1] for t in targets):
            return []
        return targets

    def _x64_bound(
        self, rest: list[capstone.CsInsn], index: int, base: int, load: capstone.CsInsn
    ) -> tuple[int | None, bool]:
        """Walk back from the load to `cmp; ja`: only extensions of the index and the
        load of the image base may lie between them; the base may also be loaded right
        before the `cmp`."""
        wanted = _family(load, index)
        base_family = _family(load, base)
        base_set = False
        position = len(rest) - 1
        while position >= 1:
            insn = rest[position]
            if insn.id == x86.X86_INS_JA:
                count = _bound(rest[: position + 1], None, wanted)
                if count is None:
                    return None, False
                before = rest[position - 2] if position >= 2 else None
                if not base_set and before is not None and self._image_base(before, base_family):
                    base_set = True
                return count, base_set
            if self._image_base(insn, base_family):
                base_set = True
            elif (source := _extension(insn)) is not None and _family(
                insn, _register(insn, 0)
            ) == wanted:
                wanted = _family(insn, source)
            else:
                return None, False
            position -= 1
        return None, False

    def _image_base(self, insn: capstone.CsInsn, family: str | None) -> bool:
        """`lea b, [rip + disp]` whose address is the image base (RVA 0)."""
        memory = _memory(insn, 1)
        return (
            insn.id == x86.X86_INS_LEA
            and memory is not None
            and memory.base == x86.X86_REG_RIP
            and not memory.index
            and insn.address + insn.size + memory.disp == 0
            and _family(insn, _register(insn, 0)) == family
        )

    # --- shared ----------------------------------------------------------------------

    def _byte_index(self, rva: int, count: int) -> int | None:
        """Entries of the jump table a two-level switch indexes: one more than the
        largest byte of its index table."""
        values = self._read(rva, count)
        if values is None:
            return None
        entries = max(values) + 1
        return entries if entries <= MAX_ENTRIES else None

    def _read(self, rva: int, size: int) -> bytes | None:
        try:
            offset, _ = self.layout.locate(rva, size)
        except InvalidTable:
            return None
        return self.layout.data[offset : offset + size]

    def _inside(self, jump: int, targets: list[int]) -> bool:
        index = bisect.bisect_right(self.starts, jump) - 1
        region = self.regions[index]
        return all(region.rva <= target < region.end for target in targets)


def _candidate(raw: bytes, bits: int) -> bool:
    """`jmp dword ptr [i*4 + disp32]` (x86) or `jmp reg` (x64)."""
    if bits == 32:
        return len(raw) == 7 and raw[0] == 0xFF and raw[1] == 0x24 and raw[2] & 0xC7 == 0x85
    return (len(raw) == 2 and raw[0] == 0xFF and 0xE0 <= raw[1] <= 0xE7) or (
        len(raw) == 3 and raw[:2] == b"\x41\xff" and 0xE0 <= raw[2] <= 0xE7
    )


def _register(insn: capstone.CsInsn, position: int) -> int | None:
    operands = insn.operands
    if position < len(operands) and operands[position].type == x86.X86_OP_REG:
        return int(operands[position].reg)
    return None


class _Memory:
    """A memory operand without segment override: base, index, scale, disp and size."""

    def __init__(self, operand: capstone.x86.X86Op):
        self.base = int(operand.mem.base)
        self.index = int(operand.mem.index)
        self.scale = int(operand.mem.scale)
        self.disp = int(operand.mem.disp)
        self.size = int(operand.size)


def _memory(insn: capstone.CsInsn, position: int) -> _Memory | None:
    operands = insn.operands
    if position < len(operands) and operands[position].type == x86.X86_OP_MEM:
        if operands[position].mem.segment:
            return None
        return _Memory(operands[position])
    return None


def _family(insn: capstone.CsInsn, register: int | None) -> str | None:
    if register is None:
        return None
    return _FAMILIES.get(insn.reg_name(register))


def _extension(insn: capstone.CsInsn) -> int | None:
    """The source register of `movsxd r64, r32`, `mov r32, r32` or `cdqe` (eax)."""
    if insn.id == x86.X86_INS_CDQE:
        return int(x86.X86_REG_EAX)
    if insn.id in (x86.X86_INS_MOVSXD, x86.X86_INS_MOV) and len(insn.operands) == 2:
        return _register(insn, 1)
    return None


def _bound(rest: list[capstone.CsInsn], index: int | None, family: str | None = None) -> int | None:
    """Entries allowed by `cmp index, imm; ja` ending `rest`: imm + 1, if within bounds."""
    if len(rest) < 2 or rest[-1].id != x86.X86_INS_JA:
        return None
    compare = rest[-2]
    if compare.id != x86.X86_INS_CMP or len(compare.operands) != 2:
        return None
    register = _register(compare, 0)
    if register is None or compare.operands[1].type != x86.X86_OP_IMM:
        return None
    if index is not None and register != index:
        return None
    if family is not None and _family(compare, register) != family:
        return None
    limit = compare.operands[1].imm
    if not 0 <= limit < MAX_ENTRIES:
        return None
    return int(limit) + 1
