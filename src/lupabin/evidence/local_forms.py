"""Canonical byte forms that name a local variable of the frame: its address or its value.

A local variable is a frame slot: a displacement from the frame register (`ebp` in
x86; `rsp` or `rbp` in x64). The worker decides which instructions pass it to which
calls (the walk's rule); these functions only say which slot an instruction's bytes
name and through which register, so the host can check them without a disassembler.
Anything outside these forms names no slot, and LupaBin abstains.
"""

from typing import Literal, NamedTuple

Frame = Literal["ebp", "rsp", "rbp"]
# Which parameter of which function writes a handle into a local variable, checked
# against Microsoft Learn: phkResult of RegOpenKeyExA/W (5th) and RegCreateKeyExA/W
# (8th). The functions that read it are the catalog's hkey parameters.
WRITERS = {
    b"RegOpenKeyExA": (4, "phkResult"),
    b"RegOpenKeyExW": (4, "phkResult"),
    b"RegCreateKeyExA": (7, "phkResult"),
    b"RegCreateKeyExW": (7, "phkResult"),
}
MAX_DISTANCE = 4096  # bytes from the end of the writing call to the reading instruction
X64_ARGUMENT_REGISTERS = (1, 2, 8, 9)  # rcx, rdx, r8, r9
# x64 home area: the four slots at [rsp] belong to the callee, and "the caller may not
# save information in this region of stack across a function call" (Microsoft Learn,
# x64 stack usage). A variable there cannot carry a handle from one call to another.
HOME_AREA = 0x20


def keeps_across_calls(slot: "Slot") -> bool:
    return slot.frame != "rsp" or slot.displacement >= HOME_AREA


class Slot(NamedTuple):
    frame: Frame
    displacement: int  # signed


class Named(NamedTuple):
    """What an instruction does with a slot: loads its address or its value into a
    register (0-15), or pushes its value (register None)."""

    slot: Slot
    register: int | None


def _signed(raw: bytes) -> int:
    return int.from_bytes(raw, "little", signed=True)


def _memory32(modrm_and_rest: bytes) -> tuple[int, Slot] | None:
    """x86 ModRM (+disp) addressing [ebp + disp8/disp32]: (reg field, slot)."""
    modrm = modrm_and_rest[0]
    mod, reg, rm = modrm >> 6, (modrm >> 3) & 7, modrm & 7
    rest = modrm_and_rest[1:]
    if rm != 5 or (mod, len(rest)) not in ((1, 1), (2, 4)):
        return None
    return reg, Slot("ebp", _signed(rest))


def _memory64(rex: int, body: bytes) -> tuple[int, Slot] | None:
    """x64 ModRM (+SIB, +disp) addressing [rsp + disp] or [rbp + disp], REX.B clear:
    (register field with REX.R, slot)."""
    modrm = body[0]
    mod, reg, rm = modrm >> 6, ((modrm >> 3) & 7) + (8 if rex & 4 else 0), modrm & 7
    rest = body[1:]
    if rm == 4:  # SIB: only [rsp + disp] (base rsp, no index)
        if not rest or rest[0] != 0x24:
            return None
        rest = rest[1:]
        frame: Frame = "rsp"
    elif rm == 5 and mod != 0:
        frame = "rbp"
    else:
        return None
    if (mod, len(rest)) not in ((1, 1), (2, 4)):
        return None
    return reg, Slot(frame, _signed(rest))


def x86_lea(raw: bytes) -> Named | None:
    """lea r32, [ebp + disp]: 8D /r. The register holds the slot's address."""
    if len(raw) >= 3 and raw[0] == 0x8D:
        found = _memory32(raw[1:])
        if found is not None and found[0] != 4:
            return Named(found[1], found[0])
    return None


def x86_push_register(raw: bytes) -> int | None:
    """push r32: 50+r (not esp)."""
    if len(raw) == 1 and 0x50 <= raw[0] <= 0x57 and raw[0] != 0x54:
        return raw[0] - 0x50
    return None


def x86_push_value(raw: bytes) -> Named | None:
    """push dword ptr [ebp + disp]: FF /6. Pushes the slot's value."""
    if len(raw) >= 3 and raw[0] == 0xFF:
        found = _memory32(raw[1:])
        if found is not None and found[0] == 6:
            return Named(found[1], None)
    return None


def x64_lea(raw: bytes) -> Named | None:
    """lea r64, [rsp/rbp + disp]: 48/4C 8D /r. The register holds the slot's address."""
    if len(raw) >= 4 and raw[0] in (0x48, 0x4C) and raw[1] == 0x8D:
        found = _memory64(raw[0], raw[2:])
        if found is not None and found[0] != 4:
            return Named(found[1], found[0])
    return None


def x64_load(raw: bytes) -> Named | None:
    """mov r64, qword ptr [rsp/rbp + disp]: 48/4C 8B /r. The register holds its value."""
    if len(raw) >= 4 and raw[0] in (0x48, 0x4C) and raw[1] == 0x8B:
        found = _memory64(raw[0], raw[2:])
        if found is not None and found[0] != 4:
            return Named(found[1], found[0])
    return None
