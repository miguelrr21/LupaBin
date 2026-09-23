"""Canonical byte forms of an instruction that sets a call argument to a constant
(design section 3.4), shared by the worker and the host.

The worker decides which instruction sets which argument (the walk's rule); these
functions only say what constant a given instruction's bytes set and where. Anything
outside these forms sets an unknown value, and Dissect abstains.
"""

from typing import Literal, NamedTuple

Kind = Literal["address", "immediate"]


class Setting(NamedTuple):
    target: int  # x64: argument register index (0 rcx, 1 rdx, 2 r8, 3 r9); x86: -1 (a push)
    kind: Kind  # an RVA inside the image, or a plain number
    value: int


_X64_ARGUMENTS = {1: 0, 2: 1}  # low register number -> argument, without REX.R/REX.B
_X64_EXTENDED = {0: 2, 1: 3}  # r8, r9 with REX.R/REX.B


def _signed(raw: bytes) -> int:
    return int.from_bytes(raw, "little", signed=True)


def x64_setting(raw: bytes, rva: int) -> Setting | None:
    """lea r, [rip+disp32]; mov r32, imm32; mov r64, simm32; xor r32, r32 (zero)."""
    size = len(raw)
    # lea: 48 8D /r or 4C 8D /r with a RIP-relative operand (mod 00, rm 101)
    if size == 7 and raw[0] in (0x48, 0x4C) and raw[1] == 0x8D and raw[2] & 0xC7 == 0x05:
        register = (raw[2] >> 3) & 7
        table = _X64_EXTENDED if raw[0] == 0x4C else _X64_ARGUMENTS
        if register in table:
            target = rva + 7 + _signed(raw[3:])
            if 0 < target <= 0xFFFFFFFF:
                return Setting(table[register], "address", target)
        return None
    # mov r32, imm32: B8+r imm32, or 41 B8+r for r8d-r15d (zero-extends)
    if size == 5 and 0xB8 <= raw[0] <= 0xBF and raw[0] - 0xB8 in _X64_ARGUMENTS:
        return Setting(
            _X64_ARGUMENTS[raw[0] - 0xB8], "immediate", int.from_bytes(raw[1:], "little")
        )
    if size == 6 and raw[0] == 0x41 and 0xB8 <= raw[1] <= 0xBF and raw[1] - 0xB8 in _X64_EXTENDED:
        return Setting(_X64_EXTENDED[raw[1] - 0xB8], "immediate", int.from_bytes(raw[2:], "little"))
    # mov r64, simm32: 48 C7 C0+r imm32, or 49 C7 C0+r (sign-extended to 64 bits)
    if size == 7 and raw[0] in (0x48, 0x49) and raw[1] == 0xC7 and raw[2] & 0xF8 == 0xC0:
        register = raw[2] & 7
        table = _X64_EXTENDED if raw[0] == 0x49 else _X64_ARGUMENTS
        if register in table:
            return Setting(table[register], "immediate", _signed(raw[3:]) & 0xFFFFFFFFFFFFFFFF)
        return None
    # xor r32, r32 (31 /r or 33 /r with mod 11 and the same register): zero
    body, extended = raw, False
    if size == 3 and raw[0] == 0x45:
        body, extended = raw[1:], True
    if len(body) == 2 and body[0] in (0x31, 0x33) and body[1] & 0xC0 == 0xC0:
        first, second = (body[1] >> 3) & 7, body[1] & 7
        table = _X64_EXTENDED if extended else _X64_ARGUMENTS
        if first == second and first in table:
            return Setting(table[first], "immediate", 0)
    return None


def x86_push(raw: bytes) -> Setting | None:
    """push imm32 (68) or push simm8 (6A), as a number: only the parameter's type says
    whether it is an address (HKEY_CURRENT_USER, 0x80000001, is above any image base)."""
    if len(raw) == 5 and raw[0] == 0x68:
        return Setting(-1, "immediate", int.from_bytes(raw[1:], "little"))
    if len(raw) == 2 and raw[0] == 0x6A:
        return Setting(-1, "immediate", _signed(raw[1:]) & 0xFFFFFFFF)
    return None


def address_of(setting: Setting, bits: int, image_base: int) -> int | None:
    """The RVA an argument points to: a RIP-relative lea in x64, an absolute push in x86."""
    if bits == 64:
        return setting.value if setting.kind == "address" else None
    rva = setting.value - image_base
    return rva if 0 < rva <= 0xFFFFFFFF else None
