"""Canonical byte forms of an instruction that sets a call argument to a constant
(design sections 3.4 and 11), shared by the worker and the host.

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


class StackStore(NamedTuple):
    """A store to argument `position`'s stack slot in x64 (design section 11.1)."""

    position: int  # 4..15: the slot [rsp + 8 * position] at the call
    width: int  # bytes written: 4 or 8
    value: int | None  # the stored immediate, or None when it copies `register`
    register: int | None  # 0..15, the general register it copies


# x64 general register number -> argument index: rcx, rdx, r8, r9
_X64_ARGUMENTS = {1: 0, 2: 1, 8: 2, 9: 3}
_STACK_POINTER = 4


def _signed(raw: bytes) -> int:
    return int.from_bytes(raw, "little", signed=True)


def x64_register(raw: bytes, rva: int) -> tuple[int, Setting] | None:
    """(register 0-15, setting) for lea r64, [rip+disp32]; mov r32, imm32;
    mov r64, simm32; xor r32, r32 (zero). The setting's target is the register."""
    size = len(raw)
    found: tuple[int, Kind, int] | None = None
    # lea: 48 8D /r or 4C 8D /r (REX.R: r8-r15) with a RIP-relative operand (mod 00, rm 101)
    if size == 7 and raw[0] in (0x48, 0x4C) and raw[1] == 0x8D and raw[2] & 0xC7 == 0x05:
        register = ((raw[2] >> 3) & 7) + (8 if raw[0] == 0x4C else 0)
        target = rva + 7 + _signed(raw[3:])
        found = (register, "address", target) if 0 < target <= 0xFFFFFFFF else None
    # mov r32, imm32: B8+r imm32, or 41 B8+r for r8d-r15d (zero-extends)
    elif size == 5 and 0xB8 <= raw[0] <= 0xBF:
        found = (raw[0] - 0xB8, "immediate", int.from_bytes(raw[1:], "little"))
    elif size == 6 and raw[0] == 0x41 and 0xB8 <= raw[1] <= 0xBF:
        found = (8 + raw[1] - 0xB8, "immediate", int.from_bytes(raw[2:], "little"))
    # mov r64, simm32: 48 C7 C0+r imm32, or 49 C7 C0+r (sign-extended to 64 bits)
    elif size == 7 and raw[0] in (0x48, 0x49) and raw[1] == 0xC7 and raw[2] & 0xF8 == 0xC0:
        register = (raw[2] & 7) + (8 if raw[0] == 0x49 else 0)
        found = (register, "immediate", _signed(raw[3:]) & 0xFFFFFFFFFFFFFFFF)
    else:
        # xor r32, r32 (31 /r or 33 /r with mod 11 and the same register): zero
        body, extended = raw, 0
        if size == 3 and raw[0] == 0x45:  # REX.R and REX.B: r8d-r15d
            body, extended = raw[1:], 8
        if len(body) == 2 and body[0] in (0x31, 0x33) and body[1] & 0xC0 == 0xC0:
            first, second = (body[1] >> 3) & 7, body[1] & 7
            if first == second:
                found = (first + extended, "immediate", 0)
    if found is None or found[0] == _STACK_POINTER:
        return None
    register, kind, value = found
    return register, Setting(register, kind, value)


def x64_setting(raw: bytes, rva: int) -> Setting | None:
    """The same forms, when they set an argument register (rcx, rdx, r8 or r9)."""
    found = x64_register(raw, rva)
    if found is None or found[0] not in _X64_ARGUMENTS:
        return None
    register, setting = found
    return setting._replace(target=_X64_ARGUMENTS[register])


def x64_stack_store(raw: bytes) -> StackStore | None:
    """mov dword/qword ptr [rsp+d8], imm32; and dword/qword ptr [rsp+d8], 0;
    mov [rsp+d8], r32/r64 — with d8 = 8 * position and 4 <= position <= 15."""
    body, wide = raw, False
    if raw[:1] == b"\x48":  # REX.W alone
        body, wide = raw[1:], True
    width = 8 if wide else 4
    store: tuple[int, int | None, int | None] | None = None  # (disp8, value, register)
    if len(body) == 8 and body[:3] == b"\xc7\x44\x24":
        value = int.from_bytes(body[4:], "little")
        if wide:
            value = _signed(body[4:]) & 0xFFFFFFFFFFFFFFFF
        store = (body[3], value, None)
    elif len(body) == 5 and body[:3] == b"\x83\x64\x24" and body[4] == 0:
        store = (body[3], 0, None)
    else:
        # mov [rsp+d8], reg: 89 /r, ModRM 01 reg 100, SIB 24; 44 (REX.R) or 4C (REX.W+R)
        extended = 0
        if raw[:1] in (b"\x44", b"\x4c"):
            body, extended, width = raw[1:], 8, 8 if raw[0] == 0x4C else 4
        if len(body) == 4 and body[0] == 0x89 and body[1] & 0xC7 == 0x44 and body[2] == 0x24:
            store = (body[3], None, ((body[1] >> 3) & 7) + extended)
    if store is None:
        return None
    displacement, stored, register = store
    if displacement % 8 or not 4 <= displacement // 8 <= 15 or register == _STACK_POINTER:
        return None
    return StackStore(displacement // 8, width, stored, register)


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
