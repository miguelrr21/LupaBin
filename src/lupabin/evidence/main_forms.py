"""Canonical byte forms of the call through which the compiler's startup enters `main`,
shared by the worker and the host (docs/metodo.md, «La función main»).

`__getmainargs` and `__wgetmainargs` (msvcrt.dll) receive the addresses of three
variables and fill them with argc, argv and envp (Microsoft Learn: they "copy the
arguments to main() back through the passed pointers"). The startup then calls `main`
with the values of those three variables. The worker decides which instructions set
and load them (the walk's rule); these functions only say what address an
instruction's bytes use, and where a direct call goes. Anything else is not claimed.
"""

from lupabin.evidence.argument_forms import x64_setting, x86_push

GETMAINARGS = frozenset({b"__getmainargs", b"__wgetmainargs"})
DLL = b"msvcrt.dll"
ARGUMENTS = 3  # argc, argv, envp


def _signed(raw: bytes) -> int:
    return int.from_bytes(raw, "little", signed=True)


def direct_call(raw: bytes, rva: int) -> int | None:
    """The target RVA of call rel32 (E8)."""
    if len(raw) != 5 or raw[0] != 0xE8:
        return None
    target = rva + 5 + _signed(raw[1:])
    return target if 0 <= target <= 0xFFFFFFFF else None


def setter(raw: bytes, rva: int, bits: int, image_base: int) -> tuple[int, int] | None:
    """(argument position, RVA) for an instruction that passes a variable's address:
    lea rcx/rdx/r8, [rip+disp32] in x64; push imm32 in x86 (its position is where the
    push lands, which the worker decides: -1 here)."""
    if bits == 64:
        setting = x64_setting(raw, rva)
        if setting is None or setting.kind != "address":
            return None
        return setting.target, setting.value
    if len(raw) != 5:
        return None  # push simm8 cannot hold an address in the image
    pushed = x86_push(raw)
    if pushed is None:
        return None
    address = pushed.value - image_base
    return (-1, address) if 0 < address <= 0xFFFFFFFF else None


# x64 argument register (ModRM reg field plus REX.R) -> position: rcx, rdx, r8
_X64_LOADED = {1: 0, 2: 1, 8: 2}


def load(raw: bytes, rva: int, bits: int, image_base: int) -> tuple[int, int] | None:
    """(argument position, RVA) for an instruction that passes a variable's value:
    mov ecx/rcx/edx/rdx/r8d/r8, [rip+disp32] in x64 (8B /r, mod 00, rm 101, optional
    REX with only W and R); push dword ptr [disp32] (FF 35) in x86, position -1."""
    if bits == 64:
        body, extended = raw, 0
        if raw[:1] and 0x40 <= raw[0] <= 0x4F:
            if raw[0] & 0x3:  # REX.X or REX.B: not these forms
                return None
            body, extended = raw[1:], 8 if raw[0] & 0x4 else 0
        if len(body) != 6 or body[0] != 0x8B or body[1] & 0xC7 != 0x05:
            return None
        register = ((body[1] >> 3) & 7) + extended
        if register not in _X64_LOADED:
            return None
        address = rva + len(raw) + _signed(body[2:])
        return (_X64_LOADED[register], address) if 0 < address <= 0xFFFFFFFF else None
    if len(raw) != 6 or raw[:2] != b"\xff\x35":
        return None
    address = int.from_bytes(raw[2:], "little") - image_base
    return (-1, address) if 0 < address <= 0xFFFFFFFF else None
