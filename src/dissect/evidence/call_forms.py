"""Canonical byte forms of a call to an imported function (design section 3.3).

The worker finds instruction boundaries with a disassembler; deciding whether an
instruction calls an import only reads these fixed encodings and their operand
arithmetic. The host runs the same functions on the bytes a report cites, so it can
re-derive every call without a disassembler of its own. Anything outside these
forms is not a call to an import for Dissect: it abstains instead of guessing.
"""

CALL = 0x15  # FF /2 with a memory operand: call [slot]
JMP = 0x25  # FF /4 with a memory operand: jmp [slot]
_STACK_POINTER = 4  # esp/rsp: loading it and calling through it is not a call form


def _slot(value: int) -> int | None:
    return value if 0 < value <= 0xFFFFFFFF else None


def _rip(rva: int, length: int, disp: bytes) -> int | None:
    return _slot(rva + length + int.from_bytes(disp, "little", signed=True))


def memory_slot(raw: bytes, rva: int, bits: int, image_base: int, opcode: int) -> int | None:
    """RVA of the slot read by `call [slot]` or `jmp [slot]`, or None if not canonical.

    x86: FF 15/25 abs32, an absolute address. x64: FF 15/25 disp32, optionally
    after REX.W (48), relative to the next instruction.
    """
    if bits == 32:
        if len(raw) == 6 and raw[0] == 0xFF and raw[1] == opcode:
            return _slot(int.from_bytes(raw[2:], "little") - image_base)
        return None
    body = raw[1:] if len(raw) == 7 and raw[0] == 0x48 else raw
    if len(body) == 6 and body[0] == 0xFF and body[1] == opcode:
        return _rip(rva, len(raw), body[2:])
    return None


def relative_target(raw: bytes, rva: int) -> int | None:
    """RVA reached by `call rel32` (E8), or None if not canonical."""
    if len(raw) == 5 and raw[0] == 0xE8:
        return _rip(rva, 5, raw[1:])
    return None


def register_load(raw: bytes, rva: int, bits: int, image_base: int) -> tuple[int, int] | None:
    """(register number, slot RVA) of `mov reg, [slot]` loading a whole pointer.

    x86: A1 abs32 (eax) or 8B /r with a disp32-only operand. x64: 48/4C 8B /r with a
    RIP-relative operand; without REX.W the load is 32 bits, not a pointer.
    """
    if bits == 32:
        if len(raw) == 5 and raw[0] == 0xA1:
            register, address = 0, raw[1:]
        elif len(raw) == 6 and raw[0] == 0x8B and raw[1] & 0xC7 == 0x05:
            register, address = (raw[1] >> 3) & 7, raw[2:]
        else:
            return None
        slot = _slot(int.from_bytes(address, "little") - image_base)
    else:
        if not (len(raw) == 7 and raw[0] in (0x48, 0x4C) and raw[1] == 0x8B):
            return None
        if raw[2] & 0xC7 != 0x05:
            return None
        register = ((raw[0] & 4) << 1) | ((raw[2] >> 3) & 7)
        slot = _rip(rva, 7, raw[3:])
    if slot is None or register == _STACK_POINTER:
        return None
    return register, slot


def register_call(raw: bytes, bits: int) -> int | None:
    """Register number of `call reg` (FF D0+r; 41 FF D0+r for r8-r15 in x64)."""
    if len(raw) == 2 and raw[0] == 0xFF and 0xD0 <= raw[1] <= 0xD7:
        register = raw[1] - 0xD0
    elif bits == 64 and len(raw) == 3 and raw[:2] == b"\x41\xff" and 0xD0 <= raw[2] <= 0xD7:
        register = 8 + raw[2] - 0xD0
    else:
        return None
    return None if register == _STACK_POINTER else register
