"""Canonical byte forms of an instruction that takes the address of a string, shared by
the worker and the host (docs/metodo.md, «Textos que usa el código»): lea r64,
[rip+disp32] in x64; push imm32 or mov r32, imm32 in x86. Anything else is not claimed."""

from lupabin.evidence.argument_forms import x64_register, x86_push


def address(raw: bytes, rva: int, bits: int, image_base: int) -> int | None:
    """The RVA the instruction's bytes put in a register or on the stack."""
    if bits == 64:
        found = x64_register(raw, rva)
        if found is None or found[1].kind != "address":
            return None
        return found[1].value
    if len(raw) == 5 and raw[0] == 0x68:
        pushed = x86_push(raw)
        value = None if pushed is None else pushed.value
    elif len(raw) == 5 and 0xB8 <= raw[0] <= 0xBF:
        value = int.from_bytes(raw[1:], "little")
    else:
        return None
    if value is None or value <= image_base:
        return None
    rva = value - image_base
    return rva if rva <= 0xFFFFFFFF else None
