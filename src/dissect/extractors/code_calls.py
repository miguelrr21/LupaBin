"""Which walked call sites reach an imported function, and by which of three forms."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Literal

from dissect.evidence import call_forms
from dissect.extractors.code_disasm import Site

Via = Literal["direct", "thunk", "register"]


@dataclass(frozen=True)
class Call:
    via: Via
    rva: int
    size: int
    slot: int
    helper: tuple[int, int] | None  # (rva, size): the thunk's jmp or the register load


def classify(
    sites: list[Site],
    read: Callable[[int, int], bytes | None],
    bits: int,
    image_base: int,
    slots: Mapping[int, object],
) -> list[Call]:
    """Calls whose slot is a known import slot, in the order the walk found them.

    `read(rva, size)` returns code bytes, or None outside the executable regions.
    """
    calls = []
    for site in sites:
        raw = read(site.rva, site.size)
        if raw is None:
            continue
        slot = call_forms.memory_slot(raw, site.rva, bits, image_base, call_forms.CALL)
        if slot is not None:
            if slot in slots:
                calls.append(Call("direct", site.rva, site.size, slot, None))
            continue
        target = call_forms.relative_target(raw, site.rva)
        if target is not None:
            thunk = _thunk(read, target, bits, image_base)
            if thunk is not None and thunk[1] in slots:
                calls.append(Call("thunk", site.rva, site.size, thunk[1], (target, thunk[0])))
            continue
        register = call_forms.register_call(raw, bits)
        if register is not None and site.previous is not None:
            before = read(*site.previous)
            load = (
                None
                if before is None
                else call_forms.register_load(before, site.previous[0], bits, image_base)
            )
            if load is not None and load[0] == register and load[1] in slots:
                calls.append(Call("register", site.rva, site.size, load[1], site.previous))
    return calls


def _thunk(
    read: Callable[[int, int], bytes | None], rva: int, bits: int, image_base: int
) -> tuple[int, int] | None:
    """(size, slot) when `rva` holds a canonical `jmp [slot]`."""
    for size in (6,) if bits == 32 else (6, 7):
        raw = read(rva, size)
        if raw is not None:
            slot = call_forms.memory_slot(raw, rva, bits, image_base, call_forms.JMP)
            if slot is not None:
                return size, slot
    return None
