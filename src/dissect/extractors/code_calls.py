"""Which walked calls reach an imported function, and by which of three forms."""

from collections.abc import Callable, Container
from dataclasses import dataclass
from typing import Literal

from dissect.evidence import call_forms

Via = Literal["direct", "thunk", "register"]


@dataclass(frozen=True)
class Call:
    via: Via
    rva: int
    size: int
    slot: int
    helper: tuple[int, int] | None  # (rva, size): the thunk's jmp or the register load
    start: int  # RVA where the call's linear stretch starts (code_disasm.walk)


class CallFinder:
    """Classifies each call the walk meets, in bounded memory.

    Publication order is each import's first call, then repeated calls, cut at
    `quota`: when calls are dropped, the published ones still cover as many imports
    as possible. Memory holds one call per import slot plus `quota` repeats.
    """

    def __init__(
        self,
        read: Callable[[int, int], bytes | None],
        bits: int,
        image_base: int,
        slots: Container[int],
        quota: int,
    ):
        self.read = read
        self.bits = bits
        self.base = image_base
        self.slots = slots
        self.quota = quota
        self.first: dict[int, Call] = {}
        self.repeated: list[Call] = []
        self.found = 0

    def calls(self) -> list[Call]:
        return (list(self.first.values()) + self.repeated)[: self.quota]

    @property
    def dropped(self) -> bool:
        return self.found > self.quota

    def visit(
        self, data: bytearray, offset: int, rva: int, size: int, previous: int, start: int
    ) -> None:
        call = self._classify(data, offset, rva, size, previous, start)
        if call is None:
            return
        self.found += 1
        if call.slot not in self.first:
            self.first[call.slot] = call
        elif len(self.repeated) < self.quota:
            self.repeated.append(call)

    def _classify(
        self, data: bytearray, offset: int, rva: int, size: int, previous: int, start: int
    ) -> Call | None:
        bits, base = self.bits, self.base
        raw = bytes(data[offset : offset + size])
        target = call_forms.relative_target(raw, rva)
        if target is not None:
            for stub_size in (6,) if bits == 32 else (6, 7):
                stub = self.read(target, stub_size)
                if stub is None:
                    continue
                slot = call_forms.memory_slot(stub, target, bits, base, call_forms.JMP)
                if slot is not None:
                    if slot not in self.slots:
                        return None
                    return Call("thunk", rva, size, slot, (target, stub_size), start)
            return None
        slot = call_forms.memory_slot(raw, rva, bits, base, call_forms.CALL)
        if slot is not None:
            return Call("direct", rva, size, slot, None, start) if slot in self.slots else None
        register = call_forms.register_call(raw, bits)
        if register is None or not previous:
            return None
        before = bytes(data[offset - previous : offset])
        load = call_forms.register_load(before, rva - previous, bits, base)
        if load is None or load[0] != register or load[1] not in self.slots:
            return None
        return Call("register", rva, size, load[1], (rva - previous, previous), start)
