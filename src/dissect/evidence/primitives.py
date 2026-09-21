from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

UInt = Annotated[int, Field(ge=0, le=0xFFFFFFFF)]
NonNegative = Annotated[int, Field(ge=0)]
EvidenceId = Annotated[str, Field(pattern=r"^E[1-9][0-9]*$", max_length=16)]
Source = Literal["pe", "strings"]
Status = Literal["completed", "partial", "failed"]
Component = Literal[
    "headers",
    "sections",
    "entropy",
    "imports_normal",
    "imports_delay",
    "exports",
    "anomalies",
    "ascii",
    "utf16le",
]
COMPONENTS: dict[Source, tuple[Component, ...]] = {
    "pe": (
        "headers",
        "sections",
        "entropy",
        "imports_normal",
        "imports_delay",
        "exports",
        "anomalies",
    ),
    "strings": ("ascii", "utf16le"),
}


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)


class Limits(Model):
    input_bytes: Annotated[int, Field(gt=0, le=20971520)] = 20971520
    timeout_seconds: Annotated[int, Field(gt=0, le=30)] = 30
    memory_bytes: Literal[536870912] = 536870912
    cpus: Literal[1] = 1
    pids: Literal[64] = 64
    output_bytes: Annotated[int, Field(gt=0, le=8388608)] = 8388608
    imports: Annotated[int, Field(gt=0, le=10000)] = 10000
    sections: Annotated[int, Field(gt=0, le=96)] = 96
    import_descriptors: Annotated[int, Field(gt=0, le=4096)] = 4096
    exports: Annotated[int, Field(gt=0, le=5000)] = 5000
    export_names: Annotated[int, Field(gt=0, le=10000)] = 10000
    strings: Annotated[int, Field(gt=0, le=5000)] = 5000
    string_characters: Annotated[int, Field(ge=4, le=1024)] = 1024
    anomalies: Annotated[int, Field(gt=0, le=128)] = 128
    entropy_bytes: Annotated[int, Field(gt=0, le=20971520)] = 20971520

    @property
    def evidence_bytes(self) -> int:
        return max(0, min(6 * 1024 * 1024, self.output_bytes - 1024 * 1024))


class Name(Model):
    raw_hex: Annotated[str, Field(pattern=r"^(?:[a-f0-9]{2})+$", max_length=8192)]
    text: Annotated[str, Field(max_length=4096)] | None = None

    @classmethod
    def from_bytes(cls, value: bytes) -> Self:
        try:
            text = value.decode("ascii")
        except UnicodeDecodeError:
            text = None
        return cls(raw_hex=value.hex(), text=text)

    @model_validator(mode="after")
    def faithful(self) -> Self:
        try:
            text = bytes.fromhex(self.raw_hex).decode("ascii")
        except UnicodeDecodeError:
            text = None
        if self.text != text:
            raise ValueError("text does not match original bytes")
        return self


class Location(Model):
    offset: NonNegative | None = None
    rva: UInt | None = None
    length: Annotated[int, Field(gt=0)] | None = None
    section: Name | None = None

    @model_validator(mode="after")
    def length_has_offset(self) -> Self:
        if self.length is not None and self.offset is None:
            raise ValueError("length requires a file offset")
        return self


class Provenance(Model):
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(max_length=32)] = ()
