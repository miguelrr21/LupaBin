from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

UInt = Annotated[int, Field(ge=0, le=0xFFFFFFFF)]
NonNegative = Annotated[int, Field(ge=0)]
EvidenceId = Annotated[str, Field(pattern=r"^E[1-9][0-9]*$", max_length=16)]
Source = Literal["pe", "strings", "yara", "decode", "code"]
Status = Literal["completed", "partial", "failed"]
Component = Literal[
    "headers",
    "sections",
    "entropy",
    "imports_normal",
    "imports_delay",
    "exports",
    "anomalies",
    "toolchain",
    "ascii",
    "utf16le",
    "yara_rules",
    "yara_scan",
    "yara_evidence",
    "decode_strings",
    "decode_xor",
    "disassembly",
    "api_calls",
    "call_arguments",
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
        "toolchain",
    ),
    "strings": ("ascii", "utf16le"),
    "yara": ("yara_rules", "yara_scan", "yara_evidence"),
    "decode": ("decode_strings", "decode_xor"),
    "code": ("disassembly", "api_calls", "call_arguments"),
}


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)


class YaraLimits(Model):
    rules: Annotated[int, Field(gt=0, le=32)] = 32
    source_bytes: Annotated[int, Field(gt=0, le=16384)] = 16384
    total_source_bytes: Annotated[int, Field(gt=0, le=262144)] = 262144
    manifest_bytes: Annotated[int, Field(gt=0, le=65536)] = 65536
    patterns_per_rule: Annotated[int, Field(gt=0, le=8)] = 8
    scan_seconds: Annotated[int, Field(gt=0, le=5)] = 5
    process_seconds: Annotated[int, Field(gt=0, le=10)] = 10
    matches: Annotated[int, Field(gt=0, le=32)] = 32
    instances: Annotated[int, Field(gt=0, le=16)] = 16
    capture_bytes: Annotated[int, Field(gt=0, le=256)] = 256
    output_bytes: Annotated[int, Field(gt=0, le=1048576)] = 1048576
    stderr_bytes: Annotated[int, Field(gt=0, le=65536)] = 65536


class DecodeLimits(Model):
    strings: Annotated[int, Field(gt=0, le=2000)] = 2000
    xor: Annotated[int, Field(gt=0, le=256)] = 256
    xor_examined: Annotated[int, Field(gt=0, le=200000)] = 200000
    # The XOR scan stops once the analysis has run this long (or a third of
    # timeout_seconds, if less), leaving time for the code walk and the report.
    seconds: Annotated[int, Field(gt=0, le=30)] = 10


class CodeLimits(Model):
    instructions: Annotated[int, Field(gt=0, le=8000000)] = 8000000
    entries: Annotated[int, Field(gt=0, le=262144)] = 262144
    call_sites: Annotated[int, Field(gt=0, le=1048576)] = 1048576
    # The walk stops once the analysis has run this long (or half of timeout_seconds, if
    # less): it is the last source, and a timeout would lose the whole report.
    seconds: Annotated[int, Field(gt=0, le=30)] = 15
    calls: Annotated[int, Field(gt=0, le=4096)] = 4096
    arguments: Annotated[int, Field(gt=0, le=4096)] = 4096
    # Instructions decoded in capstone's detail mode to recover arguments, across all
    # calls of the catalog, measured on benign binaries (docs/metodo.md).
    argument_instructions: Annotated[int, Field(gt=0, le=262144)] = 65536


class Limits(Model):
    yara: YaraLimits = Field(default_factory=YaraLimits)
    decode: DecodeLimits = Field(default_factory=DecodeLimits)
    code: CodeLimits = Field(default_factory=CodeLimits)
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


TransformName = Literal["base64-strict-v1", "hex-strict-v1", "xor-repeating-v1"]


def minimal_period(key: bytes) -> bytes:
    for period in range(1, len(key) + 1):
        if len(key) % period == 0 and key == key[:period] * (len(key) // period):
            return key[:period]
    return key


def canonical_key(key: bytes) -> bytes:
    """The same repeating key regardless of phase: minimal period, least rotation."""
    period = minimal_period(key)
    return min(period[shift:] + period[:shift] for shift in range(len(period)))


class Transform(Model):
    name: TransformName
    key_hex: Annotated[str, Field(pattern=r"^(?:[a-f0-9]{2}){1,8}$")] | None = None

    @model_validator(mode="after")
    def key_matches_transform(self) -> Self:
        if (self.name == "xor-repeating-v1") != (self.key_hex is not None):
            raise ValueError("xor-repeating-v1 requires a key; other transforms carry none")
        if self.key_hex is not None:
            key = bytes.fromhex(self.key_hex)
            if not any(key):
                raise ValueError("an all-zero XOR key is the identity, not a decoding")
            if minimal_period(key) != key:
                raise ValueError("an XOR key must be published in its minimal period")
        return self


class Provenance(Model):
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(max_length=32)] = ()
