import struct
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from lupabin.evidence import toolchain
from lupabin.evidence.primitives import (
    Component,
    EvidenceId,
    Location,
    Model,
    Name,
    NonNegative,
    Provenance,
    Source,
    Transform,
    UInt,
)
from lupabin.evidence.yara import YaraMatchData


class ImportData(Model):
    dll: Name
    function: Name | None = None
    ordinal: Annotated[int, Field(ge=0, le=65535)] | None = None
    table: Literal["normal", "delay"]
    # RVA of this import's slot in the import address table, where calls point.
    iat_rva: Annotated[int, Field(gt=0, le=0xFFFFFFFF)]

    @model_validator(mode="after")
    def name_or_ordinal(self) -> Self:
        if (self.function is None) == (self.ordinal is None):
            raise ValueError("exactly one of function and ordinal is required")
        return self


class HeaderData(Model):
    machine: Annotated[int, Field(ge=0, le=65535)]
    number_of_sections: Annotated[int, Field(ge=1, le=65535)]
    timestamp_raw: UInt
    characteristics: Annotated[int, Field(ge=0, le=65535)]
    optional_magic: Literal[267, 523]
    image_base: Annotated[int, Field(ge=0, le=0xFFFFFFFFFFFFFFFF)]
    entry_point_rva: UInt
    section_alignment: UInt
    file_alignment: UInt
    size_of_image: UInt
    size_of_headers: UInt


class SectionData(Model):
    index: Annotated[int, Field(ge=0, lt=96)]
    name_raw_hex: Annotated[str, Field(pattern=r"^[a-f0-9]{16}$")]
    name_text: Annotated[str, Field(max_length=8)] | None
    rva: UInt
    virtual_size: UInt
    raw_offset: UInt
    raw_size: UInt
    characteristics: UInt
    raw_status: Literal["present", "empty", "out_of_bounds"]
    permissions: tuple[Literal["read", "write", "execute"], ...]

    @model_validator(mode="after")
    def faithful(self) -> Self:
        try:
            name = bytes.fromhex(self.name_raw_hex).rstrip(b"\0").decode("utf-8")
        except UnicodeDecodeError:
            name = None
        if name != self.name_text:
            raise ValueError("section name does not match bytes")
        permissions = tuple(
            label
            for flag, label in (
                (0x40000000, "read"),
                (0x80000000, "write"),
                (0x20000000, "execute"),
            )
            if self.characteristics & flag
        )
        if self.permissions != permissions:
            raise ValueError("permissions disagree with declared flags")
        if (self.raw_size == 0) != (self.raw_status == "empty"):
            raise ValueError("empty section status disagrees with size")
        return self


class EntropyData(Model):
    method: Literal["shannon-byte-v1"] = "shannon-byte-v1"
    byte_count: Annotated[int, Field(gt=0, le=20971520)]
    bits_per_byte: Annotated[float, Field(ge=0, le=8)]


class ExportData(Model):
    eat_index: UInt
    ordinal: UInt
    names: Annotated[tuple[Name, ...], Field(max_length=10000)] = ()
    names_status: Literal["complete", "incomplete"]
    target_rva: Annotated[int, Field(gt=0, le=0xFFFFFFFF)]
    forwarder: Name | None = None
    target_kind: Literal["declared_rva", "forwarder", "unreadable_forwarder"]

    @model_validator(mode="after")
    def target_matches(self) -> Self:
        if (self.target_kind == "forwarder") != (self.forwarder is not None):
            raise ValueError("forwarder text disagrees with target kind")
        return self


class StringData(Model):
    encoding: Literal["ascii", "utf-16-le"]
    repertoire: Literal["ascii-printable-v1"] = "ascii-printable-v1"
    text: Annotated[str, Field(min_length=4, max_length=1024)]
    raw_hex: Annotated[str, Field(pattern=r"^(?:[a-f0-9]{2})+$", max_length=4096)]
    characters: Annotated[int, Field(ge=4, le=1024)]
    complete: bool
    total_characters: NonNegative | None = None

    @model_validator(mode="after")
    def faithful(self) -> Self:
        if any(not 32 <= ord(char) <= 126 for char in self.text):
            raise ValueError("unsupported string repertoire")
        if (
            self.text.encode(self.encoding).hex() != self.raw_hex
            or len(self.text) != self.characters
        ):
            raise ValueError("string differs from original bytes")
        if self.complete and self.total_characters != self.characters:
            raise ValueError("complete string requires its exact length")
        if not self.complete and self.total_characters is not None:
            if self.total_characters <= self.characters:
                raise ValueError("truncated string cannot have a shorter total")
        return self


AnomalyCode = Literal[
    "section_raw_out_of_bounds",
    "section_raw_overlap",
    "section_virtual_overlap",
    "section_exceeds_image",
    "entry_point_outside_image",
]


class AnomalyData(Model):
    code: AnomalyCode
    rule_version: Literal["pe-structure-v1"] = "pe-structure-v1"
    section_indices: Annotated[tuple[UInt, ...], Field(max_length=2)] = ()


class Fact(Model):
    id: EvidenceId
    source: Source
    component: Component
    location: Location
    confidence: Literal["observed"] = "observed"
    provenance: Provenance = Field(default_factory=Provenance)


class ImportEvidence(Fact):
    kind: Literal["import"] = "import"
    data: ImportData


class HeaderEvidence(Fact):
    kind: Literal["pe_header"] = "pe_header"
    data: HeaderData


class SectionEvidence(Fact):
    kind: Literal["section"] = "section"
    data: SectionData


class EntropyEvidence(Fact):
    kind: Literal["entropy"] = "entropy"
    data: EntropyData


class ExportEvidence(Fact):
    kind: Literal["export"] = "export"
    data: ExportData


class StringEvidence(Fact):
    kind: Literal["string"] = "string"
    data: StringData


class DecodedStringData(Model):
    encoding: Literal["ascii", "utf-16-le"]
    repertoire: Literal["ascii-printable-v1"] = "ascii-printable-v1"
    text: Annotated[str, Field(min_length=4, max_length=1024)]
    raw_hex: Annotated[str, Field(pattern=r"^(?:[a-f0-9]{2})+$", max_length=4096)]
    characters: Annotated[int, Field(ge=4, le=1024)]
    complete: bool
    total_characters: NonNegative | None = None

    @model_validator(mode="after")
    def faithful(self) -> Self:
        if any(not 32 <= ord(char) <= 126 for char in self.text):
            raise ValueError("unsupported string repertoire")
        if (
            self.text.encode(self.encoding).hex() != self.raw_hex
            or len(self.text) != self.characters
        ):
            raise ValueError("string differs from decoded bytes")
        if self.complete and self.total_characters != self.characters:
            raise ValueError("complete string requires its exact length")
        if not self.complete and self.total_characters is not None:
            if self.total_characters <= self.characters:
                raise ValueError("truncated string cannot have a shorter total")
        return self


class XorAnchor(Model):
    catalog: Literal["lupabin-xor-cribs-v3"]
    crib: Annotated[str, Field(min_length=5, max_length=64)]
    crib_offset: NonNegative

    @model_validator(mode="after")
    def printable_crib(self) -> Self:
        if any(not 32 <= ord(char) <= 126 for char in self.crib):
            raise ValueError("crib outside the printable ASCII repertoire")
        return self


class DecodedStringEvidence(Model):
    id: EvidenceId
    source: Literal["decode"] = "decode"
    component: Literal["decode_strings", "decode_xor"]
    kind: Literal["decoded_string"] = "decoded_string"
    location: Location
    confidence: Literal["inferred"] = "inferred"
    provenance: Provenance = Field(default_factory=Provenance)
    transform: Transform
    anchor: XorAnchor | None = None
    data: DecodedStringData

    @model_validator(mode="after")
    def coherent_with_transform(self) -> Self:
        if self.location.offset is None or self.location.length is None:
            raise ValueError("a decoded string must locate its encoded bytes")
        if self.transform.name == "xor-repeating-v1":
            if self.component != "decode_xor" or self.anchor is None:
                raise ValueError("an XOR decoding belongs to decode_xor and needs its anchor")
            if len(self.provenance.evidence_ids) > 1:
                # empty: the anchor verified the key; one: the XOR decoding that
                # established the same key elsewhere (checked against the report)
                raise ValueError("an XOR decoding cites at most the decoding that set its key")
            if self.location.length != len(self.data.raw_hex) // 2:
                raise ValueError("XOR preserves length; region and decoded bytes must match")
            end = self.anchor.crib_offset + len(self.anchor.crib)
            if self.data.text[self.anchor.crib_offset : end] != self.anchor.crib:
                raise ValueError("the anchor crib is not at its declared offset")
        else:
            if self.component != "decode_strings" or self.anchor is not None:
                raise ValueError("a Base64/hex decoding belongs to decode_strings, without anchor")
            if len(self.provenance.evidence_ids) != 1:
                raise ValueError("a Base64/hex decoding derives from exactly one source string")
        return self


InstructionHex = Annotated[str, Field(pattern=r"^(?:[a-f0-9]{2}){1,15}$")]


class Instruction(Model):
    """An instruction a claim rests on: where it is in the file and in the image."""

    offset: NonNegative
    rva: UInt
    raw_hex: InstructionHex


class ApiCallData(Model):
    # Which canonical form (evidence/call_forms.py) reaches the import's slot. `tail` is
    # a `jmp [slot]` that ends a run of code (a tail call): the import returns to the
    # caller of the code that jumps.
    via: Literal["direct", "thunk", "register", "tail"]
    raw_hex: InstructionHex
    # The thunk's `jmp [slot]` or the `mov reg, [slot]` right before the call.
    helper: Instruction | None = None

    @model_validator(mode="after")
    def helper_matches_via(self) -> Self:
        if (self.via in ("direct", "tail")) != (self.helper is None):
            raise ValueError("only thunk and register calls rest on a helper instruction")
        return self


class ApiCallEvidence(Model):
    id: EvidenceId
    source: Literal["code"] = "code"
    component: Literal["api_calls"] = "api_calls"
    kind: Literal["api_call"] = "api_call"
    location: Location
    confidence: Literal["observed"] = "observed"
    provenance: Provenance = Field(default_factory=Provenance)
    data: ApiCallData

    @model_validator(mode="after")
    def locates_its_instruction(self) -> Self:
        where = self.location
        if where.offset is None or where.rva is None or where.length is None:
            raise ValueError("a call must locate its instruction in the file and the image")
        if where.length != len(self.data.raw_hex) // 2:
            raise ValueError("call location disagrees with its bytes")
        if len(self.provenance.evidence_ids) != 1:
            raise ValueError("a call cites exactly the import it reaches")
        helper = self.data.helper
        if self.data.via == "register" and helper is not None:
            if helper.rva + len(helper.raw_hex) // 2 != where.rva:
                raise ValueError("a register load must be the instruction right before the call")
        return self


class ArgumentString(Model):
    """The NUL-terminated string an argument points to, as the file holds it."""

    offset: NonNegative
    rva: UInt
    # the text's bytes followed by its terminator
    raw_hex: Annotated[str, Field(pattern=r"^(?:[a-f0-9]{2})+$", max_length=4100)]
    text: Annotated[str, Field(min_length=1, max_length=1024)]

    @model_validator(mode="after")
    def printable(self) -> Self:
        if any(not 32 <= ord(char) <= 126 for char in self.text):
            raise ValueError("unsupported string repertoire")
        return self


class CallArgumentData(Model):
    catalog: Literal["lupabin-api-semantics-v4"] = "lupabin-api-semantics-v4"
    # block-constant-v1: a register or a push; stack-slot-v1: an x64 stack slot
    method: Literal["block-constant-v1", "stack-slot-v1"] = "block-constant-v1"
    position: Annotated[int, Field(ge=0, le=15)]
    name: Annotated[str, Field(min_length=1, max_length=64)]
    type: Literal["hkey", "string", "integer"]
    # hkey: the value as set; integer: modulo the parameter's width; string: the
    # pointer as set (an address in x86, an RVA from a RIP-relative lea in x64)
    value: Annotated[int, Field(ge=0, le=0xFFFFFFFFFFFFFFFF)]
    raw_hex: InstructionHex  # the instruction that sets it (for a stack slot, the store)
    constant: Annotated[str, Field(max_length=64)] | None = None  # the predefined key
    string: ArgumentString | None = None
    # stack-slot-v1 only: the instruction that set the register the store copies
    source: Instruction | None = None

    @model_validator(mode="after")
    def shape_matches_type(self) -> Self:
        if self.source is not None and self.method != "stack-slot-v1":
            raise ValueError("only a stack slot copies a register set elsewhere")
        if (self.type == "hkey") != (self.constant is not None):
            raise ValueError("only a key argument names a predefined key")
        if (self.type == "string") != (self.string is not None):
            raise ValueError("only a string argument carries its string")
        return self


class CallArgumentEvidence(Model):
    id: EvidenceId
    source: Literal["code"] = "code"
    component: Literal["call_arguments"] = "call_arguments"
    kind: Literal["call_argument"] = "call_argument"
    location: Location  # the instruction that sets the argument
    confidence: Literal["inferred"] = "inferred"
    provenance: Provenance = Field(default_factory=Provenance)
    data: CallArgumentData

    @model_validator(mode="after")
    def locates_its_instruction(self) -> Self:
        where = self.location
        if where.offset is None or where.rva is None or where.length is None:
            raise ValueError("an argument must locate the instruction that sets it")
        if where.length != len(self.data.raw_hex) // 2:
            raise ValueError("argument location disagrees with its bytes")
        if len(self.provenance.evidence_ids) != 1:
            raise ValueError("an argument cites exactly the call it belongs to")
        return self


class CodeFunctionData(Model):
    """An x64 `.pdata` RUNTIME_FUNCTION entry: one contiguous range of one function,
    as the file declares it."""

    begin: UInt
    end: UInt
    unwind: UInt
    raw_hex: Annotated[str, Field(pattern=r"^[a-f0-9]{24}$")]  # the entry's 12 bytes

    @model_validator(mode="after")
    def decoded(self) -> Self:
        if struct.unpack("<III", bytes.fromhex(self.raw_hex)) != (
            self.begin,
            self.end,
            self.unwind,
        ):
            raise ValueError("a function range must be what its entry's bytes say")
        if self.begin >= self.end:
            raise ValueError("a function range must not be empty")
        return self


class CodeFunctionEvidence(Model):
    id: EvidenceId
    source: Literal["code"] = "code"
    component: Literal["api_calls"] = "api_calls"
    kind: Literal["code_function"] = "code_function"
    location: Location  # the .pdata entry
    confidence: Literal["observed"] = "observed"
    provenance: Provenance = Field(default_factory=Provenance)
    data: CodeFunctionData

    @model_validator(mode="after")
    def locates_its_entry(self) -> Self:
        where = self.location
        if where.offset is None or where.rva is None or where.length != 12:
            raise ValueError("a function range must locate its 12-byte .pdata entry")
        if self.provenance.evidence_ids:
            raise ValueError("a function range cites nothing but its own bytes")
        return self


class FrameSlot(Model):
    """A local variable: a displacement from the frame register."""

    frame: Literal["ebp", "rsp", "rbp"]
    displacement: Annotated[int, Field(ge=-(1 << 31), lt=1 << 31)]


class LocalLinkData(Model):
    """A call's parameter receives the address of a local variable (`phkResult`), and a
    later call passes that variable's value (`hKey`): the value the first call leaves
    there, if nothing in between changes it (the walk's rule)."""

    method: Literal["frame-slot-v1"] = "frame-slot-v1"
    slot: FrameSlot
    writer_position: Annotated[int, Field(ge=0, le=15)]
    writer_name: Annotated[str, Field(min_length=1, max_length=64)]
    reader_position: Annotated[int, Field(ge=0, le=15)]
    reader_name: Annotated[str, Field(min_length=1, max_length=64)]
    raw_hex: InstructionHex  # the instruction that passes the value to the reader
    address: Instruction  # the lea that takes the variable's address for the writer
    passes: Instruction  # the push or stack store that passes that address


class LocalLinkEvidence(Model):
    id: EvidenceId
    source: Literal["code"] = "code"
    component: Literal["call_arguments"] = "call_arguments"
    kind: Literal["local_link"] = "local_link"
    location: Location  # the instruction that passes the value to the reader
    confidence: Literal["inferred"] = "inferred"
    provenance: Provenance = Field(default_factory=Provenance)
    data: LocalLinkData

    @model_validator(mode="after")
    def locates_its_instruction(self) -> Self:
        where = self.location
        if where.offset is None or where.rva is None or where.length is None:
            raise ValueError("a link must locate the instruction that passes the value")
        if where.length != len(self.data.raw_hex) // 2:
            raise ValueError("link location disagrees with its bytes")
        if len(self.provenance.evidence_ids) != 2:
            raise ValueError("a link cites the call that writes and the call that reads")
        return self


class MainCallData(Model):
    """The direct call through which the compiler's startup enters `main`: its first
    three arguments are the values of the variables whose addresses a call to
    __getmainargs or __wgetmainargs (msvcrt.dll) received (evidence/main_forms.py)."""

    method: Literal["getmainargs-v1"] = "getmainargs-v1"
    raw_hex: InstructionHex  # the call rel32
    target: UInt  # the RVA of main
    # the instructions that pass &argc, &argv and &envp to __getmainargs, in that order
    setters: tuple[Instruction, Instruction, Instruction]
    # the instructions that load argc, argv and envp for main, in that order
    loads: tuple[Instruction, Instruction, Instruction]


class MainCallEvidence(Model):
    id: EvidenceId
    source: Literal["code"] = "code"
    component: Literal["main_function"] = "main_function"
    kind: Literal["main_call"] = "main_call"
    location: Location  # the call
    confidence: Literal["inferred"] = "inferred"
    provenance: Provenance = Field(default_factory=Provenance)
    data: MainCallData

    @model_validator(mode="after")
    def locates_its_call(self) -> Self:
        where = self.location
        if where.offset is None or where.rva is None or where.length != 5:
            raise ValueError("a main call locates its 5-byte call in the file and the image")
        if where.length != len(self.data.raw_hex) // 2:
            raise ValueError("main call location disagrees with its bytes")
        if len(self.provenance.evidence_ids) != 1:
            raise ValueError("a main call cites exactly the call to __getmainargs")
        return self


class CodeReachData(Model):
    """Published calls to imports that the walk reaches from one root, following only
    constant calls and jumps: from `main`, or from the entry point and the TLS callbacks
    without entering `main` and not from `main` (the startup)."""

    method: Literal["direct-reach-v1"] = "direct-reach-v1"
    root: Literal["main", "startup"]
    calls: Annotated[tuple[EvidenceId, ...], Field(max_length=4096)] = ()


class CodeReachEvidence(Model):
    id: EvidenceId
    source: Literal["code"] = "code"
    component: Literal["main_function"] = "main_function"
    kind: Literal["code_reach"] = "code_reach"
    location: None = None
    confidence: Literal["inferred"] = "inferred"
    provenance: Provenance = Field(default_factory=Provenance)
    data: CodeReachData

    @model_validator(mode="after")
    def cites_main(self) -> Self:
        if len(self.provenance.evidence_ids) != 1:
            raise ValueError("a reach cites exactly the main call it starts from")
        if len(set(self.data.calls)) != len(self.data.calls):
            raise ValueError("a reach lists each call once")
        return self


class AnomalyEvidence(Fact):
    kind: Literal["header_anomaly"] = "header_anomaly"
    data: AnomalyData


class ToolchainData(Model):
    """Bytes of the catalog's exact form of a marker that a compiler, linker or
    packager leaves in the file (evidence/toolchain.py)."""

    catalog: Literal["lupabin-toolchains-v1"] = "lupabin-toolchains-v1"
    marker: toolchain.Marker
    raw_hex: Annotated[str, Field(pattern=r"^(?:[a-f0-9]{2})+$", max_length=8192)]
    # what the bytes say: the GCC ident, the Go version, the CLR runtime version or the
    # Python library of a PyInstaller archive
    text: Annotated[str, Field(min_length=1, max_length=200)] | None = None

    @model_validator(mode="after")
    def exact_form(self) -> Self:
        if toolchain.marker_text(self.marker, bytes.fromhex(self.raw_hex)) != self.text:
            raise ValueError("marker text disagrees with its bytes")
        return self


class ToolchainEvidence(Fact):
    kind: Literal["toolchain_marker"] = "toolchain_marker"
    data: ToolchainData

    @model_validator(mode="after")
    def locates_its_bytes(self) -> Self:
        where = self.location
        if where.offset is None or where.length != len(self.data.raw_hex) // 2:
            raise ValueError("a marker locates exactly its bytes")
        if not toolchain.location_ok(self.data.marker, where):
            raise ValueError("only the Go and CLR headers claim a place in the image")
        if self.provenance.evidence_ids:
            raise ValueError("a marker cites nothing but its own bytes")
        return self


class YaraEvidence(Model):
    id: EvidenceId
    source: Literal["yara"] = "yara"
    component: Literal["yara_evidence"] = "yara_evidence"
    kind: Literal["yara_match"] = "yara_match"
    location: None = None
    confidence: Literal["observed"] = "observed"
    provenance: Provenance = Field(default_factory=Provenance)
    data: YaraMatchData

    @model_validator(mode="after")
    def no_invented_dependencies(self) -> Self:
        if self.provenance.evidence_ids:
            raise ValueError(
                "YARA matches cite byte instances and rule sources, not unrelated facts"
            )
        return self


Evidence = Annotated[
    ImportEvidence
    | HeaderEvidence
    | SectionEvidence
    | EntropyEvidence
    | ExportEvidence
    | StringEvidence
    | AnomalyEvidence
    | ToolchainEvidence
    | YaraEvidence
    | DecodedStringEvidence
    | ApiCallEvidence
    | CallArgumentEvidence
    | CodeFunctionEvidence
    | LocalLinkEvidence
    | MainCallEvidence
    | CodeReachEvidence,
    Field(discriminator="kind"),
]
Payload = (
    ImportData
    | HeaderData
    | SectionData
    | EntropyData
    | ExportData
    | StringData
    | AnomalyData
    | ToolchainData
    | YaraMatchData
    | DecodedStringData
    | ApiCallData
    | CallArgumentData
    | CodeFunctionData
    | LocalLinkData
    | MainCallData
    | CodeReachData
)
