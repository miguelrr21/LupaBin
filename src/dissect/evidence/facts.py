from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from dissect.evidence.primitives import (
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
from dissect.evidence.yara import YaraMatchData


class ImportData(Model):
    dll: Name
    function: Name | None = None
    ordinal: Annotated[int, Field(ge=0, le=65535)] | None = None
    table: Literal["normal", "delay"]

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
    catalog: Literal["dissect-xor-cribs-v1"]
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
            if self.provenance.evidence_ids:
                raise ValueError("an XOR decoding derives from raw bytes, not from other facts")
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


class AnomalyEvidence(Fact):
    kind: Literal["header_anomaly"] = "header_anomaly"
    data: AnomalyData


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
    | YaraEvidence
    | DecodedStringEvidence,
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
    | YaraMatchData
    | DecodedStringData
)
