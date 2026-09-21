from collections import deque
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from dissect import __version__

NonNegative = Annotated[int, Field(ge=0)]
EvidenceId = Annotated[str, Field(pattern=r"^E[1-9][0-9]*$", max_length=16)]
Source = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=32)]
Status = Literal["completed", "partial", "failed"]
Coverage = Literal["complete", "partial", "not_attempted"]
ErrorCode = Literal[
    "invalid_pe",
    "unsupported_format",
    "timeout",
    "resource_limit",
    "output_limit",
    "extractor_failure",
    "parser_warning",
    "import_limit",
    "invalid_import_table",
]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Limits(Model):
    input_bytes: Annotated[int, Field(gt=0, le=20 * 1024 * 1024)] = 20 * 1024 * 1024
    timeout_seconds: Annotated[int, Field(gt=0, le=30)] = 30
    memory_bytes: Literal[536870912] = 536870912
    cpus: Literal[1] = 1
    pids: Literal[64] = 64
    output_bytes: Annotated[int, Field(gt=0, le=8 * 1024 * 1024)] = 8 * 1024 * 1024
    imports: Annotated[int, Field(gt=0, le=10000)] = 10000


class Analysis(Model):
    version: Literal["0.1.0"] = __version__
    started_at: AwareDatetime
    finished_at: AwareDatetime
    status: Status
    limits: Limits = Field(default_factory=Limits)

    @model_validator(mode="after")
    def chronological(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("analysis end precedes start")
        return self


class Sample(Model):
    sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    md5: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
    size: Annotated[int, Field(gt=0, le=20 * 1024 * 1024)]
    type: Literal["PE32", "PE32+", "unknown"]


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
        raw = bytes.fromhex(self.raw_hex)
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            text = None
        if self.text != text:
            raise ValueError("text does not match original bytes")
        return self


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


class Location(Model):
    offset: NonNegative | None = None
    rva: NonNegative | None = None
    length: Annotated[int, Field(gt=0)] | None = None
    section: Name | None = None

    @model_validator(mode="after")
    def length_has_offset(self) -> Self:
        if self.length is not None and self.offset is None:
            raise ValueError("length requires a file offset")
        return self


class Provenance(Model):
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(max_length=32)] = ()


class Evidence(Model):
    id: EvidenceId
    kind: Literal["import"] = "import"
    source: Source
    data: ImportData
    location: Location = Field(default_factory=Location)
    confidence: Literal["observed"] = "observed"
    provenance: Provenance = Field(default_factory=Provenance)


class Run(Model):
    source: Source
    version: Annotated[str, Field(min_length=1, max_length=64)]
    status: Literal["completed", "partial", "failed", "not_applicable"]
    normal: Coverage = "not_attempted"
    delay: Coverage = "not_attempted"

    @model_validator(mode="after")
    def coverage_matches_status(self) -> Self:
        if self.status == "completed" and (self.normal, self.delay) != ("complete", "complete"):
            raise ValueError("completed extraction requires complete coverage")
        return self


class ExtractorError(Model):
    source: Source
    code: ErrorCode


class Report(Model):
    schema_version: Literal["0.1.0"] = "0.1.0"
    analysis: Analysis
    sample: Sample
    evidence: Annotated[tuple[Evidence, ...], Field(max_length=10000)] = ()
    extractor_runs: Annotated[tuple[Run, ...], Field(min_length=1, max_length=32)]
    extractor_errors: Annotated[tuple[ExtractorError, ...], Field(max_length=128)] = ()

    @model_validator(mode="after")
    def consistent(self) -> Self:
        runs = {run.source: run for run in self.extractor_runs}
        facts = {fact.id: fact for fact in self.evidence}
        if len(runs) != len(self.extractor_runs) or len(facts) != len(self.evidence):
            raise ValueError("duplicate source or evidence ID")
        if self.sample.size > self.analysis.limits.input_bytes:
            raise ValueError("sample exceeds effective size limit")
        if len(self.evidence) > self.analysis.limits.imports:
            raise ValueError("evidence exceeds effective import limit")
        error_sources = {error.source for error in self.extractor_errors}
        if not error_sources <= runs.keys():
            raise ValueError("error has unknown source")
        for run in runs.values():
            if (run.status != "completed") != (run.source in error_sources):
                raise ValueError("extraction status and errors disagree")
        complete = all(run.status == "completed" for run in runs.values())
        expected = "completed" if complete else "partial" if self.evidence else "failed"
        if self.analysis.status != expected:
            raise ValueError("global status disagrees with extraction results")
        if self.sample.type == "unknown" and (complete or self.evidence):
            raise ValueError("unknown format cannot have completed PE evidence")
        degrees = {}
        children: dict[str, list[str]] = {key: [] for key in facts}
        for fact in self.evidence:
            if fact.source not in runs or runs[fact.source].status not in ("completed", "partial"):
                raise ValueError("evidence has no successful or partial source")
            location = fact.location
            if location.offset is not None:
                if location.offset + (location.length or 1) > self.sample.size:
                    raise ValueError("evidence location exceeds sample bounds")
            refs = fact.provenance.evidence_ids
            if len(refs) != len(set(refs)) or not set(refs) <= facts.keys():
                raise ValueError("duplicate or missing provenance reference")
            degrees[fact.id] = len(refs)
            for ref in refs:
                children[ref].append(fact.id)
        ready = deque(key for key, degree in degrees.items() if degree == 0)
        visited = 0
        while ready:
            key = ready.popleft()
            visited += 1
            for child in children[key]:
                degrees[child] -= 1
                if degrees[child] == 0:
                    ready.append(child)
        if visited != len(facts):
            raise ValueError("cyclic provenance")
        return self
