from collections import Counter, deque
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from dissect.evidence.facts import Evidence as Evidence
from dissect.evidence.facts import ImportData as ImportData
from dissect.evidence.primitives import (
    COMPONENTS,
    Component,
    Model,
    NonNegative,
    Source,
    Status,
)
from dissect.evidence.primitives import Limits as Limits
from dissect.evidence.primitives import Location as Location
from dissect.evidence.primitives import Name as Name
from dissect.evidence.relations import validate_anomaly
from dissect.evidence.yara import YaraContext, YaraReason, validate_matches

Coverage = Literal["complete", "partial", "blocked"]
ErrorCode = (
    Literal[
        "invalid_pe",
        "unsupported_format",
        "extractor_failure",
        "parser_warning",
        "invalid_import_table",
        "invalid_export_table",
        "invalid_section_table",
        "unsafe_mapping",
        "import_limit",
        "descriptor_limit",
        "export_limit",
        "export_name_limit",
        "section_limit",
        "string_limit",
        "string_length_limit",
        "entropy_limit",
        "anomaly_limit",
        "evidence_budget",
        "dependency_omitted",
        "output_limit",
    ]
    | YaraReason
)


class Analysis(Model):
    version: Literal["0.3.0"] = "0.3.0"
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
    size: Annotated[int, Field(gt=0, le=20971520)]
    type: Literal["PE32", "PE32+", "unknown"]


class ComponentRun(Model):
    name: Component
    status: Coverage
    examined: NonNegative | None = 0
    evidence_count: NonNegative = 0


def aggregate(states: tuple[Coverage, ...]) -> Status:
    return (
        "completed"
        if all(s == "complete" for s in states)
        else ("failed" if all(s == "blocked" for s in states) else "partial")
    )


class Run(Model):
    source: Source
    version: Annotated[str, Field(min_length=1, max_length=64)]
    status: Status
    components: Annotated[tuple[ComponentRun, ...], Field(max_length=7)]
    evidence_count: NonNegative

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if tuple(part.name for part in self.components) != COMPONENTS[self.source]:
            raise ValueError("unexpected component coverage")
        if self.status != aggregate(tuple(part.status for part in self.components)):
            raise ValueError("extractor status disagrees with coverage")
        if any(
            part.examined is None and (self.source != "yara" or part.status == "complete")
            for part in self.components
        ):
            raise ValueError("unknown examined count is only valid for incomplete YARA components")
        if self.evidence_count != sum(part.evidence_count for part in self.components):
            raise ValueError("extractor evidence count disagrees with components")
        return self


class ExtractorError(Model):
    source: Source
    component: Component
    code: ErrorCode


class Report(Model):
    schema_version: Literal["0.3.0"] = "0.3.0"
    analysis: Analysis
    sample: Sample
    evidence: Annotated[tuple[Evidence, ...], Field(max_length=20353)] = ()
    extractor_runs: Annotated[tuple[Run, ...], Field(min_length=1, max_length=3)]
    yara_context: YaraContext | None = None
    extractor_errors: Annotated[tuple[ExtractorError, ...], Field(max_length=128)] = ()
    limitations: Annotated[tuple[ExtractorError, ...], Field(max_length=128)] = ()

    @model_validator(mode="after")
    def consistent(self) -> Self:
        runs = {run.source: run for run in self.extractor_runs}
        facts = {fact.id: fact for fact in self.evidence}
        if len(runs) != len(self.extractor_runs) or len(facts) != len(self.evidence):
            raise ValueError("duplicate source or evidence ID")
        limits = self.analysis.limits
        if self.sample.size > limits.input_bytes:
            raise ValueError("sample exceeds effective size limit")
        counts: Counter[str] = Counter(fact.kind for fact in self.evidence)
        quotas = {
            "import": limits.imports,
            "pe_header": 1,
            "section": limits.sections,
            "entropy": limits.sections,
            "export": limits.exports,
            "string": limits.strings,
            "header_anomaly": limits.anomalies,
            "yara_match": limits.yara.matches,
        }
        if any(counts[kind] > limit for kind, limit in quotas.items()):
            raise ValueError("evidence exceeds effective quota")
        reasons = self.extractor_errors + self.limitations
        reason_parts = {(reason.source, reason.component) for reason in reasons}
        for reason in reasons:
            if reason.source not in runs or reason.component not in COMPONENTS[reason.source]:
                raise ValueError("reason has unknown source or component")
        for run in runs.values():
            for part in run.components:
                if (part.status != "complete") != ((run.source, part.name) in reason_parts):
                    raise ValueError("component status and reasons disagree")
                actual = sum(
                    f.source == run.source and f.component == part.name for f in self.evidence
                )
                if actual != part.evidence_count or (part.status == "blocked" and actual):
                    raise ValueError("component count disagrees with evidence")
        statuses = [run.status for run in runs.values()]
        expected = (
            "completed"
            if all(s == "completed" for s in statuses)
            else ("failed" if all(s == "failed" for s in statuses) else "partial")
        )
        if self.analysis.status != expected:
            raise ValueError("global status disagrees with coverage")
        if ("yara" in runs) != (self.yara_context is not None):
            raise ValueError("YARA coverage requires its own context")
        yara_matches = tuple(fact.data for fact in self.evidence if fact.kind == "yara_match")
        if self.yara_context is not None:
            context = self.yara_context
            if runs["yara"].status == "completed" and (
                context.catalog is None
                or context.package_version is None
                or context.module_version is None
            ):
                raise ValueError("completed YARA scan requires observed catalog and versions")
            parts: dict[str, ComponentRun] = {part.name: part for part in runs["yara"].components}
            if context.catalog is not None:
                if len(context.catalog.rules) > limits.yara.rules:
                    raise ValueError("catalog exceeds rule quota")
                for name in ("yara_rules", "yara_scan"):
                    part = parts[name]
                    if part.status == "complete" and part.examined != len(context.catalog.rules):
                        raise ValueError("complete YARA coverage disagrees with catalog size")
                validate_matches(yara_matches, context, self.sample.size, limits.yara)
            elif yara_matches or parts["yara_rules"].status == "complete":
                raise ValueError("YARA evidence or compiled rules cannot lack a catalog")
            if yara_matches and any(
                parts[name].status != "complete" for name in ("yara_rules", "yara_scan")
            ):
                raise ValueError("interrupted YARA scans cannot publish matches")
            if parts["yara_evidence"].status == "complete":
                if any(match.instances_status != "complete" for match in yara_matches):
                    raise ValueError("limited YARA instances cannot claim complete coverage")
                if parts["yara_evidence"].examined != len(yara_matches):
                    raise ValueError("complete YARA reporting disagrees with retained matches")
        degrees: dict[str, int] = {}
        children: dict[str, list[str]] = {key: [] for key in facts}
        for fact in self.evidence:
            if fact.source not in runs or runs[fact.source].status == "failed":
                raise ValueError("evidence has no successful or partial source")
            if fact.kind == "yara_match":
                degrees[fact.id] = 0
                continue
            if fact.source != ("strings" if fact.kind == "string" else "pe"):
                raise ValueError("evidence source disagrees with kind")
            expected_component = {
                "pe_header": "headers",
                "section": "sections",
                "entropy": "entropy",
                "export": "exports",
                "header_anomaly": "anomalies",
            }.get(fact.kind)
            if fact.kind == "import":
                expected_component = "imports_" + fact.data.table
            if fact.kind == "string":
                expected_component = "ascii" if fact.data.encoding == "ascii" else "utf16le"
                if fact.location.length != len(bytes.fromhex(fact.data.raw_hex)):
                    raise ValueError("string location disagrees with bytes")
                if fact.data.characters > limits.string_characters:
                    raise ValueError("string exceeds character limit")
                if fact.location.rva is not None or fact.location.section is not None:
                    raise ValueError("strings do not claim a PE mapping")
            elif self.sample.type == "unknown":
                raise ValueError("unknown format cannot have PE evidence")
            if fact.component != expected_component:
                raise ValueError("evidence component disagrees with kind")
            location = fact.location
            if location.offset is None or location.length is None:
                raise ValueError("observed evidence requires an exact byte span")
            if location.offset + location.length > self.sample.size:
                raise ValueError("evidence location exceeds sample bounds")
            refs = fact.provenance.evidence_ids
            if len(refs) != len(set(refs)) or not set(refs) <= facts.keys():
                raise ValueError("duplicate or missing provenance reference")
            if fact.kind == "pe_header":
                expected_type = "PE32" if fact.data.optional_magic == 267 else "PE32+"
                if self.sample.type != expected_type:
                    raise ValueError("sample type disagrees with observed header")
            if fact.kind == "section":
                raw = fact.data
                status = (
                    "empty"
                    if raw.raw_size == 0
                    else (
                        "present"
                        if raw.raw_offset + raw.raw_size <= self.sample.size
                        else "out_of_bounds"
                    )
                )
                if raw.raw_status != status:
                    raise ValueError("section range validation is inconsistent")
            if fact.kind == "entropy":
                if len(refs) != 1 or facts[refs[0]].kind != "section":
                    raise ValueError("entropy requires one section reference")
                section = facts[refs[0]]
                if section.kind == "section" and (
                    section.data.raw_status != "present"
                    or fact.location.offset != section.data.raw_offset
                    or fact.location.length != section.data.raw_size
                    or fact.data.byte_count != section.data.raw_size
                ):
                    raise ValueError("entropy span disagrees with section")
            if fact.kind == "header_anomaly":
                if not refs or any(facts[ref].kind not in ("pe_header", "section") for ref in refs):
                    raise ValueError("anomaly requires structural evidence")
                validate_anomaly(fact, facts)
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
        if (
            sum(f.data.byte_count for f in self.evidence if f.kind == "entropy")
            > limits.entropy_bytes
        ):
            raise ValueError("entropy exceeds byte budget")
        return self
