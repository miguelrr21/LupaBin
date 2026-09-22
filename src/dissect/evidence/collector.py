from collections import Counter

from pydantic import TypeAdapter

from dissect.evidence.facts import (
    AnomalyData,
    EntropyData,
    Evidence,
    ExportData,
    HeaderData,
    ImportData,
    Payload,
    SectionData,
    StringData,
)
from dissect.evidence.models import (
    ComponentRun,
    Coverage,
    ErrorCode,
    ExtractorError,
    Run,
    aggregate,
)
from dissect.evidence.primitives import COMPONENTS, Component, Limits, Location, Provenance, Source
from dissect.evidence.yara import YaraContext, YaraMatchData

ADAPTER: TypeAdapter[Evidence] = TypeAdapter(Evidence)
KINDS = {
    ImportData: "import",
    HeaderData: "pe_header",
    SectionData: "section",
    EntropyData: "entropy",
    ExportData: "export",
    StringData: "string",
    AnomalyData: "header_anomaly",
    YaraMatchData: "yara_match",
}


class Progress:
    def __init__(self, source: Source, version: str):
        self.source = source
        self.version = version
        self.states: dict[Component, Coverage] = {name: "blocked" for name in COMPONENTS[source]}
        self.examined: Counter[Component] = Counter()
        self.unknown_examined: set[Component] = (
            set(COMPONENTS[source]) if source == "yara" else set()
        )
        self.yara_context: YaraContext | None = YaraContext() if source == "yara" else None
        self.counts: Counter[Component] = Counter()
        self.errors: list[ExtractorError] = []
        self.limitations: list[ExtractorError] = []

    def issue(
        self, component: Component, code: ErrorCode, *, limit: bool = False, blocked: bool = False
    ) -> None:
        reason = ExtractorError(source=self.source, component=component, code=code)
        target = self.limitations if limit else self.errors
        if reason not in target:
            target.append(reason)
        self.states[component] = "blocked" if blocked and not self.counts[component] else "partial"

    def complete(self, component: Component) -> None:
        if not any(r.component == component for r in self.errors + self.limitations):
            self.states[component] = "complete"

    def block_remaining(self, code: ErrorCode) -> None:
        for component, state in self.states.items():
            if state == "blocked" and not any(
                reason.component == component for reason in self.errors + self.limitations
            ):
                self.issue(component, code, blocked=True)

    def finish(self) -> Run:
        parts = tuple(
            ComponentRun(
                name=name,
                status=self.states[name],
                examined=None if name in self.unknown_examined else self.examined[name],
                evidence_count=self.counts[name],
            )
            for name in COMPONENTS[self.source]
        )
        return Run(
            source=self.source,
            version=self.version,
            status=aggregate(tuple(part.status for part in parts)),
            components=parts,
            evidence_count=sum(self.counts.values()),
        )


class Collector:
    def __init__(self, limits: Limits):
        self.limits = limits
        self.facts: list[Evidence] = []
        self.ids: dict[str, str] = {}
        self.counts: Counter[str] = Counter()
        self.used_bytes = 0
        self.quotas = {
            "pe_header": 1,
            "section": limits.sections,
            "entropy": limits.sections,
            "import": limits.imports,
            "export": limits.exports,
            "header_anomaly": limits.anomalies,
            "string": limits.strings,
            "yara_match": limits.yara.matches,
        }

    def add(
        self,
        key: str,
        progress: Progress,
        component: Component,
        data: Payload,
        location: Location | None,
        refs: tuple[str, ...] = (),
    ) -> bool:
        if key in self.ids:
            raise ValueError("duplicate internal fact key")
        kind = KINDS[type(data)]
        if any(ref not in self.ids for ref in refs):
            progress.issue(component, "dependency_omitted", limit=True)
            return False
        if self.counts[kind] >= self.quotas[kind]:
            codes: dict[str, ErrorCode] = {
                "import": "import_limit",
                "export": "export_limit",
                "string": "string_limit",
                "header_anomaly": "anomaly_limit",
                "yara_match": "yara_match_limit",
            }
            progress.issue(component, codes.get(kind, "evidence_budget"), limit=True)
            return False
        fact = ADAPTER.validate_python(
            {
                "id": f"E{len(self.facts) + 1}",
                "kind": kind,
                "source": progress.source,
                "component": component,
                "data": data,
                "location": location,
                "provenance": Provenance(evidence_ids=tuple(self.ids[ref] for ref in refs)),
            }
        )
        size = len(fact.model_dump_json().encode("utf-8")) + 1
        if self.used_bytes + size > self.limits.evidence_bytes:
            progress.issue(component, "evidence_budget", limit=True)
            return False
        self.used_bytes += size
        self.ids[key] = fact.id
        self.facts.append(fact)
        self.counts[kind] += 1
        progress.counts[component] += 1
        return True
