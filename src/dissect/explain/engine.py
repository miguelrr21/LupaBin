"""Build explanations from a validated report, and validate them by regeneration."""

from collections.abc import Iterator

from dissect.evidence.facts import (
    AnomalyEvidence,
    DecodedStringEvidence,
    EntropyEvidence,
    Evidence,
    ExportEvidence,
    HeaderEvidence,
    ImportEvidence,
    SectionEvidence,
    StringEvidence,
    YaraEvidence,
)
from dissect.evidence.models import Report
from dissect.explain.models import Explanation, Item, Note, ReportRef
from dissect.explain.rules import RULES
from dissect.explain.text import COMPONENTS, MESSAGES, SOURCES, STATUSES
from dissect.glossary.catalog import Glossary

RUN_STATUS = {"completed": "completo", "partial": "parcial", "failed": "fallido"}


class ExplanationError(ValueError):
    pass


def notes(report: Report) -> tuple[Note, ...]:
    """Coverage first: every run, every incomplete component, every error and limit."""
    result = []
    for run in report.extractor_runs:
        label = SOURCES[run.source]
        result.append(
            Note(
                rule="run.status@1",
                source=run.source,
                statement=f"{label}: análisis {RUN_STATUS[run.status]}.",
                glossary_ids=("analysis.coverage",),
            )
        )
        for part in run.components:
            if part.status != "complete":
                result.append(
                    Note(
                        rule="component.status@1",
                        source=run.source,
                        component=part.name,
                        statement=f"{label}, {COMPONENTS[part.name]}: {STATUSES[part.status]}.",
                        glossary_ids=("analysis.coverage",),
                    )
                )
        for issue in (*report.extractor_errors, *report.limitations):
            if issue.source == run.source:
                result.append(
                    Note(
                        rule="issue@1",
                        source=issue.source,
                        component=issue.component,
                        code=issue.code,
                        statement=f"{label}, {COMPONENTS[issue.component]}: {MESSAGES[issue.code]}",
                        glossary_ids=("analysis.coverage",),
                    )
                )
    return tuple(result)


def _citations(report: Report) -> Iterator[tuple[str, tuple[Evidence, ...]]]:
    """(rule, cited evidence) in a fixed didactic order, covering every fact."""
    facts = {fact.id: fact for fact in report.evidence}
    evidence = report.evidence
    for fact in evidence:
        if isinstance(fact, HeaderEvidence):
            yield "pe.header@1", (fact,)
    for fact in evidence:
        if isinstance(fact, SectionEvidence):
            yield "pe.section@1", (fact,)
            if {"write", "execute"} <= set(fact.data.permissions):
                yield "pe.section.writable_executable@1", (fact,)
    for fact in evidence:
        if isinstance(fact, EntropyEvidence):
            yield "entropy.value@1", (fact, *(facts[r] for r in fact.provenance.evidence_ids))
    for fact in evidence:
        if isinstance(fact, AnomalyEvidence):
            refs = tuple(facts[r] for r in fact.provenance.evidence_ids)
            yield f"anomaly.{fact.data.code}@1", (fact, *refs)
    groups: dict[tuple[str, str], list[Evidence]] = {}
    for fact in evidence:
        if isinstance(fact, ImportEvidence):
            groups.setdefault((fact.data.dll.raw_hex, fact.data.table), []).append(fact)
    for group in groups.values():
        yield "imports.dll@1", tuple(group)
    exports = tuple(fact for fact in evidence if isinstance(fact, ExportEvidence))
    if exports:
        yield "exports.table@1", exports
    strings = tuple(fact for fact in evidence if isinstance(fact, StringEvidence))
    if strings:
        yield "strings.summary@1", strings
    for fact in evidence:
        if isinstance(fact, YaraEvidence):
            yield "yara.match@1", (fact,)
    for fact in evidence:
        if isinstance(fact, DecodedStringEvidence):
            refs = tuple(facts[r] for r in fact.provenance.evidence_ids)
            if fact.transform.name == "xor-repeating-v1":
                yield ("decoded.xor_reused@1" if refs else "decoded.xor@1"), (fact, *refs)
            else:
                rule = (
                    "decoded.base64@1"
                    if fact.transform.name == "base64-strict-v1"
                    else ("decoded.hex@1")
                )
                yield rule, (fact, *refs)


def _item(number: int, rule_id: str, cited: tuple[Evidence, ...], report: Report) -> Item | None:
    rule = RULES.get(rule_id)
    if rule is None:
        return None
    derived = rule.derive(cited, report)
    if derived is None:
        return None
    slots, glossary_ids = derived
    return Item(
        id=f"X{number}",
        rule=rule_id,
        level="inferred" if any(f.confidence == "inferred" for f in cited) else "observed",
        statement=rule.statement(slots),
        slots=slots,
        evidence_ids=tuple(fact.id for fact in cited),
        glossary_ids=glossary_ids,
        not_proven=rule.not_proven,
    )


def explain(report: Report, glossary: Glossary) -> Explanation:
    items: list[Item] = []
    for rule_id, cited in _citations(report):
        item = _item(len(items) + 1, rule_id, cited, report)
        if item is None:
            raise ExplanationError(f"rule {rule_id} does not apply to what it was given")
        items.append(item)
    explanation = Explanation(
        report=ReportRef(sample_sha256=report.sample.sha256, schema_version=report.schema_version),
        glossary=glossary.info,
        status=report.analysis.status,
        notes=notes(report),
        items=tuple(items),
    )
    validate(explanation, report, glossary)
    return explanation


def check_item(item: Item, report: Report, glossary: Glossary) -> str | None:
    """None if the item is exactly what its rule derives from its citations."""
    facts = {fact.id: fact for fact in report.evidence}
    if any(ref not in facts for ref in item.evidence_ids):
        return f"{item.id} cites evidence that is not in the report"
    number = int(item.id[1:])
    expected = _item(number, item.rule, tuple(facts[ref] for ref in item.evidence_ids), report)
    if expected is None:
        return f"{item.id}: rule {item.rule} is unknown or does not hold for its citations"
    if item != expected:
        return f"{item.id} differs from what {item.rule} derives from its citations"
    missing = [ref for ref in item.glossary_ids if ref not in glossary.entries]
    if missing:
        return f"{item.id} links unknown glossary entries: {missing}"
    return None


def validate(explanation: Explanation, report: Report, glossary: Glossary) -> tuple[Item, ...]:
    """Raise on document-level problems; return the items that regenerate exactly."""
    if explanation.report != ReportRef(
        sample_sha256=report.sample.sha256, schema_version=report.schema_version
    ):
        raise ExplanationError("the explanation belongs to another report")
    if explanation.glossary != glossary.info:
        raise ExplanationError("the explanation was built with another glossary")
    if explanation.status != report.analysis.status:
        raise ExplanationError("the explanation misstates the analysis status")
    if explanation.notes != notes(report):
        raise ExplanationError("coverage notes are missing, extra or altered")
    for note in explanation.notes:
        if any(ref not in glossary.entries for ref in note.glossary_ids):
            raise ExplanationError("a note links an unknown glossary entry")
    cited = {ref for item in explanation.items for ref in item.evidence_ids}
    if any(fact.id not in cited for fact in report.evidence):
        raise ExplanationError("some evidence is not explained")
    return tuple(item for item in explanation.items if check_item(item, report, glossary) is None)
