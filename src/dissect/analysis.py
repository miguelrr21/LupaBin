from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Literal

from dissect.evidence.collector import Collector, Progress
from dissect.evidence.models import Analysis, Limits, Report, Sample
from dissect.extractors.base import Extraction, Extractor
from dissect.extractors.pe import PEExtractor
from dissect.extractors.strings import StringsExtractor
from dissect.ingest.reader import from_bytes


def utc_now() -> datetime:
    return datetime.now(UTC)


def analyze_bytes(
    data: bytes,
    limits: Limits | None = None,
    *,
    extractors: Sequence[Extractor] | None = None,
    clock: Callable[[], datetime] = utc_now,
) -> Report:
    effective = limits or Limits()
    started = clock()
    blob = from_bytes(data, effective)
    collector = Collector(effective)
    results = []
    for extractor in extractors if extractors is not None else (PEExtractor(), StringsExtractor()):
        progress = Progress(extractor.source, extractor.version)
        start_count = len(collector.facts)
        try:
            result = extractor.extract(blob.data, collector, progress)
        except Exception:
            for component, state in progress.states.items():
                if state != "complete":
                    progress.issue(
                        component, "extractor_failure", blocked=not progress.counts[component]
                    )
            if all(state == "complete" for state in progress.states.values()):
                progress.issue(next(iter(progress.states)), "extractor_failure")
            known_type: Literal["PE32", "PE32+", "unknown"] = "unknown"
            for fact in collector.facts[start_count:]:
                if fact.kind == "pe_header":
                    known_type = "PE32" if fact.data.optional_magic == 267 else "PE32+"
            result = Extraction(known_type, progress)
        progress.block_remaining("extractor_failure")
        results.append(result)
    known_types = {result.sample_type for result in results if result.sample_type != "unknown"}
    if len(known_types) > 1:
        raise ValueError("extractors disagree on sample format")
    sample = Sample.model_validate(
        {**blob.sample.model_dump(), "type": next(iter(known_types), "unknown")}
    )
    runs = tuple(result.progress.finish() for result in results)
    complete = all(run.status == "completed" for run in runs)
    failed = all(run.status == "failed" for run in runs)
    return Report(
        analysis=Analysis(
            started_at=started,
            finished_at=clock(),
            limits=effective,
            status="completed" if complete else "failed" if failed else "partial",
        ),
        sample=sample,
        evidence=tuple(collector.facts),
        extractor_runs=runs,
        extractor_errors=tuple(error for result in results for error in result.progress.errors),
        limitations=tuple(reason for result in results for reason in result.progress.limitations),
    )
