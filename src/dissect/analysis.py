from collections.abc import Callable, Sequence
from datetime import UTC, datetime

from dissect.evidence.models import Analysis, Evidence, ExtractorError, Limits, Report, Run, Sample
from dissect.extractors.base import Extraction, Extractor
from dissect.extractors.pe import PEExtractor
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
    results = []
    for extractor in extractors if extractors is not None else (PEExtractor(),):
        try:
            result = extractor.extract(blob.data, effective)
        except Exception:
            result = Extraction(
                "unknown",
                (),
                Run(source=extractor.source, version=extractor.version, status="failed"),
                (ExtractorError(source=extractor.source, code="extractor_failure"),),
            )
        results.append(result)
    findings = sorted(
        (finding for result in results for finding in result.findings),
        key=lambda item: (
            item.source,
            item.data.model_dump_json(),
            item.location.model_dump_json(),
        ),
    )
    evidence = tuple(
        Evidence(id=f"E{index}", source=item.source, data=item.data, location=item.location)
        for index, item in enumerate(findings, 1)
    )
    known_types = {result.sample_type for result in results if result.sample_type != "unknown"}
    if len(known_types) > 1:
        raise ValueError("extractors disagree on sample format")
    sample = Sample.model_validate(
        {**blob.sample.model_dump(), "type": next(iter(known_types), "unknown")}
    )
    complete = all(result.run.status == "completed" for result in results)
    return Report(
        analysis=Analysis(
            started_at=started,
            finished_at=clock(),
            limits=effective,
            status="completed" if complete else "partial" if evidence else "failed",
        ),
        sample=sample,
        evidence=evidence,
        extractor_runs=tuple(result.run for result in results),
        extractor_errors=tuple(error for result in results for error in result.errors),
    )
