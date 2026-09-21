from dataclasses import dataclass
from typing import Literal, Protocol

from dissect.evidence.models import ExtractorError, ImportData, Limits, Location, Run


@dataclass(frozen=True)
class Finding:
    source: str
    data: ImportData
    location: Location


@dataclass(frozen=True)
class Extraction:
    sample_type: Literal["PE32", "PE32+", "unknown"]
    findings: tuple[Finding, ...]
    run: Run
    errors: tuple[ExtractorError, ...] = ()


class Extractor(Protocol):
    source: str
    version: str

    def extract(self, data: bytes, limits: Limits) -> Extraction: ...
