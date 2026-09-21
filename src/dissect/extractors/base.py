from dataclasses import dataclass
from typing import Literal, Protocol

from dissect.evidence.collector import Collector, Progress
from dissect.evidence.primitives import Source


@dataclass(frozen=True)
class Extraction:
    sample_type: Literal["PE32", "PE32+", "unknown"]
    progress: Progress


class Extractor(Protocol):
    source: Source
    version: str

    def extract(self, data: bytes, collector: Collector, progress: Progress) -> Extraction: ...
