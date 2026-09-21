import heapq
import re
from collections.abc import Iterator
from typing import Literal

from dissect.evidence.collector import Collector, Progress
from dissect.evidence.facts import StringData
from dissect.evidence.primitives import COMPONENTS, Component, Location, Source
from dissect.extractors.base import Extraction

Candidate = tuple[int, Literal["ascii", "utf-16-le"], int]


def ascii_runs(data: bytes) -> Iterator[Candidate]:
    for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
        yield match.start(), "ascii", match.end()


def utf16_runs(data: bytes, alignment: int) -> Iterator[Candidate]:
    start = alignment
    position = alignment
    while position + 1 < len(data):
        if 32 <= data[position] <= 126 and data[position + 1] == 0:
            position += 2
            continue
        if position - start >= 8:
            yield start, "utf-16-le", position
        position += 2
        start = position
    if position - start >= 8:
        yield start, "utf-16-le", position


class StringsExtractor:
    source: Source = "strings"
    version = "ascii-printable-v1"

    def extract(self, data: bytes, collector: Collector, progress: Progress) -> Extraction:
        candidates = heapq.merge(ascii_runs(data), utf16_runs(data, 0), utf16_runs(data, 1))
        for offset, encoding, end in candidates:
            component: Component = "ascii" if encoding == "ascii" else "utf16le"
            progress.examined[component] += 1
            if collector.counts["string"] >= collector.limits.strings:
                for name in COMPONENTS["strings"]:
                    progress.issue(name, "string_limit", limit=True)
                break
            width = 1 if encoding == "ascii" else 2
            characters = (end - offset) // width
            returned = min(characters, collector.limits.string_characters)
            raw = data[offset : offset + returned * width]
            complete = characters == returned
            if not complete:
                progress.issue(component, "string_length_limit", limit=True)
            payload = StringData(
                encoding=encoding,
                text=raw.decode(encoding),
                raw_hex=raw.hex(),
                characters=returned,
                total_characters=characters,
                complete=complete,
            )
            if not collector.add(
                f"strings:{offset}:{encoding}",
                progress,
                component,
                payload,
                Location(offset=offset, length=len(raw)),
            ):
                for name in COMPONENTS["strings"]:
                    progress.issue(name, "evidence_budget", limit=True)
                break
        progress.complete("ascii")
        progress.complete("utf16le")
        return Extraction("unknown", progress)
