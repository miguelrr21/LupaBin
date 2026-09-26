"""Reproduce the measurements of toolchain markers on benign binaries.

    uv run python -m tests.toolchain_eval corpus DIR [DIR ...] [--recursive]
        [--ext .exe,.dll,.sys] [--stride N] [--limit N] [--out markers.jsonl]

`corpus` treats every file as benign and runs the PE extractor on it, then the host
checks of every marker against the file's bytes and the explanation engine, which
regenerates every item. It counts the binaries with each marker and each combination
of markers, and any report, check or explanation that fails. `--out` writes the
markers of every binary, one per line, so that each one can be compared by hand with
what the binary is: a marker on a binary its tool did not produce is a false positive.
Files are only read as bytes: nothing is executed, and they never enter the
repository. Not part of the package or of CI.
"""

import argparse
import json
import time
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

from lupabin.analysis import analyze_bytes
from lupabin.evidence.facts import ToolchainEvidence
from lupabin.evidence.models import Limits
from lupabin.evidence.toolchain_checks import verify_markers
from lupabin.explain.engine import explain, validate
from lupabin.extractors.pe import PEExtractor
from lupabin.glossary.catalog import load_glossary

MAX_INPUT = 20 * 1024 * 1024
GLOSSARY = load_glossary()


def files(roots: list[Path], recursive: bool, ext: tuple[str, ...], stride: int) -> Iterator[Path]:
    for root in roots:
        found = sorted(root.rglob("*") if recursive else root.iterdir())
        chosen = [p for p in found if p.suffix.lower() in ext and p.is_file()]
        yield from chosen[::stride]


def corpus(args: argparse.Namespace) -> None:
    ext = tuple(item.strip().lower() for item in args.ext.split(","))
    counts: Counter[str] = Counter()
    combinations: Counter[str] = Counter()
    started = time.monotonic()
    out = open(args.out, "w", encoding="utf-8") if args.out else None  # noqa: SIM115
    try:
        for path in files([Path(d) for d in args.dirs], args.recursive, ext, args.stride):
            if args.limit and counts["pe"] >= args.limit:
                break
            try:
                if path.stat().st_size > MAX_INPUT:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            if data[:2] != b"MZ":
                continue
            try:
                report = analyze_bytes(data, Limits(), extractors=[PEExtractor()])
            except Exception:  # noqa: BLE001
                counts["report_failures"] += 1
                continue
            if report.sample.type == "unknown":
                continue
            counts["pe"] += 1
            markers = [f for f in report.evidence if isinstance(f, ToolchainEvidence)]
            try:
                verify_markers(report.evidence, data)
            except ValueError:
                counts["verify_failures"] += 1
            items = validate(explain(report, GLOSSARY), report, GLOSSARY)
            explained = sum(item.rule.startswith("toolchain.") for item in items)
            if explained != len({(f.data.marker) for f in markers}):
                counts["explanation_failures"] += 1
            part = next(p for p in report.extractor_runs[0].components if p.name == "toolchain")
            counts[f"coverage_{part.status}"] += 1
            kinds = sorted({fact.data.marker for fact in markers})
            for kind in kinds:
                counts[kind] += 1
            combinations["+".join(kinds) or "(none)"] += 1
            if out is not None:
                row = {
                    "path": str(path),
                    "markers": [(f.data.marker, f.data.text) for f in markers],
                }
                out.write(json.dumps(row) + "\n")
    finally:
        if out is not None:
            out.close()
    print(json.dumps(dict(counts)))
    for combination, count in combinations.most_common():
        print(f"{count:8d}  {combination}")
    print(f"{time.monotonic() - started:.0f} s")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("corpus")
    run.add_argument("dirs", nargs="+")
    run.add_argument("--recursive", action="store_true")
    run.add_argument("--ext", default=".exe,.dll,.sys")
    run.add_argument("--stride", type=int, default=1)
    run.add_argument("--limit", type=int, default=0)
    run.add_argument("--out", help="write the markers of every binary as JSON lines")
    args = parser.parse_args()
    corpus(args)


if __name__ == "__main__":
    main()
