"""Reproduce the measurements of main detection on benign executables.

    uv run python -m tests.main_eval corpus DIR [DIR ...] [--recursive]
        [--stride N] [--limit N] [--out cases.jsonl]

`corpus` treats every .exe as benign and runs the PE and code extractors on it, then the
host checks of the bytes and the explanation engine, which regenerates every item. It
counts the executables that call __getmainargs or __wgetmainargs, those where main is
found and those where LupaBin abstains, and any report, check or explanation that fails.
`--out` writes every executable with its main call and the size of each reach, so that
each case can be reviewed by disassembling the call and the start of main: a main that
does not receive argc and argv is a false positive. Files are only read as bytes:
nothing is executed, and they never enter the repository. Not part of the package or
of CI.
"""

import argparse
import json
import time
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

from lupabin.analysis import analyze_bytes
from lupabin.evidence.code import verify_calls
from lupabin.evidence.facts import CodeReachEvidence, MainCallEvidence
from lupabin.evidence.models import Limits
from lupabin.explain.engine import explain, validate
from lupabin.extractors.code import CodeExtractor
from lupabin.extractors.pe import PEExtractor
from lupabin.glossary.catalog import load_glossary

MAX_INPUT = 20 * 1024 * 1024
GLOSSARY = load_glossary()


def files(roots: list[Path], recursive: bool, stride: int) -> Iterator[Path]:
    for root in roots:
        found = sorted(root.rglob("*.exe") if recursive else root.glob("*.exe"))
        yield from [p for p in found if p.is_file()][::stride]


def corpus(args: argparse.Namespace) -> None:
    counts: Counter[str] = Counter()
    seconds: list[float] = []
    out = open(args.out, "w", encoding="utf-8") if args.out else None  # noqa: SIM115
    try:
        for path in files([Path(d) for d in args.dirs], args.recursive, args.stride):
            if args.limit and counts["exe"] >= args.limit:
                break
            try:
                if path.stat().st_size > MAX_INPUT:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            if data[:2] != b"MZ":
                continue
            started = time.monotonic()
            try:
                report = analyze_bytes(data, Limits(), extractors=[PEExtractor(), CodeExtractor()])
            except Exception:  # noqa: BLE001
                counts["report_failures"] += 1
                continue
            seconds.append(time.monotonic() - started)
            run = next((r for r in report.extractor_runs if r.source == "code"), None)
            part = (
                next(p for p in run.components if p.name == "main_function")
                if run is not None
                else None
            )
            if part is None or part.status == "blocked":
                continue
            counts["exe"] += 1
            try:
                verify_calls(report.evidence, data)
            except ValueError:
                counts["verify_failures"] += 1
            items = validate(explain(report, GLOSSARY), report, GLOSSARY)
            mains = [f for f in report.evidence if isinstance(f, MainCallEvidence)]
            reaches = {
                f.data.root: len(f.data.calls)
                for f in report.evidence
                if isinstance(f, CodeReachEvidence)
            }
            explained = sum(item.rule.startswith(("code.main", "code.reach")) for item in items)
            if explained != (1 + len(reaches) if mains else 0):
                counts["explanation_failures"] += 1
            if part.examined:
                counts["with_getmainargs"] += 1
                counts["main_found" if mains else "abstained"] += 1
            if part.status == "partial":
                counts["main_partial"] += 1
            if out is not None:
                row = {
                    "path": str(path),
                    "main": [mains[0].location.rva, mains[0].data.target] if mains else None,
                    "reach": reaches,
                }
                out.write(json.dumps(row) + "\n")
    finally:
        if out is not None:
            out.close()
    print(json.dumps(dict(counts)))
    if seconds:
        seconds.sort()
        print(f"seconds: median {seconds[len(seconds) // 2]:.2f}, max {seconds[-1]:.2f}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("corpus")
    run.add_argument("dirs", nargs="+")
    run.add_argument("--recursive", action="store_true")
    run.add_argument("--stride", type=int, default=1)
    run.add_argument("--limit", type=int, default=0)
    run.add_argument("--out", help="write every executable as JSON lines, for review")
    args = parser.parse_args()
    corpus(args)


if __name__ == "__main__":
    main()
