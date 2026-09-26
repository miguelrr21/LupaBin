"""Reproduce the measurements of capabilities on benign binaries.

    uv run python -m tests.capability_eval corpus DIR [DIR ...] [--recursive]
        [--ext .exe,.dll,.sys] [--stride N] [--limit N] [--jobs N] [--out cases.jsonl]
    uv run python -m tests.capability_eval review cases.jsonl [--capability ID]

`corpus` treats every file as benign and runs the PE and code extractors on it, then
the explanation engine, which regenerates every item. For each capability it counts
the binaries with at least one case, over every PE file analysed,
and the binaries that call one of its functions at all. `--out` writes every case
with its call site and arguments, one binary per line, so that each case can be
reviewed by hand: a case whose wording does not describe what the call's arguments
say is a false positive. It also counts the abstentions that the design names, so
they can be measured instead of assumed. Files are only read as bytes: nothing is
executed, and they never enter the repository. Not part of the package or of CI.
"""

import argparse
import json
import sys
import time
from collections import Counter
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

from lupabin.analysis import analyze_bytes
from lupabin.evidence.code import verify_calls
from lupabin.evidence.facts import ApiCallEvidence, CallArgumentEvidence, ImportEvidence
from lupabin.explain import capabilities as capabilities_module
from lupabin.explain.capabilities import CAPABILITIES, RUN_KEYS, cases
from lupabin.explain.text import name, number
from lupabin.extractors.code import CodeExtractor
from lupabin.extractors.pe import PEExtractor
from lupabin.glossary.catalog import load_glossary

# A capability being measured has no benign figure yet, and its explanation needs one to
# be generated; the placeholder only lives in this measuring process, never in a report.
for _capability in CAPABILITIES:
    capabilities_module.BENIGN.setdefault(_capability.id, 0)

MAX_INPUT = 20 * 1024 * 1024
GLOSSARY = load_glossary()
CALLED = {function for capability in CAPABILITIES for function in capability.reads}


def files(roots: list[Path], recursive: bool, ext: tuple[str, ...], stride: int) -> Iterator[Path]:
    for root in roots:
        found = sorted(root.rglob("*") if recursive else root.iterdir())
        chosen = [p for p in found if p.suffix.lower() in ext and p.is_file()]
        yield from chosen[::stride]


def _abstentions(report: Any) -> Counter[str]:
    """Calls the design says LupaBin abstains on, counted to measure the coverage cost."""
    facts = {fact.id: fact for fact in report.evidence}
    arguments: dict[str, dict[str, CallArgumentEvidence]] = {}
    for fact in report.evidence:
        if isinstance(fact, CallArgumentEvidence):
            arguments.setdefault(fact.provenance.evidence_ids[0], {})[fact.data.name] = fact
    found: Counter[str] = Counter()
    for fact in report.evidence:
        if not isinstance(fact, ApiCallEvidence):
            continue
        target = facts.get(fact.provenance.evidence_ids[0])
        if not isinstance(target, ImportEvidence) or target.data.function is None:
            continue
        function, args = name(target.data.function), arguments.get(fact.id, {})
        protection = args.get("flProtect") or args.get("flNewProtect")
        if protection is not None and function.startswith("Virtual"):
            value = protection.data.value
            if value & 0xFF in (0x40, 0x80) and value & ~0x400007FF:
                found["executable_writable_with_unnamed_bits"] += 1
        subkey = args.get("lpSubKey")
        if subkey is not None and subkey.data.string is not None:
            path = subkey.data.string.text.lower().rstrip("\\")
            if any(path.endswith(key.path) for key in RUN_KEYS):
                access = args.get("samDesired")
                if function.startswith(("RegOpenKey", "RegCreateKey")) and "Ex" not in function:
                    found["run_key_without_rights"] += 1
                elif access is None:
                    found["run_key_rights_unknown"] += 1
                elif access.data.value == 0x02000000:
                    found["run_key_maximum_allowed"] += 1
        if function == "CreateProcessW" and "lpApplicationName" not in args:
            found["create_process_w_without_application"] += 1
    return found


def measure(path_text: str) -> dict[str, Any]:
    path = Path(path_text)
    try:
        data = path.read_bytes()
    except OSError:
        return {"path": path_text, "skipped": "unreadable"}
    if not data.startswith(b"MZ") or len(data) > MAX_INPUT:
        return {"path": path_text, "skipped": "not a PE or too large"}
    start = time.perf_counter()
    try:
        report = analyze_bytes(data, extractors=(PEExtractor(), CodeExtractor()))
    except ValueError as error:
        return {"path": path_text, "invalid": str(error)[:200]}
    result: dict[str, Any] = {"path": path_text, "pe": True}
    code = next(run for run in report.extractor_runs if run.source == "code")
    result["walk"] = {part.name: part.status for part in code.components}
    try:
        verify_calls(report.evidence, data)
    except ValueError:
        result["verify_failure"] = True
    try:
        from lupabin.explain.engine import explain  # after the placeholder figures

        explanation = explain(report, GLOSSARY)  # regenerates and validates every item
    except ValueError as error:
        result["explanation_error"] = str(error)[:200]
        return result
    items = {item.rule: item for item in explanation.items}
    facts = {fact.id: fact for fact in report.evidence}
    imported = set()
    for fact in report.evidence:
        if isinstance(fact, ApiCallEvidence):
            target = facts.get(fact.provenance.evidence_ids[0])
            if isinstance(target, ImportEvidence) and target.data.function is not None:
                imported.add(name(target.data.function))
    result["calls"] = sorted(imported & CALLED)
    result["capabilities"] = {}
    for capability in CAPABILITIES:
        found = cases(capability, report)
        if not found:
            continue
        item = items.get(capability.rule_id)  # the engine must have published it
        if item is None or item.slots["count"] != number(len(found)):
            result["item_mismatch"] = capability.id
        result["capabilities"][capability.id] = [
            {
                "heading": case.heading,
                "details": case.details,
                "technique": case.technique,
                "arguments": [
                    {a.data.name: (a.data.string.text if a.data.string else a.data.value)}
                    for a in case.cited
                    if isinstance(a, CallArgumentEvidence)
                ],
            }
            for case in found
        ]
    result["functions"] = sum(fact.kind == "code_function" for fact in report.evidence)
    result["abstentions"] = dict(_abstentions(report))
    result["seconds"] = round(time.perf_counter() - start, 3)
    return result


def corpus(args: argparse.Namespace) -> None:
    ext = tuple(e.strip().lower() for e in args.ext.split(","))
    paths = [str(p) for p in files([Path(d) for d in args.dirs], args.recursive, ext, args.stride)]
    if args.limit:
        paths = paths[: args.limit]
    totals: Counter[str] = Counter()
    binaries: Counter[str] = Counter()
    callers: Counter[str] = Counter()
    case_count: Counter[str] = Counter()
    techniques: Counter[str] = Counter()
    abstentions: Counter[str] = Counter()
    out = open(args.out, "w", encoding="utf-8") if args.out else None  # noqa: SIM115
    with ProcessPoolExecutor(max_workers=args.jobs) as pool:
        for done, result in enumerate(pool.map(measure, paths, chunksize=4), 1):
            if "skipped" in result:
                totals["skipped"] += 1
                continue
            if "invalid" in result:
                totals["invalid_reports"] += 1
                print("INVALID", result["path"], result["invalid"])
                continue
            totals["pe_files"] += 1
            totals["verify_failures"] += result.get("verify_failure", False)
            if "item_mismatch" in result:
                totals["item_mismatches"] += 1
                print("MISMATCH", result["path"], result["item_mismatch"])
            if "explanation_error" in result:
                totals["explanation_errors"] += 1
                print("EXPLAIN", result["path"], result["explanation_error"])
                continue
            abstentions.update(result["abstentions"])
            totals["function_ranges"] += result["functions"]
            for capability in CAPABILITIES:
                if set(result["calls"]) & set(capability.reads):
                    callers[capability.id] += 1
            for capability_id, found in result["capabilities"].items():
                binaries[capability_id] += 1
                case_count[capability_id] += len(found)
                techniques.update(case["technique"] for case in found if case["technique"])
            if out is not None and result["capabilities"]:
                out.write(json.dumps(result, ensure_ascii=False) + "\n")
            if done % 200 == 0:
                print(f"... {done} of {len(paths)}", file=sys.stderr)
    if out is not None:
        out.close()
    pe = totals["pe_files"]
    print(dict(totals))
    print(f"{'capability':<28} {'binaries':>9} {'share':>7} {'cases':>7} {'callers':>8}")
    for capability in CAPABILITIES:
        count = binaries[capability.id]
        share = f"{100 * count / pe:.2f}%" if pe else "-"
        print(
            f"{capability.id:<28} {count:>9} {share:>7} {case_count[capability.id]:>7} "
            f"{callers[capability.id]:>8}"
        )
    print("techniques", dict(techniques))
    print("abstentions", dict(abstentions))


def review(args: argparse.Namespace) -> None:
    """Print every case, for a reviewer to compare its wording with its arguments."""
    with open(args.cases, encoding="utf-8") as stream:
        for line in stream:
            result = json.loads(line)
            for capability_id, found in result["capabilities"].items():
                if args.capability and capability_id != args.capability:
                    continue
                for case in found:
                    print(
                        f"{capability_id} | {Path(result['path']).name} | {case['heading']}: "
                        f"{case['details']}"
                        + (f" ({case['technique']})" if case["technique"] else "")
                        + f" | {json.dumps(case['arguments'], ensure_ascii=False)}"
                    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("corpus")
    run.add_argument("dirs", nargs="+")
    run.add_argument("--recursive", action="store_true")
    run.add_argument("--ext", default=".exe,.dll,.sys")
    run.add_argument("--stride", type=int, default=1)
    run.add_argument("--limit", type=int, default=0)
    run.add_argument("--jobs", type=int, default=1)
    run.add_argument("--out", help="write every case as JSON lines, for review")
    listing = commands.add_parser("review")
    listing.add_argument("cases")
    listing.add_argument("--capability")
    args = parser.parse_args()
    corpus(args) if args.command == "corpus" else review(args)


if __name__ == "__main__":
    main()
