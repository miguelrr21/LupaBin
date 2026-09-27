import argparse
import asyncio
import json
import time
from collections import Counter
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from lupabin.evidence.models import Limits
from lupabin.explain.capabilities import CAPABILITIES, CASES_SHOWN, TECHNIQUES, cases
from lupabin.explain.engine import explain
from lupabin.glossary.catalog import load_glossary
from lupabin.ingest.reader import read_sample
from lupabin.runner import run_isolated
from lupabin.transport import DockerCLI
from lupabin.virustotal.contrast import compare, local_context
from lupabin.virustotal.models import Behaviour, Technique, VirusTotalReport


def select(root, count, recursive=False):
    candidates = []
    for path in root.rglob("*.exe") if recursive else root.glob("*.exe"):
        try:
            if (
                path.is_file()
                and not path.is_symlink()
                and 0 < path.stat().st_size <= Limits().input_bytes
            ):
                candidates.append(path)
        except OSError:
            continue
    candidates.sort()
    if len(candidates) < count:
        raise ValueError(f"not enough eligible files in {root}")
    return [candidates[i * len(candidates) // count] for i in range(count)]


async def evaluate(paths, output):
    counts = Counter()
    glossary = load_glossary()
    with output.open("x", encoding="utf-8") as stream:
        for index, path in enumerate(paths, 1):
            blob = read_sample(path, Limits())
            report = await run_isolated(blob.data, Limits(), DockerCLI())
            explanation = explain(report, glossary)
            start = time.perf_counter()
            context = local_context(report)
            elapsed = time.perf_counter() - start
            vt = VirusTotalReport(
                sample_sha256=report.sample.sha256,
                retrieved_at=datetime.now(UTC),
                status="found",
                permalink="https://www.virustotal.com/gui/file/" + report.sample.sha256,
                behaviour=Behaviour(
                    mitre_attack_techniques=tuple(
                        Technique(id=t) for t in (*TECHNIQUES, "T1059", "invalid")
                    )
                ),
            )
            comparisons = compare(vt, context)
            expected = {key: set() for key in TECHNIQUES}
            review = []
            for capability in CAPABILITIES:
                for case in cases(capability, report):
                    if case.technique in expected:
                        expected[case.technique].update(f.id for f in case.cited)
                        review.append(
                            {
                                "technique": case.technique,
                                "rule": capability.rule_id,
                                "details": case.details,
                                "heading": case.heading,
                                "evidence": [f.id for f in case.cited],
                            }
                        )
            failures = []
            for row in comparisons:
                if row.id in expected and set(row.evidence) != expected[row.id]:
                    failures.append(row.id)
                if row.status == "static_match" and not row.evidence:
                    failures.append("empty_match")
                details = [
                    f"{case['heading']}: {case['details']}"
                    for case in review
                    if case["technique"] == row.id
                ]
                if row.details != tuple(details[:CASES_SHOWN]):
                    failures.append("case_details")
                if row.omitted_details != max(0, len(details) - CASES_SHOWN):
                    failures.append("omitted_details")
            if comparisons[-2].status != "unsupported" or comparisons[-1].status != "invalid_id":
                failures.append("unsupported_or_invalid")
            counts.update(row.status for row in comparisons)
            counts["files"] += 1
            counts["files_with_error"] += bool(failures)
            record = {
                "path": str(path),
                "sha256": report.sample.sha256,
                "synthetic_vt": True,
                "status": report.analysis.status,
                "context_seconds": elapsed,
                "explanations": len(explanation.items),
                "failures": failures,
                "comparisons": [asdict(row) for row in comparisons],
                "review": review,
            }
            stream.write(json.dumps(record, ensure_ascii=True) + "\n")
            stream.flush()
            if index % 25 == 0:
                print(json.dumps(dict(counts)), flush=True)
    print(json.dumps(dict(counts)), flush=True)
    return 1 if counts["files_with_error"] else 0


def review(path):
    with path.open(encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream]
    times = sorted(row["context_seconds"] for row in rows)
    counts = Counter(item["status"] for row in rows for item in row["comparisons"])
    print(
        json.dumps(
            {
                "files": len(rows),
                "failed_files": sum(bool(row["failures"]) for row in rows),
                "statuses": dict(counts),
                "max_seconds": max(times, default=0),
                "median_seconds": times[len(times) // 2] if times else None,
                "synthetic_vt": all(row["synthetic_vt"] for row in rows),
            }
        )
    )
    for row in rows:
        for case in row["review"]:
            print(json.dumps({"path": row["path"], **case}, ensure_ascii=True))
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--review", type=Path)
    parser.add_argument("--jobs", type=int, choices=[1], default=1)
    parser.add_argument("--select-only", action="store_true")
    parser.add_argument("--reference", type=Path, nargs=2)
    parser.add_argument("--files", type=Path, nargs="+")
    args = parser.parse_args()
    if args.review:
        return review(args.review)
    if not args.output or not (args.reference or args.files):
        parser.error("--output and either --reference or --files are required")
    paths = args.files or (
        select(Path("C:/Windows/System32"), 100)
        + select(Path("C:/Windows/SysWOW64"), 60)
        + select(Path("C:/Program Files"), 238, True)
        + args.reference
    )
    if args.select_only:
        print(json.dumps({"files": len(paths)}))
        return 0
    return asyncio.run(evaluate(paths, args.output))


if __name__ == "__main__":
    raise SystemExit(main())
