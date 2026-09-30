import argparse
import asyncio
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from lupabin.challenge.engine import generate, grade, validate, web_challenge
from lupabin.challenge.models import Answers, Selection
from lupabin.evidence.models import Limits
from lupabin.ghidra import build_document
from lupabin.ingest.reader import read_sample
from lupabin.render.safe import visible
from lupabin.runner import run_isolated
from lupabin.transport import DockerCLI


def citation_value(report, fact_map, citation):
    value = report if citation.evidence_id is None else fact_map[citation.evidence_id]
    for token in re.findall(r"[^.\[\]]+", citation.path):
        value = value[int(token)] if isinstance(value, list) else value[token]
    return visible(value if isinstance(value, str) else json.dumps(value, ensure_ascii=False))


async def evaluate(paths, output):
    counts = Counter()
    with output.open("x", encoding="utf-8") as stream:
        for index, path in enumerate(paths, 1):
            blob = read_sample(path, Limits())
            report = await run_isolated(blob.data, Limits(), DockerCLI())
            original = report.model_dump(mode="json")
            facts = {fact["id"]: fact for fact in original["evidence"]}
            challenge = generate(report)
            validate(challenge, report)
            shown = web_challenge(report)
            solutions = {item["question_id"]: item["correct_option"] for item in shown["feedback"]}
            errors = []
            for question in challenge.questions:
                if len({option.text for option in question.options}) != 3:
                    errors.append("ambiguous_options")
                for citation in question.citations:
                    if citation.value != citation_value(original, facts, citation):
                        errors.append("citation_value")
                counts["question_" + question.rule] += 1
            for right in (True, False):
                answers = Answers(
                    challenge_id=challenge.id,
                    sample_sha256=challenge.sample_sha256,
                    selections=tuple(
                        Selection(
                            question_id=q.id,
                            option_id=next(
                                o.id for o in q.options if (o.id == solutions[q.id]) == right
                            ),
                        )
                        for q in challenge.questions
                    ),
                )
                result = grade(report, answers)
                if result.correct != (len(challenge.questions) if right else 0):
                    errors.append("grading")
            exported = build_document(report, blob.data)
            if (
                exported.report.model_dump(mode="json") != original
                or report.model_dump(mode="json") != original
            ):
                errors.append("report_mutation")
            ids = set()
            for annotation in exported.annotations:
                ids.add(annotation.evidence_id)
                if annotation.evidence_id not in facts:
                    errors.append("annotation_reference")
                if annotation.offset is None:
                    if annotation.reason is None:
                        errors.append("missing_location_reason")
                else:
                    raw = blob.data[annotation.offset : annotation.offset + annotation.length]
                    if hashlib.sha256(raw).hexdigest() != annotation.range_sha256:
                        errors.append("annotation_bytes")
                if "{@" in annotation.text:
                    errors.append("active_annotation_syntax")
            if ids != set(facts):
                errors.append("omitted_evidence")
            counts["files"] += 1
            counts["files_with_error"] += bool(errors)
            counts["annotations"] += len(exported.annotations)
            counts["questions"] += len(challenge.questions)
            counts[report.analysis.status] += 1
            stream.write(
                json.dumps(
                    {
                        "path": str(path),
                        "sha256": report.sample.sha256,
                        "errors": errors,
                        "annotations": len(exported.annotations),
                        "challenge": challenge.model_dump(mode="json"),
                        "feedback": shown["feedback"],
                        "status": report.analysis.status,
                    },
                    ensure_ascii=True,
                )
                + "\n"
            )
            stream.flush()
            if index % 25 == 0:
                print(json.dumps(dict(counts)), flush=True)
    print(json.dumps(dict(counts)), flush=True)
    return 1 if counts["files_with_error"] else 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, choices=[1], default=1)
    parser.add_argument("--limit", type=int, default=400)
    args = parser.parse_args()
    with args.manifest.open(encoding="utf-8") as stream:
        paths = [Path(json.loads(line)["path"]) for line in stream][: args.limit]
    raise SystemExit(asyncio.run(evaluate(paths, args.output)))


if __name__ == "__main__":
    main()
