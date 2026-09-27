import hashlib
import json
from dataclasses import asdict
from typing import Any, Literal

from lupabin.challenge.bank import CATALOG, RULES
from lupabin.challenge.models import (
    Answers,
    Challenge,
    Citation,
    Feedback,
    GradedItem,
    Option,
    OptionId,
    Question,
    Result,
    RuleId,
    Selection,
)
from lupabin.evidence.models import Evidence, Report
from lupabin.render.safe import visible


def _digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


BANK_DIGEST = _digest([asdict(rule) for rule in RULES])


def _citation(fact: Evidence, path: str) -> Citation:
    value: Any = fact.model_dump(mode="json")
    for key in path.split("."):
        value = value[key]
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return Citation(evidence_id=fact.id, path=path, value=visible(text))


def _candidates(report: Report) -> dict[RuleId, tuple[dict[str, str], tuple[Citation, ...]]]:
    chosen: dict[RuleId, tuple[dict[str, str], tuple[Citation, ...]]] = {}
    facts = {fact.id: fact for fact in report.evidence}
    seen: set[str] = set()
    for fact in report.evidence:
        if fact.kind in seen:
            continue
        seen.add(fact.kind)
        slots = {"id": fact.id}
        rule: RuleId
        paths: tuple[str, ...]
        extra: tuple[Citation, ...] = ()
        if fact.kind == "pe_header":
            rule, paths = "header", ("data.number_of_sections",)
            count = fact.data.number_of_sections
            slots.update(
                value=str(count),
                alternative1=str(count % 65535 + 1),
                alternative2=str((count + 1) % 65535 + 1),
            )
        elif fact.kind == "section":
            rule, paths = "section", ("data.raw_size",)
            slots["value"] = str(fact.data.raw_size)
        elif fact.kind == "import":
            rule, paths = "import", ("kind", "data.table", "data.dll.text", "data.dll.raw_hex")
            dll = fact.data.dll.text or f"bytes {fact.data.dll.raw_hex}"
            function = fact.data.function
            paths += (
                ("data.function.text", "data.function.raw_hex") if function else ("data.ordinal",)
            )
            name = (
                (function.text or f"bytes {function.raw_hex}")
                if function
                else f"ordinal {fact.data.ordinal}"
            )
            slots.update(value=fact.data.table, label=visible(f"{dll}!{name}"))
        elif fact.kind == "api_call":
            rule, paths = (
                "call",
                (
                    "kind",
                    "data.via",
                    "data.raw_hex",
                    "location.offset",
                    "location.rva",
                    "provenance.evidence_ids",
                ),
            )
            slots["value"] = fact.data.via
            target = facts[fact.provenance.evidence_ids[0]]
            extra = (_citation(target, "kind"), _citation(target, "data.iat_rva"))
        elif fact.kind == "string":
            rule, paths = (
                "string",
                ("kind", "confidence", "data.encoding", "data.text", "data.complete"),
            )
            slots["value"] = fact.data.encoding
        elif fact.kind == "decoded_string":
            rule, paths = (
                "decoded",
                ("kind", "confidence", "transform.name", "data.text", "provenance.evidence_ids"),
            )
            slots["value"] = fact.transform.name
        else:
            continue
        if rule not in chosen:
            chosen[rule] = (slots, tuple(_citation(fact, path) for path in paths) + extra)
    for run_index, run in enumerate(report.extractor_runs):
        for part_index, part in enumerate(run.components):
            if part.status != "complete" and "coverage" not in chosen:
                label = f"{run.source}/{part.name}"
                chosen["coverage"] = (
                    {"label": label, "value": part.status},
                    (
                        Citation(
                            evidence_id=None,
                            path=f"extractor_runs[{run_index}].source",
                            value=run.source,
                        ),
                        Citation(
                            evidence_id=None,
                            path=f"extractor_runs[{run_index}].components[{part_index}].name",
                            value=part.name,
                        ),
                        Citation(
                            evidence_id=None,
                            path=f"extractor_runs[{run_index}].components[{part_index}].status",
                            value=part.status,
                        ),
                    ),
                )
    return chosen


def _build(report: Report) -> tuple[Challenge, tuple[Feedback, ...]]:
    report = Report.model_validate(report.model_dump())
    snapshot = report.model_dump(mode="json")
    del snapshot["analysis"]["started_at"]
    del snapshot["analysis"]["finished_at"]
    report_digest = _digest(snapshot)
    identity = _digest([CATALOG, BANK_DIGEST, report_digest])
    candidates = _candidates(report)
    questions: list[Question] = []
    feedback: list[Feedback] = []
    labels: tuple[OptionId, OptionId, OptionId] = ("A", "B", "C")
    for rule in RULES:
        candidate = candidates.get(rule.id)
        if candidate is None:
            continue
        slots, citations = candidate
        texts = tuple(text.format_map(slots) for text in rule.choices)
        if len(set(texts)) != 3:
            continue
        ordered = sorted(range(3), key=lambda index: _digest([identity, rule.id, index]))
        options = tuple(
            Option(id=label, text=texts[index])
            for label, index in zip(labels, ordered, strict=True)
        )
        question = Question(
            id=f"Q{len(questions) + 1}",
            rule=rule.id,
            level=rule.level,
            prompt=rule.prompt.format_map(slots),
            options=(options[0], options[1], options[2]),
            citations=citations,
        )
        questions.append(question)
        feedback.append(
            Feedback(
                question_id=question.id,
                rule=rule.id,
                correct_option=labels[ordered.index(0)],
                explanation=rule.explanation.format_map(slots),
                not_proven=rule.not_proven,
                citations=citations,
            )
        )
    challenge = Challenge(
        id=identity,
        sample_sha256=report.sample.sha256,
        report_digest=report_digest,
        questions=tuple(questions),
        empty_reason=None if questions else "Sin preguntas sustentadas por las reglas disponibles.",
    )
    content_digest = _digest(
        [challenge.model_dump(mode="json"), [item.model_dump(mode="json") for item in feedback]]
    )
    return challenge.model_copy(update={"id": content_digest}), tuple(feedback)


def generate(report: Report) -> Challenge:
    return _build(report)[0]


def validate(challenge: Challenge, report: Report) -> Challenge:
    expected = generate(report)
    if challenge != expected:
        raise ValueError("El reto no coincide con el que generan estas evidencias y reglas.")
    return expected


def template(challenge: Challenge) -> Answers:
    return Answers(
        challenge_id=challenge.id,
        sample_sha256=challenge.sample_sha256,
        selections=tuple(Selection(question_id=q.id) for q in challenge.questions),
    )


def grade(report: Report, answers: Answers) -> Result:
    answers = Answers.model_validate(answers.model_dump())
    challenge, feedback = _build(report)
    if (answers.challenge_id, answers.sample_sha256, answers.report_schema, answers.catalog) != (
        challenge.id,
        challenge.sample_sha256,
        challenge.report_schema,
        challenge.catalog,
    ):
        raise ValueError("Las respuestas no pertenecen a este informe y banco de preguntas.")
    questions = {q.id: q for q in challenge.questions}
    selections = {answer.question_id: answer.option_id for answer in answers.selections}
    if len(selections) != len(answers.selections) or not selections.keys() <= questions.keys():
        raise ValueError("Hay preguntas duplicadas o desconocidas.")
    for question_id, selected in selections.items():
        if selected is not None and selected not in {o.id for o in questions[question_id].options}:
            raise ValueError("Opción desconocida.")
    items: list[GradedItem] = []
    for solution in feedback:
        selected = selections.get(solution.question_id)
        outcome: Literal["unanswered", "correct", "incorrect"] = (
            "unanswered"
            if selected is None
            else "correct"
            if selected == solution.correct_option
            else "incorrect"
        )
        items.append(GradedItem(**solution.model_dump(), selected_option=selected, outcome=outcome))
    correct = sum(item.outcome == "correct" for item in items)
    answered = sum(item.outcome != "unanswered" for item in items)
    review = tuple(dict.fromkeys(item.rule for item in items if item.outcome != "correct"))
    summary = (
        "Sin preguntas: no se asigna una nota."
        if not items
        else f"{correct}/{len(items)} respuestas correctas; {len(items) - answered} sin responder. "
        + (
            "Repasa: " + ", ".join(review) + "."
            if review
            else "Has acertado las preguntas disponibles."
        )
        + " Esta puntuación no evalúa el riesgo de la muestra."
    )
    return Result(
        challenge_id=challenge.id,
        sample_sha256=challenge.sample_sha256,
        correct=correct,
        answered=answered,
        total=len(items),
        items=tuple(items),
        summary=summary,
    )


def web_challenge(report: Report) -> dict[str, Any]:
    challenge, feedback = _build(report)
    return {
        "challenge_id": challenge.id,
        "challenge": challenge.model_dump(mode="json"),
        "feedback": [item.model_dump(mode="json") for item in feedback],
    }
