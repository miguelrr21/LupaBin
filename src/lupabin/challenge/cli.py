import json
import sys
from pathlib import Path
from typing import Annotated

import typer

from lupabin.challenge.engine import generate, grade, template
from lupabin.challenge.models import Answers, Challenge, Citation, Question, Result, Selection
from lupabin.errors import LupaBinError
from lupabin.evidence.models import Limits
from lupabin.ingest.reader import read_sample
from lupabin.saved_report import CHECKED, UNCHECKED, check_against_sample, load_report


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def challenge_print(text: str) -> None:
    sys.stdout.buffer.write((text + "\n").encode("utf-8"))


def challenge_citations(citations: tuple[Citation, ...]) -> str:
    return "\n".join(
        f"  {citation.evidence_id or 'informe'} · {citation.path} = {citation.value}"
        for citation in citations
    )


def challenge_question(question: Question) -> None:
    challenge_print(f"\n{question.id} [{question.level}] {question.prompt}")
    for option in question.options:
        challenge_print(f"  {option.id}. {option.text}")
    challenge_print("Citas:\n" + challenge_citations(question.citations))


def challenge_results(result: Result) -> None:
    labels = {"correct": "Correcta", "incorrect": "Incorrecta", "unanswered": "Sin responder"}
    for item in result.items:
        challenge_print(
            f"\n{item.question_id}: {labels[item.outcome]}. Respuesta: {item.correct_option}.\n"
            f"{item.explanation}\nNo demuestra: {item.not_proven}\n"
            f"Citas:\n{challenge_citations(item.citations)}"
        )
    challenge_print("\n" + result.summary)


def challenge_practice(challenge: Challenge) -> Answers:
    selections: list[Selection] = []
    for question in challenge.questions:
        challenge_question(question)
        while True:
            answer = (
                typer.prompt("Respuesta A/B/C (Enter para omitir)", default="", show_default=False)
                .strip()
                .upper()
            )
            if answer in ("", "A", "B", "C"):
                break
            challenge_print("Elige A, B o C; Enter deja la pregunta sin responder.")
        selections.append(
            Selection.model_validate({"question_id": question.id, "option_id": answer or None})
        )
    return Answers(
        challenge_id=challenge.id,
        sample_sha256=challenge.sample_sha256,
        selections=tuple(selections),
    )


def challenge_command(
    report_file: Annotated[
        Path, typer.Argument(help="Informe de hechos guardado con analyze --json.")
    ],
    json_output: Annotated[
        bool, typer.Option("--json", help="Reto y plantilla de respuestas, o resultado tipado.")
    ] = False,
    practice: Annotated[
        bool,
        typer.Option("--practice", help="Seleccionar respuestas en la terminal y corregirlas."),
    ] = False,
    answers_file: Annotated[
        Path | None,
        typer.Option("--answers", help="JSON de answers_template con option_id A/B/C o null."),
    ] = None,
    sample: Annotated[
        Path | None,
        typer.Option("--sample", help="Contrastar el informe con la muestra sin ejecutarla."),
    ] = None,
) -> None:
    if practice and (json_output or answers_file is not None):
        raise typer.BadParameter("--practice no se combina con --json ni --answers")
    try:
        report = load_report(report_file, Limits())
        origin = UNCHECKED
        if sample is not None:
            check_against_sample(report, read_sample(sample, report.analysis.limits))
            origin = CHECKED
    except LupaBinError as error:
        sys.stderr.buffer.write(
            (json.dumps({"error": {"code": error.code, "message": str(error)}}) + "\n").encode(
                "utf-8"
            )
        )
        raise typer.Exit(1) from None
    challenge = generate(report)
    result = None
    if answers_file is not None:
        try:
            with answers_file.open("rb") as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise ValueError("too large")
            json.loads(raw, object_pairs_hook=_unique_object)
            answers = Answers.model_validate_json(raw)
            result = grade(report, answers)
        except (OSError, ValueError, RecursionError):
            raise typer.BadParameter(
                "Respuestas inválidas: comprueba tamaño, IDs, opciones y vínculo con el informe."
            ) from None
    if json_output:
        envelope: dict[str, object] = {"origin": origin}
        if result is None:
            envelope.update(
                challenge=challenge.model_dump(mode="json"),
                answers_template=template(challenge).model_dump(mode="json"),
            )
        else:
            envelope["result"] = result.model_dump(mode="json")
        challenge_print(json.dumps(envelope, ensure_ascii=False, indent=2))
        return
    challenge_print(
        f"LUPABIN · modo reto\n{origin}\n{challenge.notice}\n"
        f"SHA-256: {challenge.sample_sha256}\nBanco: {challenge.catalog}\nReto: {challenge.id}\n"
        "observed: lectura de bytes; inferred: resultado de un método; "
        "general: criterio educativo, no un hecho adicional de la muestra."
    )
    if challenge.empty_reason:
        challenge_print(challenge.empty_reason)
    if practice:
        result = grade(report, challenge_practice(challenge))
    elif result is None:
        for question in challenge.questions:
            challenge_question(question)
        challenge_print(
            "\nUsa --practice para responder aquí. Con --json, guarda solo answers_template "
            "en respuestas.json, edita option_id y usa --answers respuestas.json para corregir."
        )
    if result is not None:
        challenge_results(result)
