from typing import Annotated, Literal

from pydantic import Field

from lupabin.evidence.primitives import EvidenceId, Model

Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
QuestionId = Annotated[str, Field(pattern=r"^Q[1-7]$")]
OptionId = Literal["A", "B", "C"]
RuleId = Literal["header", "section", "import", "call", "string", "decoded", "coverage"]
Level = Literal["observed", "inferred", "general"]
Catalog = Literal["lupabin-challenges-v1"]
NOTICE = (
    "Práctica educativa, no examen protegido contra trampas. Las opciones son alternativas "
    "del ejercicio, no hechos adicionales del informe. La puntuación mide respuestas, "
    "no riesgo de la muestra. Sin LLM ni red; las soluciones web son inspeccionables."
)


class Citation(Model):
    evidence_id: EvidenceId | None
    path: str
    value: str


class Option(Model):
    id: OptionId
    text: str


class Question(Model):
    id: QuestionId
    rule: RuleId
    level: Level
    prompt: str
    options: tuple[Option, Option, Option]
    citations: Annotated[tuple[Citation, ...], Field(min_length=1, max_length=8)]


class Challenge(Model):
    schema_version: Literal["0.1.0"] = "0.1.0"
    catalog: Catalog = "lupabin-challenges-v1"
    id: Digest
    sample_sha256: Digest
    report_schema: Literal["0.11.0"] = "0.11.0"
    report_digest: Digest
    questions: Annotated[tuple[Question, ...], Field(max_length=7)]
    notice: str = NOTICE
    empty_reason: str | None = None


class Selection(Model):
    question_id: QuestionId
    option_id: OptionId | None = None


class Answers(Model):
    schema_version: Literal["0.1.0"] = "0.1.0"
    catalog: Catalog = "lupabin-challenges-v1"
    challenge_id: Digest
    sample_sha256: Digest
    report_schema: Literal["0.11.0"] = "0.11.0"
    selections: Annotated[tuple[Selection, ...], Field(max_length=7)] = ()


class Feedback(Model):
    question_id: QuestionId
    rule: RuleId
    correct_option: OptionId
    explanation: str
    not_proven: str
    citations: Annotated[tuple[Citation, ...], Field(min_length=1, max_length=8)]


class GradedItem(Feedback):
    selected_option: OptionId | None
    outcome: Literal["correct", "incorrect", "unanswered"]


class Result(Model):
    schema_version: Literal["0.1.0"] = "0.1.0"
    catalog: Catalog = "lupabin-challenges-v1"
    challenge_id: Digest
    sample_sha256: Digest
    report_schema: Literal["0.11.0"] = "0.11.0"
    correct: Annotated[int, Field(ge=0, le=7)]
    answered: Annotated[int, Field(ge=0, le=7)]
    total: Annotated[int, Field(ge=0, le=7)]
    items: Annotated[tuple[GradedItem, ...], Field(max_length=7)]
    summary: str
