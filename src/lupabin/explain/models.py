"""Explanation contract 0.1.0: deterministic statements about a validated report.

A separate document from the report: it cites report evidence by ID and glossary
entries by ID, and every item can be regenerated from what it cites (engine.validate).
"""

from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from lupabin.evidence.models import ErrorCode
from lupabin.evidence.primitives import Component, EvidenceId, Model, Source
from lupabin.glossary.models import EntryId, GlossaryInfo

ItemId = Annotated[str, Field(pattern=r"^X[1-9][0-9]*$", max_length=16)]
RuleId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.]*@[1-9][0-9]*$", max_length=64)]
Sentence = Annotated[str, Field(min_length=1, max_length=2000)]
SlotValue = str | int | bool | tuple[str, ...]


class ReportRef(Model):
    sample_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    schema_version: Literal["0.9.0"]


class Item(Model):
    """One statement about the sample, backed by the evidence it cites."""

    id: ItemId
    rule: RuleId
    # The weakest confidence among the cited evidence; "general" is glossary-only.
    level: Literal["observed", "inferred"]
    statement: Sentence
    slots: dict[str, SlotValue]
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1, max_length=25000)]
    glossary_ids: Annotated[tuple[EntryId, ...], Field(min_length=1, max_length=8)]
    not_proven: Sentence


class Note(Model):
    """What could not be analysed, or how far the analysis went; shown before findings."""

    rule: RuleId
    source: Source
    component: Component | None = None
    code: ErrorCode | None = None
    statement: Sentence
    glossary_ids: Annotated[tuple[EntryId, ...], Field(min_length=1, max_length=4)]


class Explanation(Model):
    schema_version: Literal["0.1.0"] = "0.1.0"
    report: ReportRef
    glossary: GlossaryInfo
    status: Literal["completed", "partial", "failed"]
    notes: Annotated[tuple[Note, ...], Field(max_length=512)] = ()
    items: Annotated[tuple[Item, ...], Field(max_length=25000)] = ()

    @model_validator(mode="after")
    def numbered(self) -> Self:
        if tuple(item.id for item in self.items) != tuple(
            f"X{n}" for n in range(1, len(self.items) + 1)
        ):
            raise ValueError("items must be numbered X1, X2... in order")
        return self
