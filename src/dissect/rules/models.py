from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from dissect.evidence.primitives import Model

Identifier = Annotated[str, Field(pattern=r"^[a-zA-Z_][a-zA-Z0-9_]*$", max_length=128)]
PatternId = Annotated[str, Field(pattern=r"^\$[a-zA-Z_][a-zA-Z0-9_]*$", max_length=128)]
Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Revision = Annotated[str, Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$", max_length=32)]


class RuleDefinition(Model):
    rule_id: Identifier
    namespace: Identifier
    filename: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*\.yar$", max_length=132)]
    revision: Revision
    pattern_ids: Annotated[tuple[PatternId, ...], Field(min_length=1, max_length=8)]
    description: Annotated[str, Field(min_length=1, max_length=320)]
    license: Literal["Apache-2.0"]

    @model_validator(mode="after")
    def unique(self) -> Self:
        if self.namespace != self.rule_id or self.filename != self.rule_id + ".yar":
            raise ValueError("rule identity disagrees with namespace or filename")
        if len(set(self.pattern_ids)) != len(self.pattern_ids):
            raise ValueError("duplicate pattern ID")
        return self


class Manifest(Model):
    format_version: Literal["1"]
    catalog_id: Identifier
    revision: Revision
    rules: Annotated[tuple[RuleDefinition, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def unique(self) -> Self:
        if len({rule.rule_id for rule in self.rules}) != len(self.rules):
            raise ValueError("duplicate rule ID")
        return self


class RuleInfo(RuleDefinition):
    source_sha256: Digest


class CatalogInfo(Model):
    format_version: Literal["1"] = "1"
    catalog_id: Identifier
    revision: Revision
    manifest_sha256: Digest
    ruleset_sha256: Digest
    rules: Annotated[tuple[RuleInfo, ...], Field(min_length=1, max_length=32)]

    @model_validator(mode="after")
    def ordered(self) -> Self:
        ids = tuple(rule.rule_id for rule in self.rules)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("rule inventory must be unique and canonical")
        return self
