import hashlib
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from dissect.evidence.primitives import Model, NonNegative, YaraLimits
from dissect.rules.models import CatalogInfo, Digest, PatternId, RuleInfo

Version = Annotated[str, Field(min_length=1, max_length=64)]
YaraReason = Literal[
    "yara_catalog_invalid",
    "yara_unavailable",
    "yara_compile_error",
    "yara_scan_error",
    "yara_timeout",
    "yara_policy_violation",
    "yara_warning",
    "yara_process_failure",
    "yara_output_limit",
    "yara_result_invalid",
    "yara_instance_limit",
    "yara_data_limit",
    "yara_match_limit",
    "yara_catalog_mismatch",
]


class YaraContext(Model):
    catalog: CatalogInfo | None = None
    package_version: Version | None = None
    module_version: Version | None = None


class YaraInstance(Model):
    string_id: PatternId
    offset: NonNegative
    matched_length: Annotated[int, Field(gt=0, le=20971520)]
    captured_length: Annotated[int, Field(gt=0, le=256)]
    raw_hex: Annotated[str, Field(pattern=r"^(?:[a-f0-9]{2})+$", max_length=512)]
    complete: bool

    @model_validator(mode="after")
    def faithful(self) -> Self:
        if (
            len(self.raw_hex) != 2 * self.captured_length
            or self.captured_length > self.matched_length
        ):
            raise ValueError("captured bytes disagree with lengths")
        if self.complete != (self.captured_length == self.matched_length):
            raise ValueError("capture completeness disagrees with lengths")
        return self


class YaraMatchData(RuleInfo):
    ruleset_sha256: Digest
    package_version: Version
    module_version: Version
    instances: Annotated[tuple[YaraInstance, ...], Field(min_length=1, max_length=16)]
    instances_status: Literal["complete", "partial"]
    omitted_instances: NonNegative | None

    @model_validator(mode="after")
    def faithful(self) -> Self:
        keys = tuple((i.string_id, i.offset, i.matched_length) for i in self.instances)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("instances must be unique and canonical")
        if any(i.string_id not in self.pattern_ids for i in self.instances):
            raise ValueError("unknown rule pattern")
        complete = self.omitted_instances == 0 and all(i.complete for i in self.instances)
        if (self.instances_status == "complete") != complete:
            raise ValueError("instance status is inconsistent")
        return self


class ScanResult(Model):
    protocol_version: Literal["1"] = "1"
    sample_sha256: Digest
    sample_size: Annotated[int, Field(gt=0, le=20971520)]
    context: YaraContext
    rules_ok: bool = False
    scan_ok: bool = False
    matches: Annotated[tuple[YaraMatchData, ...], Field(max_length=32)] = ()
    omitted_rules: NonNegative = 0
    reason: YaraReason | None = None

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if self.scan_ok:
            if not self.rules_ok or self.reason is not None or self.context.catalog is None:
                raise ValueError("successful scan has inconsistent context")
            if self.context.package_version is None or self.context.module_version is None:
                raise ValueError("successful scan requires observed versions")
        elif self.matches or self.omitted_rules or self.reason is None:
            raise ValueError("interrupted scans cannot publish matches")
        ids = tuple((m.namespace, m.rule_id) for m in self.matches)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("matches must be unique and canonical")
        return self


def validate_matches(
    matches: tuple[YaraMatchData, ...],
    context: YaraContext,
    size: int,
    limits: YaraLimits,
    data: bytes | None = None,
) -> None:
    if context.catalog is None or len(matches) > limits.matches:
        raise ValueError("missing catalog or match quota exceeded")
    inventory = {(rule.namespace, rule.rule_id): rule for rule in context.catalog.rules}
    for match in matches:
        definition = inventory.get((match.namespace, match.rule_id))
        observed_definition = RuleInfo.model_validate(
            {
                key: value
                for key, value in match.model_dump().items()
                if key in RuleInfo.model_fields
            }
        )
        if (
            definition != observed_definition
            or match.ruleset_sha256 != context.catalog.ruleset_sha256
        ):
            raise ValueError("match does not identify the expected rule source")
        if (match.package_version, match.module_version) != (
            context.package_version,
            context.module_version,
        ):
            raise ValueError("match versions differ from scan context")
        if len(match.instances) > limits.instances:
            raise ValueError("instance quota exceeded")
        for instance in match.instances:
            if (
                instance.offset + instance.matched_length > size
                or instance.captured_length > limits.capture_bytes
            ):
                raise ValueError("instance exceeds input or capture bounds")
            if data is not None:
                expected = data[instance.offset : instance.offset + instance.captured_length]
                if expected.hex() != instance.raw_hex:
                    raise ValueError("match bytes differ from original input")


def validate_scan(
    result: ScanResult, data: bytes, catalog: CatalogInfo, limits: YaraLimits
) -> None:
    if result.sample_sha256 != hashlib.sha256(data).hexdigest() or result.sample_size != len(data):
        raise ValueError("scan belongs to another input")
    if result.context.catalog != catalog:
        raise ValueError("scan belongs to another catalog")
    validate_matches(result.matches, result.context, len(data), limits, data)
