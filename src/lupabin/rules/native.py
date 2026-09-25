import hashlib
import heapq
from collections.abc import Iterator
from importlib import import_module
from importlib.metadata import PackageNotFoundError, version
from typing import Protocol, cast

from lupabin.evidence.primitives import YaraLimits
from lupabin.evidence.yara import ScanResult, YaraContext, YaraInstance, YaraMatchData, YaraReason
from lupabin.rules.catalog import Catalog, CatalogError, load_catalog


class NativeInstance(Protocol):
    offset: int
    matched_length: int
    matched_data: bytes


class NativeString(Protocol):
    identifier: str
    instances: list[NativeInstance]


class NativeMatch(Protocol):
    rule: str
    namespace: str
    strings: list[NativeString]


class NativeRule(Protocol):
    identifier: str
    is_private: bool
    is_global: bool


class NativeRules(Protocol):
    def __iter__(self) -> Iterator[NativeRule]: ...
    def match(self, **kwargs: object) -> list[NativeMatch]: ...


class Backend(Protocol):
    __version__: str
    CALLBACK_CONTINUE: int
    CALLBACK_ABORT: int
    TimeoutError: type[Exception]

    def set_config(self, **kwargs: int) -> None: ...
    def compile(self, **kwargs: object) -> NativeRules: ...


def scan(
    data: bytes, limits: YaraLimits | None = None, *, catalog: Catalog | None = None
) -> ScanResult:
    effective = limits or YaraLimits()
    context = YaraContext()
    compiled_ok = False
    digest = hashlib.sha256(data).hexdigest()

    def failure(reason: YaraReason) -> ScanResult:
        return ScanResult(
            sample_sha256=digest,
            sample_size=len(data),
            context=context,
            rules_ok=compiled_ok,
            reason=reason,
        )

    if not 0 < len(data) <= 20971520:
        raise ValueError("input outside native scan bounds")
    try:
        selected = catalog or load_catalog(effective)
    except CatalogError:
        return failure("yara_catalog_invalid")
    context = YaraContext(catalog=selected.info)
    try:
        api = cast(Backend, import_module("yara"))
        context = YaraContext(
            catalog=selected.info,
            package_version=version("yara-python"),
            module_version=api.__version__,
        )
    except (ImportError, PackageNotFoundError, AttributeError, ValueError):
        return failure("yara_unavailable")
    try:
        api.set_config(
            max_strings_per_rule=effective.patterns_per_rule, max_match_data=effective.capture_bytes
        )
        for definition in selected.info.rules:
            single = api.compile(
                sources={definition.namespace: selected.sources[definition.namespace]},
                includes=False,
                error_on_warning=True,
            )
            declarations = list(single)
            if len(declarations) != 1 or declarations[0].identifier != definition.rule_id:
                return failure("yara_catalog_invalid")
            if declarations[0].is_private or declarations[0].is_global:
                return failure("yara_policy_violation")
        rules = api.compile(sources=selected.sources, includes=False, error_on_warning=True)
    except Exception:
        return failure("yara_compile_error")
    compiled_ok = True
    package_version = context.package_version
    module_version = context.module_version
    if package_version is None or module_version is None:
        return failure("yara_unavailable")
    violation = False
    warned = False

    def module_callback(info: object) -> int:
        nonlocal violation
        violation = True
        return api.CALLBACK_ABORT

    def console_callback(message: str) -> None:
        nonlocal violation
        violation = True

    def warning_callback(kind: int, message: object) -> int:
        nonlocal warned
        warned = True
        return api.CALLBACK_ABORT

    try:
        native = rules.match(
            data=data,
            fast=False,
            timeout=effective.scan_seconds,
            modules_callback=module_callback,
            console_callback=console_callback,
            warnings_callback=warning_callback,
        )
    except api.TimeoutError:
        return failure("yara_timeout")
    except Exception:
        return failure("yara_policy_violation" if violation else "yara_scan_error")
    if violation or warned:
        return failure("yara_policy_violation" if violation else "yara_warning")
    try:
        inventory = {(rule.namespace, rule.rule_id): rule for rule in selected.info.rules}
        keys = [(match.namespace, match.rule) for match in native]
        if len(keys) != len(set(keys)) or not set(keys) <= inventory.keys():
            raise ValueError("unexpected matching rule")
        results = []
        for match in sorted(native, key=lambda m: (m.namespace, m.rule))[: effective.matches]:
            definition = inventory[(match.namespace, match.rule)]
            witnesses: list[YaraInstance] = []
            extras: list[YaraInstance] = []
            total = 0
            seen_patterns = set()
            for string in sorted(match.strings, key=lambda s: s.identifier):
                if (
                    string.identifier not in definition.pattern_ids
                    or string.identifier in seen_patterns
                ):
                    raise ValueError("unexpected matching pattern")
                seen_patterns.add(string.identifier)
                total += len(string.instances)
                instances = heapq.nsmallest(
                    effective.instances,
                    string.instances,
                    key=lambda i: (i.offset, i.matched_length),
                )
                converted = []
                for instance in instances:
                    if type(instance.offset) is not int or type(instance.matched_length) is not int:
                        raise ValueError("invalid native offsets")
                    if instance.offset < 0 or instance.offset + instance.matched_length > len(data):
                        raise ValueError("native match is outside input")
                    raw = instance.matched_data[: effective.capture_bytes]
                    if raw != data[instance.offset : instance.offset + len(raw)]:
                        raise ValueError("native bytes differ from input")
                    converted.append(
                        YaraInstance(
                            string_id=string.identifier,
                            offset=instance.offset,
                            matched_length=instance.matched_length,
                            captured_length=len(raw),
                            raw_hex=raw.hex(),
                            complete=len(raw) == instance.matched_length,
                        )
                    )
                if converted:
                    witnesses.append(converted[0])
                    extras.extend(converted[1:])

            def key(instance: YaraInstance) -> tuple[str, int, int]:
                return instance.string_id, instance.offset, instance.matched_length

            retained = sorted(
                (sorted(witnesses, key=key) + sorted(extras, key=key))[: effective.instances],
                key=key,
            )
            omitted = total - len(retained)
            complete = omitted == 0 and all(instance.complete for instance in retained)
            results.append(
                YaraMatchData(
                    **definition.model_dump(),
                    ruleset_sha256=selected.info.ruleset_sha256,
                    package_version=package_version,
                    module_version=module_version,
                    instances=tuple(retained),
                    instances_status="complete" if complete else "partial",
                    omitted_instances=omitted,
                )
            )
        return ScanResult(
            sample_sha256=digest,
            sample_size=len(data),
            context=context,
            rules_ok=True,
            scan_ok=True,
            matches=tuple(results),
            omitted_rules=max(0, len(native) - len(results)),
        )
    except Exception:
        return failure("yara_result_invalid")
