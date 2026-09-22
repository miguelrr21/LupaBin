import hashlib
import json
from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path

from pydantic import ValidationError

from dissect.evidence.primitives import YaraLimits
from dissect.rules.models import CatalogInfo, Manifest, RuleInfo


class CatalogError(ValueError):
    pass


@dataclass(frozen=True)
class Catalog:
    info: CatalogInfo
    sources: dict[str, str]


def read_resource(root: Traversable, filename: str, maximum: int) -> bytes:
    path = root.joinpath(filename)
    if isinstance(path, Path):
        if path.is_symlink() or path.resolve().parent != Path(str(root)).resolve():
            raise CatalogError("unsafe rule resource")
    with path.open("rb") as stream:
        content = stream.read(maximum + 1)
    if (
        not content
        or len(content) > maximum
        or b"\r" in content
        or content.startswith(b"\xef\xbb\xbf")
    ):
        raise CatalogError("resource is empty, oversized or not canonical UTF-8/LF")
    content.decode("utf-8")
    return content


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CatalogError("duplicate JSON key")
        result[key] = value
    return result


def load_catalog(limits: YaraLimits | None = None, *, root: Traversable | None = None) -> Catalog:
    effective = limits or YaraLimits()
    resources = root if root is not None else files("dissect").joinpath("rules", "yara")
    try:
        raw = read_resource(resources, "manifest.json", effective.manifest_bytes)
        json.loads(raw, object_pairs_hook=unique_object)
        manifest = Manifest.model_validate_json(raw)
        expected = {rule.filename for rule in manifest.rules}
        actual = {
            entry.name
            for entry in resources.iterdir()
            if entry.name.lower().endswith((".yar", ".yara"))
        }
        if actual != expected or len(manifest.rules) > effective.rules:
            raise CatalogError("rule inventory differs from manifest or exceeds quota")
        sources = {}
        rules = []
        total = 0
        for definition in sorted(manifest.rules, key=lambda rule: (rule.namespace, rule.rule_id)):
            if len(definition.pattern_ids) > effective.patterns_per_rule:
                raise CatalogError("too many patterns")
            source = read_resource(resources, definition.filename, effective.source_bytes)
            total += len(source)
            if total > effective.total_source_bytes:
                raise CatalogError("source budget exceeded")
            sources[definition.namespace] = source.decode("utf-8")
            rules.append(
                RuleInfo(
                    **definition.model_dump(), source_sha256=hashlib.sha256(source).hexdigest()
                )
            )
        manifest_digest = hashlib.sha256(raw).hexdigest()
        canonical = json.dumps(
            {
                "format_version": manifest.format_version,
                "manifest_sha256": manifest_digest,
                "rules": [
                    {
                        "namespace": rule.namespace,
                        "rule_id": rule.rule_id,
                        "revision": rule.revision,
                        "source_sha256": rule.source_sha256,
                    }
                    for rule in rules
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return Catalog(
            CatalogInfo(
                catalog_id=manifest.catalog_id,
                revision=manifest.revision,
                manifest_sha256=manifest_digest,
                ruleset_sha256=hashlib.sha256(canonical).hexdigest(),
                rules=tuple(rules),
            ),
            sources,
        )
    except (OSError, UnicodeError, ValidationError, json.JSONDecodeError) as exc:
        raise CatalogError("catalog cannot be validated") from exc
