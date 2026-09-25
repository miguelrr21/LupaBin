import json
import shutil
from pathlib import Path

import pytest

from lupabin.rules.catalog import CatalogError, load_catalog

ROOT = Path(__file__).parents[1] / "src/lupabin/rules/yara"


def copy_catalog(tmp_path):
    target = tmp_path / "rules"
    shutil.copytree(ROOT, target)
    return target


def test_catalog_is_stable_and_contains_four_unique_rules():
    one = load_catalog()
    assert one.info == load_catalog().info
    assert len(one.info.rules) == 4
    assert len(one.sources) == 4
    assert all(rule.namespace == rule.rule_id for rule in one.info.rules)
    assert all(rule.license == "Apache-2.0" for rule in one.info.rules)


def test_catalog_is_independent_of_current_directory(tmp_path, monkeypatch):
    expected = load_catalog().info
    monkeypatch.chdir(tmp_path)
    assert load_catalog().info == expected


@pytest.mark.parametrize("change", ["missing", "extra", "traversal", "duplicate", "crlf", "large"])
def test_catalog_rejects_unsafe_or_inconsistent_resources(tmp_path, change):
    root = copy_catalog(tmp_path)
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    filename = manifest["rules"][0]["filename"]
    if change == "missing":
        (root / filename).unlink()
    elif change == "extra":
        (root / "extra.yar").write_text("rule extra { condition: true }")
    elif change == "traversal":
        manifest["rules"][0]["filename"] = "../outside.yar"
    elif change == "duplicate":
        manifest["rules"].append(manifest["rules"][0])
    elif change == "crlf":
        (root / filename).write_bytes((root / filename).read_bytes() + b"\r\n")
    else:
        (root / filename).write_bytes(b"x" * (16384 + 1))
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(CatalogError):
        load_catalog(root=root)


def test_source_and_metadata_changes_change_fingerprint(tmp_path):
    root = copy_catalog(tmp_path)
    original = load_catalog(root=root)
    first = original.info.rules[0]
    source = root / first.filename
    source.write_bytes(source.read_bytes() + b"\n")
    modified = load_catalog(root=root)
    assert modified.info.ruleset_sha256 != original.info.ruleset_sha256
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["rules"][0]["description"] = "Changed description"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    assert load_catalog(root=root).info.ruleset_sha256 != modified.info.ruleset_sha256
