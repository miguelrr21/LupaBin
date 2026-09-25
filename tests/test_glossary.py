import json
import re
import shutil
from pathlib import Path

import pytest

from lupabin.glossary.catalog import GlossaryError, load_glossary, write_manifest

ROOT = Path(__file__).parents[1] / "src/lupabin/glossary/entries"
ENTRY = """id = "{id}"
title = "Título"
revision = "1.0.0"
lang = "es"
summary = "Resumen."
body = "Cuerpo."
related = {related}
sources = [
  {{ title = "Fuente", publisher = "Editor", url = "{url}", verified_on = 2026-09-23 }},
]
"""


def entry(id="a.b", related="[]", url="https://example.invalid/a"):
    return ENTRY.format(id=id, related=related, url=url)


def catalog(tmp_path, *entries):
    target = tmp_path / "entries"
    target.mkdir(parents=True)
    for text in entries:
        name = text.split('"')[1]
        (target / f"{name}.toml").write_bytes(text.encode("utf-8"))
    write_manifest(target, "1.0.0")
    return target


def copy_catalog(tmp_path):
    target = tmp_path / "entries"
    shutil.copytree(ROOT, target)
    return target


def test_repository_glossary_loads_and_is_stable():
    one = load_glossary()
    assert one == load_glossary()
    assert one.entries
    assert all(entry.sources for entry in one.entries.values())
    assert all(entry.lang == "es" for entry in one.entries.values())


def test_repository_glossary_is_independent_of_current_directory(tmp_path, monkeypatch):
    expected = load_glossary().info
    monkeypatch.chdir(tmp_path)
    assert load_glossary().info == expected


def github_slug(heading):
    text = re.sub(r"[^\w\- ]", "", heading.strip().lower())
    return text.replace(" ", "-")


def test_project_document_sources_point_to_existing_headings():
    repository = Path(__file__).parents[1]
    documents = {
        source.document
        for entry in load_glossary().entries.values()
        for source in entry.sources
        if source.document
    }
    for document in documents:
        path, anchor = document.split("#")
        headings = [
            line.lstrip("#").strip()
            for line in (repository / path).read_text("utf-8").splitlines()
            if line.startswith("#")
        ]
        assert anchor in {github_slug(h) for h in headings}, document


def test_a_source_needs_exactly_one_location(tmp_path):
    both = entry().replace('url = "', 'document = "docs/a.md#b", url = "')
    neither = entry().replace('url = "https://example.invalid/a", ', "")
    for text in (both, neither):
        with pytest.raises(GlossaryError):
            load_glossary(root=catalog(tmp_path / str(len(text)), text))


def test_minimal_catalog_loads(tmp_path):
    glossary = load_glossary(root=catalog(tmp_path, entry("a.b"), entry("c", related='["a.b"]')))
    assert set(glossary.entries) == {"a.b", "c"}
    assert glossary.entries["c"].related == ("a.b",)


def test_editing_an_entry_without_repinning_fails(tmp_path):
    root = copy_catalog(tmp_path)
    path = next(root.glob("*.toml"))
    path.write_bytes(path.read_bytes().replace(b'lang = "es"', b'lang = "es"\n'))
    with pytest.raises(GlossaryError):
        load_glossary(root=root)


def test_unlisted_or_missing_files_fail(tmp_path):
    root = catalog(tmp_path, entry("a.b"))
    (root / "extra.toml").write_bytes(entry("extra").encode())
    with pytest.raises(GlossaryError):
        load_glossary(root=root)
    (root / "extra.toml").unlink()
    (root / "a.b.toml").unlink()
    with pytest.raises(GlossaryError):
        load_glossary(root=root)


def test_unknown_related_entry_fails(tmp_path):
    with pytest.raises(GlossaryError):
        load_glossary(root=catalog(tmp_path, entry("a.b", related='["nope"]')))


@pytest.mark.parametrize(
    "text",
    [
        entry(url="http://example.invalid/a"),
        entry(url="javascript:alert(1)"),
        entry(related='["a.b"]'),
        entry().replace('lang = "es"', 'lang = "en"'),
        entry().replace("sources = [", "unexpected = 1\nsources = ["),
        entry().split("sources = [")[0] + "sources = []\n",
    ],
    ids=["http", "scheme", "self-related", "language", "extra-field", "no-sources"],
)
def test_invalid_entries_are_rejected(tmp_path, text):
    with pytest.raises(GlossaryError):
        load_glossary(root=catalog(tmp_path, text))


def test_crlf_and_bom_are_rejected(tmp_path):
    root = catalog(tmp_path, entry("a.b"))
    path = root / "a.b.toml"
    for content in (path.read_bytes().replace(b"\n", b"\r\n"), b"\xef\xbb\xbf" + path.read_bytes()):
        path.write_bytes(content)
        write_manifest(root, "1.0.0")
        with pytest.raises(GlossaryError):
            load_glossary(root=root)


def test_manifest_must_be_sorted_and_named_by_id(tmp_path):
    root = catalog(tmp_path, entry("a.b"), entry("c"))
    manifest = json.loads((root / "manifest.json").read_text("utf-8"))
    manifest["entries"].reverse()
    (root / "manifest.json").write_text(json.dumps(manifest), "utf-8", newline="\n")
    with pytest.raises(GlossaryError):
        load_glossary(root=root)


def test_entry_id_must_match_its_file(tmp_path):
    root = catalog(tmp_path, entry("a.b"))
    path = root / "a.b.toml"
    path.write_bytes(path.read_bytes().replace(b'id = "a.b"', b'id = "a.c"'))
    write_manifest(root, "1.0.0")
    with pytest.raises(GlossaryError):
        load_glossary(root=root)
