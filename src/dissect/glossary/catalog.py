"""Reviewed glossary catalog: TOML entries pinned by a SHA-256 manifest.

Editing an entry without updating its digest in the manifest fails to load, so
every content change is a deliberate, reviewable manifest change as well.
Maintainers regenerate the manifest with `python -m dissect.glossary.catalog --write`.
"""

import argparse
import hashlib
import json
import tomllib
from dataclasses import dataclass
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from dissect.glossary.models import Entry, GlossaryInfo, Manifest

MAX_ENTRY_BYTES = 16384
MAX_MANIFEST_BYTES = 131072


class GlossaryError(ValueError):
    pass


@dataclass(frozen=True)
class Glossary:
    info: GlossaryInfo
    entries: dict[str, Entry]


def default_root() -> Traversable:
    return files("dissect").joinpath("glossary", "entries")


def read_resource(root: Traversable, filename: str, maximum: int) -> bytes:
    path = root.joinpath(filename)
    if isinstance(path, Path):
        if path.is_symlink() or path.resolve().parent != Path(str(root)).resolve():
            raise GlossaryError("unsafe glossary resource")
    with path.open("rb") as stream:
        content = stream.read(maximum + 1)
    if (
        not content
        or len(content) > maximum
        or b"\r" in content
        or content.startswith(b"\xef\xbb\xbf")
    ):
        raise GlossaryError("resource is empty, oversized or not canonical UTF-8/LF")
    content.decode("utf-8")
    return content


def tuples(value: Any) -> Any:
    """TOML arrays become tuples, as the strict models expect."""
    if isinstance(value, list):
        return tuple(tuples(item) for item in value)
    if isinstance(value, dict):
        return {key: tuples(item) for key, item in value.items()}
    return value


def load_glossary(*, root: Traversable | None = None) -> Glossary:
    resources = root if root is not None else default_root()
    try:
        raw = read_resource(resources, "manifest.json", MAX_MANIFEST_BYTES)
        manifest = Manifest.model_validate_json(raw)
        expected = {entry.filename for entry in manifest.entries}
        actual = {entry.name for entry in resources.iterdir() if entry.name.endswith(".toml")}
        if actual != expected:
            raise GlossaryError("entry inventory differs from manifest")
        entries: dict[str, Entry] = {}
        for pinned in manifest.entries:
            content = read_resource(resources, pinned.filename, MAX_ENTRY_BYTES)
            if hashlib.sha256(content).hexdigest() != pinned.sha256:
                raise GlossaryError(f"entry changed without updating the manifest: {pinned.id}")
            entry = Entry.model_validate(tuples(tomllib.loads(content.decode("utf-8"))))
            if entry.id != pinned.id:
                raise GlossaryError("entry id differs from its manifest record")
            entries[entry.id] = entry
        for entry in entries.values():
            missing = [ref for ref in entry.related if ref not in entries]
            if missing:
                raise GlossaryError(f"{entry.id} relates to unknown entries: {missing}")
        digest = hashlib.sha256(raw).hexdigest()
        return Glossary(
            GlossaryInfo(catalog_id=manifest.catalog_id, revision=manifest.revision, digest=digest),
            entries,
        )
    except (OSError, UnicodeError, ValidationError, tomllib.TOMLDecodeError) as exc:
        raise GlossaryError("glossary cannot be validated") from exc


def write_manifest(directory: Path, revision: str) -> None:
    """Pin every entry file's digest; only for maintainers, after reviewing the content."""
    records = []
    for path in sorted(directory.glob("*.toml")):
        content = path.read_bytes()
        records.append(
            {
                "id": path.name.removesuffix(".toml"),
                "filename": path.name,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    manifest = {
        "format_version": "1",
        "catalog_id": "dissect_glossary",
        "revision": revision,
        "entries": records,
    }
    Manifest.model_validate_json(json.dumps(manifest))
    text = json.dumps(manifest, indent=1, ensure_ascii=False) + "\n"
    (directory / "manifest.json").write_bytes(text.encode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate or re-pin the glossary catalog.")
    parser.add_argument("--write", metavar="REVISION", help="re-pin digests with this revision")
    args = parser.parse_args()
    if args.write:
        write_manifest(Path(str(default_root())), args.write)
    glossary = load_glossary()
    print(
        f"{len(glossary.entries)} entries, revision {glossary.info.revision}, "
        f"digest {glossary.info.digest}"
    )


if __name__ == "__main__":
    main()
