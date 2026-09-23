from datetime import date
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from dissect.evidence.primitives import Model

EntryId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$", max_length=96)]
Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
Revision = Annotated[str, Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$", max_length=32)]
Text = Annotated[str, Field(min_length=1, max_length=320)]


class Source(Model):
    title: Text
    publisher: Annotated[str, Field(min_length=1, max_length=120)]
    url: Annotated[str, Field(pattern=r"^https://[^\s\"<>`]+$", max_length=512)]
    # When a person or agent last checked that the page exists and supports the entry.
    verified_on: date


class Entry(Model):
    """General knowledge, never a statement about a sample."""

    id: EntryId
    title: Annotated[str, Field(min_length=1, max_length=120)]
    revision: Revision
    lang: Literal["es"]
    summary: Text
    body: Annotated[str, Field(min_length=1, max_length=4000)]
    # What the concept, when observed in a sample, does not establish by itself.
    not_proven: Text | None = None
    related: Annotated[tuple[EntryId, ...], Field(max_length=16)] = ()
    sources: Annotated[tuple[Source, ...], Field(min_length=1, max_length=8)]

    @model_validator(mode="after")
    def coherent(self) -> Self:
        if len(set(self.related)) != len(self.related) or self.id in self.related:
            raise ValueError("related entries must be unique and exclude the entry itself")
        if len({source.url for source in self.sources}) != len(self.sources):
            raise ValueError("duplicate source URL")
        return self


class ManifestEntry(Model):
    id: EntryId
    filename: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_.]*\.toml$", max_length=112)]
    sha256: Digest

    @model_validator(mode="after")
    def named(self) -> Self:
        if self.filename != self.id + ".toml":
            raise ValueError("entry filename must be its id")
        return self


class Manifest(Model):
    format_version: Literal["1"]
    catalog_id: Literal["dissect_glossary"]
    revision: Revision
    entries: Annotated[tuple[ManifestEntry, ...], Field(min_length=1, max_length=512)]

    @model_validator(mode="after")
    def canonical(self) -> Self:
        ids = tuple(entry.id for entry in self.entries)
        if ids != tuple(sorted(set(ids))):
            raise ValueError("manifest entries must be unique and sorted")
        return self


class GlossaryInfo(Model):
    catalog_id: Literal["dissect_glossary"]
    revision: Revision
    digest: Digest
