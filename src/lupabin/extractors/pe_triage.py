"""Triage facts (evidence/triage.py): what the debug directory, the certificate table,
the bytes after the sections and the version resource hold.

Each component publishes only what its reader read whole; what a reader left out makes
the component partial instead of being guessed at.
"""

from lupabin.evidence import pe_triage, triage
from lupabin.evidence.collector import Collector, Progress
from lupabin.evidence.facts import (
    CertificateData,
    OverlayData,
    PdbData,
    VersionStringData,
)
from lupabin.evidence.primitives import Component, Location, Name

COMPONENTS: tuple[Component, ...] = ("debug_info", "certificates", "overlay", "version_info")


def _issues(progress: Progress, component: Component, issues: tuple[pe_triage.Issue, ...]) -> None:
    for issue in issues:
        if issue.kind == "limit":
            progress.issue(component, "triage_limit", limit=True)
        elif issue.code != "debug_type_unsupported":
            progress.issue(component, "triage_unreadable", limit=True)


def read_triage(data: bytes, collector: Collector, progress: Progress) -> None:
    result = pe_triage.read(data, budgets=triage.BUDGETS)
    if result.layout is None:
        for component in COMPONENTS:
            progress.issue(component, "triage_unreadable", blocked=True)
        return

    progress.examined["debug_info"] = len(result.codeview.items)
    for record in result.codeview.items:
        pointer = record.debug.pointer_to_raw_data
        raw = data[pointer : pointer + record.record_length]
        collector.add(
            f"pe:pdb:{record.debug.index}",
            progress,
            "debug_info",
            PdbData(
                debug_index=record.debug.index,
                raw_hex=raw.hex(),
                guid=record.guid,
                age=record.age,
                path=Name.from_bytes(record.path_raw) if record.path_raw else None,
            ),
            Location(offset=pointer, length=len(raw)),
        )
    _issues(progress, "debug_info", result.codeview.issues)
    progress.complete("debug_info")

    progress.examined["certificates"] = len(result.certificates.items)
    # A table that cannot be walked to its end publishes nothing: its entries would not
    # be the table's.
    if result.certificates.status == "complete":
        for entry in result.certificates.items:
            collector.add(
                f"pe:certificate:{entry.index}",
                progress,
                "certificates",
                CertificateData(
                    index=entry.index,
                    header_hex=data[entry.offset : entry.offset + 8].hex(),
                    revision=entry.revision,
                    certificate_type=entry.certificate_type,
                    content_sha256=entry.payload.sha256,
                    padding=entry.padding_length,
                ),
                Location(offset=entry.offset, length=entry.length),
            )
    _issues(progress, "certificates", result.certificates.issues)
    progress.complete("certificates")

    if result.overlay.status == "unavailable":
        progress.issue("overlay", "dependency_omitted", limit=True, blocked=True)
    else:
        progress.examined["overlay"] = len(result.overlay.items)
        for index, span in enumerate(result.overlay.items):
            collector.add(
                f"pe:overlay:{index}",
                progress,
                "overlay",
                OverlayData(sha256=span.sha256),
                Location(offset=span.offset, length=span.length),
            )
        _issues(progress, "overlay", result.overlay.issues)
        progress.complete("overlay")

    parsed = triage.read_resources(data, result)
    if parsed is None:
        progress.issue("version_info", "triage_unreadable", blocked=True)
        return
    texts = triage.version_texts(data, parsed, collector.limits.string_characters)
    progress.examined["version_info"] = texts.resources
    for text in texts.found:
        collector.add(
            f"pe:version:{text.offset}",
            progress,
            "version_info",
            VersionStringData(
                language=text.language,
                codepage=text.codepage,
                raw_hex=text.raw.hex(),
                key=text.key,
                value=text.value,
            ),
            Location(offset=text.offset, length=len(text.raw)),
        )
    if texts.unread:
        progress.issue("version_info", "triage_unreadable", limit=True)
    if texts.limited:
        progress.issue("version_info", "triage_limit", limit=True)
    progress.complete("version_info")
