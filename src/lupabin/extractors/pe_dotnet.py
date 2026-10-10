"""The metadata of a .NET assembly (evidence/dotnet.py): its root, the native functions
it declares, the members it names and the types it defines. Nothing is published from
metadata that is not in the layout the method reads."""

from lupabin.evidence import dotnet_checks
from lupabin.evidence.collector import Collector, Progress
from lupabin.extractors.pe_layout import Layout


def read_dotnet(layout: Layout, collector: Collector, progress: Progress) -> None:
    if not layout.safe:
        progress.issue("dotnet", "unsafe_mapping", blocked=True)
        return
    try:
        derived = dotnet_checks.derive(layout.data, collector.limits.string_characters)
    except ValueError:
        progress.issue("dotnet", "dotnet_unsupported_layout", blocked=True)
        return
    if derived is None:
        progress.complete("dotnet")
        return
    metadata, facts = derived
    progress.examined["dotnet"] = len(facts)
    if metadata.unreadable:
        progress.issue("dotnet", "dotnet_unreadable_rows", limit=True)
    if dotnet_checks.truncated(metadata):
        progress.issue("dotnet", "dotnet_limit", limit=True)
    for key, payload, location in facts:
        refs = () if key == dotnet_checks.ROOT_KEY else (dotnet_checks.ROOT_KEY,)
        if not collector.add(key, progress, "dotnet", payload, location, refs):
            return
    progress.complete("dotnet")
