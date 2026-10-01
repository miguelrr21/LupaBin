"""UPX 5 blocks (evidence/upx.py): decompressed in the worker, never run. The host
derives the same facts again (evidence/upx_checks.py)."""

from lupabin.evidence import upx
from lupabin.evidence.collector import Collector, Progress
from lupabin.evidence.facts import SectionEvidence
from lupabin.evidence.primitives import Location
from lupabin.evidence.upx_checks import image_data, import_data, spans, string_data
from lupabin.extractors.pe_layout import Layout


def read_upx(layout: Layout, collector: Collector, progress: Progress) -> None:
    if not layout.safe:
        progress.issue("upx", "unsafe_mapping", blocked=True)
        return
    # the published sections, which are all the host will have to derive the same
    published = [fact.data for fact in collector.facts if isinstance(fact, SectionEvidence)]
    derived = upx.derive(layout.data, spans(published))
    progress.examined["upx"] = 0 if derived is None else 1
    if derived is None:
        progress.complete("upx")
        return
    header = derived.unpacked.header
    where = Location(offset=header.offset, length=upx.HEADER_SIZE)
    if not collector.add("pe:upx", progress, "upx", image_data(derived), where):
        return
    if derived.dlls is None:
        progress.issue("upx", "upx_layout_unrecognized", limit=True)
        return
    for index, item in enumerate(import_data(derived)):
        if not collector.add(f"pe:upx:{index}", progress, "upx", item, None, refs=("pe:upx",)):
            return
    if derived.image is None:
        progress.issue("upx", "upx_rebuild_unrecognized", limit=True)
        return
    limits = collector.limits
    texts = string_data(derived, limits.string_characters, limits.strings + 1)
    for index, text in enumerate(texts[: limits.strings]):
        if not text.complete:
            progress.issue("upx", "string_length_limit", limit=True)
        if not collector.add(f"pe:upx:s{index}", progress, "upx", text, None, refs=("pe:upx",)):
            return
    if len(texts) > limits.strings:
        progress.issue("upx", "string_limit", limit=True)
        return
    progress.complete("upx")
