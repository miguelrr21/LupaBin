import asyncio

from lupabin.evidence.collector import Collector, Progress
from lupabin.evidence.primitives import Component, Source
from lupabin.evidence.yara import YaraContext
from lupabin.extractors.base import Extraction
from lupabin.rules.catalog import CatalogError, load_catalog
from lupabin.rules.process import YaraProcessError, scan_child


class YaraExtractor:
    source: Source = "yara"
    version = "lupabin-yara-v1"

    def extract(self, data: bytes, collector: Collector, progress: Progress) -> Extraction:
        limits = collector.limits.yara
        try:
            catalog = load_catalog(limits)
        except CatalogError:
            progress.block_remaining("yara_catalog_invalid")
            return Extraction("unknown", progress)
        progress.yara_context = YaraContext(catalog=catalog.info)
        try:
            result = asyncio.run(scan_child(data, limits, catalog))
        except YaraProcessError as exc:
            progress.block_remaining(exc.code)
            return Extraction("unknown", progress)
        progress.yara_context = result.context

        def confirmed(component: Component, count: int) -> None:
            progress.examined[component] = count
            progress.unknown_examined.discard(component)
            progress.complete(component)

        if result.rules_ok:
            confirmed("yara_rules", len(catalog.info.rules))
        if not result.scan_ok:
            progress.block_remaining(result.reason or "yara_scan_error")
            return Extraction("unknown", progress)
        confirmed("yara_scan", len(catalog.info.rules))
        progress.examined["yara_evidence"] = len(result.matches) + result.omitted_rules
        progress.unknown_examined.discard("yara_evidence")
        for match in result.matches:
            if not collector.add(
                f"yara:{match.namespace}:{match.rule_id}", progress, "yara_evidence", match, None
            ):
                continue
            if match.omitted_instances != 0:
                progress.issue("yara_evidence", "yara_instance_limit", limit=True)
            if any(not instance.complete for instance in match.instances):
                progress.issue("yara_evidence", "yara_data_limit", limit=True)
        if result.omitted_rules:
            progress.issue("yara_evidence", "yara_match_limit", limit=True)
        progress.complete("yara_evidence")
        return Extraction("unknown", progress)
