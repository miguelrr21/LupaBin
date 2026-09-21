from datetime import UTC, datetime

from dissect.analysis import analyze_bytes
from dissect.extractors.pe import PEExtractor
from tests.fixtures.pe_builder import build_pe


class BrokenExtractor:
    source = "broken"
    version = "test"

    def extract(self, data, limits):
        raise RuntimeError("C:/private/path and arbitrary binary data")


def test_extractor_failure_is_sanitized_and_preserves_valid_facts():
    report = analyze_bytes(build_pe(), extractors=(PEExtractor(), BrokenExtractor()))
    assert report.analysis.status == "partial"
    assert len(report.evidence) == 1
    assert report.extractor_errors[0].code == "extractor_failure"
    assert "private" not in report.model_dump_json()
    assert "arbitrary" not in report.model_dump_json()


def test_fixed_clock_produces_identical_complete_report():
    now = datetime(2026, 9, 20, tzinfo=UTC)
    assert analyze_bytes(build_pe(), clock=lambda: now) == analyze_bytes(
        build_pe(), clock=lambda: now
    )
