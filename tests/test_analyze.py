"""Tests."""

from pathlib import Path

from security_finding_correlator.core import analyze_reports

FIXTURES = Path(__file__).resolve().parent.parent / "sample_data"


class TestSecurityFindingCorrelator:
    def test_loads_reports(self) -> None:
        r = analyze_reports([FIXTURES / "sample_report_cookie.json", FIXTURES / "sample_report_cors.json"])
        assert len(r.source_reports) == 2

    def test_deduplicates(self) -> None:
        r = analyze_reports([FIXTURES / "sample_report_cookie.json", FIXTURES / "sample_report_cors.json"])
        assert r.correlation.duplicate_count >= 1

    def test_correlates_multi_tool(self) -> None:
        r = analyze_reports([FIXTURES / "sample_report_cookie.json", FIXTURES / "sample_report_cors.json"])
        multi = [g for g in r.correlation.groups if len(g.source_tools) > 1]
        assert len(multi) >= 1
