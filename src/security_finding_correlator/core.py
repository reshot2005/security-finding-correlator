"""Core finding correlation analysis."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secintel_core import (
    Classification,
    Confidence,
    Evidence,
    Finding,
    InputArtifact,
    Provenance,
    Report,
    Severity,
    build_environment_info,
    canonical_config_hash,
    deterministic_finding_id,
    reproducible_now,
    sha256_file,
)
from secintel_core.security import safe_resolve_path

from security_finding_correlator.correlator import CorrelatedGroup, CorrelationResult, correlate_reports, load_reports

TOOL_NAME = "security-finding-correlator"
TOOL_VERSION = "0.1.0"
_SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}


@dataclass
class AnalysisConfig:
    base_dir: Path = field(default_factory=lambda: Path.cwd())
    max_bytes: int = 50 * 1024 * 1024


@dataclass
class AnalysisResult:
    report: Report
    correlation: CorrelationResult
    source_reports: list[Report]


def _resolve(base: Path, p: Path | str) -> Path:
    up = Path(p)
    return up.resolve() if up.is_absolute() else safe_resolve_path(base, p)


def analyze_reports(
    input_paths: Sequence[Path | str],
    *,
    config: AnalysisConfig | None = None,
    is_sample: bool = False,
) -> AnalysisResult:
    cfg = config or AnalysisConfig()
    resolved_list: list[Path] = []
    artifacts: list[InputArtifact] = []
    for input_path in input_paths:
        resolved = _resolve(cfg.base_dir, input_path)
        if not resolved.is_file():
            raise ValueError(f"Report file not found: {resolved}")
        input_hash = sha256_file(resolved, max_bytes=cfg.max_bytes)
        artifacts.append(InputArtifact(path=str(resolved), sha256=input_hash, size_bytes=resolved.stat().st_size))
        resolved_list.append(resolved)

    started = reproducible_now()
    source_reports = load_reports(resolved_list)
    correlation = correlate_reports(source_reports)
    findings = _emit_findings(
        correlation,
        source=",".join(str(p) for p in resolved_list),
        started=started,
    )

    ended = reproducible_now()
    report = Report(
        provenance=Provenance(
            tool_name=TOOL_NAME,
            tool_version=TOOL_VERSION,
            config_hash=canonical_config_hash({}),
            inputs=artifacts,
            analysis_started_at=started,
            analysis_ended_at=ended,
            environment=build_environment_info(),
        ),
        findings=findings,
        is_sample_data=is_sample,
        metadata={
            "source_report_count": len(source_reports),
            "unique_groups": correlation.unique_count,
            "duplicates_removed": correlation.duplicate_count,
        },
    )
    return AnalysisResult(report=report, correlation=correlation, source_reports=source_reports)


def _emit_findings(
    correlation: CorrelationResult,
    *,
    source: str,
    started: Any,
) -> list[Finding]:
    findings: list[Finding] = []
    multi_tool = [g for g in correlation.groups if len(g.source_tools) > 1]
    findings.append(
        Finding(
            id=deterministic_finding_id("correlation-observed", source, {"reports": correlation.unique_count}),
            title=f"Findings correlated: {correlation.unique_count} unique groups from {len(correlation.groups)} buckets",
            classification=Classification.OBSERVED,
            evidence=[Evidence(source=source, locator={"unique": correlation.unique_count, "duplicates": correlation.duplicate_count}, retrieved_at=started)],
            method="Cross-report title/tag clustering",
            why_it_matters="Deduplication reduces alert fatigue.",
            plain_language=f"Consolidated into {correlation.unique_count} unique finding groups.",
            severity=Severity.INFO,
            tags=["correlation"],
            timestamp=started,
        )
    )
    for group in multi_tool:
        boosted = min(0.99, group.max_confidence + 0.05 * (len(group.source_tools) - 1))
        findings.append(
            Finding(
                id=deterministic_finding_id("correlated-finding", source, {"key": group.group_key}),
                title=f"Correlated: {group.group_key.split('|')[0]}",
                classification=Classification.CORRELATED,
                confidence=Confidence(
                    score=boosted,
                    rationale=f"Confirmed by {len(group.source_tools)} tools: {', '.join(group.source_tools)}",
                    supporting_indicators=list(group.source_tools),
                ),
                evidence=[Evidence(source=source, locator={"tools": list(group.source_tools), "finding_ids": list(group.finding_ids)}, retrieved_at=started)],
                method="Multi-tool finding correlation",
                why_it_matters="Multi-tool agreement increases confidence.",
                plain_language=f"Issue confirmed across {', '.join(group.source_tools)}.",
                severity=_SEV.get(group.severity, Severity.MEDIUM),
                tags=["correlated", *list(group.tags)[:3]],
                timestamp=started,
            )
        )
    return findings
