"""Cross-tool finding correlation and deduplication."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from secintel_core import Report
from secintel_core.security import bounded_read_file


@dataclass(frozen=True)
class CorrelatedGroup:
    group_key: str
    finding_ids: tuple[str, ...]
    source_tools: tuple[str, ...]
    title: str
    tags: tuple[str, ...]
    max_confidence: float
    severity: str


@dataclass(frozen=True)
class CorrelationResult:
    groups: list[CorrelatedGroup]
    unique_count: int
    duplicate_count: int


def _normalize_title(title: str) -> str:
    cleaned = re.sub(r"\s+", " ", title.lower().strip())
    return re.sub(r"[^a-z0-9 ]", "", cleaned)


def _group_key(finding_title: str, tags: list[str]) -> str:
    del tags  # title is the primary dedup key; tags used for enrichment only
    return _normalize_title(finding_title)


def load_reports(paths: list[Path]) -> list[Report]:
    reports: list[Report] = []
    for path in paths:
        data = json.loads(bounded_read_file(path, max_bytes=50 * 1024 * 1024))
        reports.append(Report.model_validate(data))
    return reports


def correlate_reports(reports: list[Report]) -> CorrelationResult:
    buckets: dict[str, list[tuple[str, str, list[str], float, str, str]]] = {}
    total = 0
    for report in reports:
        tool = report.provenance.tool_name
        for finding in report.findings:
            if finding.classification.value in {"OBSERVED", "DERIVED", "INFO"}:
                continue
            if finding.severity.value == "INFO":
                continue
            total += 1
            key = _group_key(finding.title, finding.tags)
            score = finding.confidence.score if finding.confidence else 0.5
            buckets.setdefault(key, []).append(
                (finding.id, tool, finding.tags, score, finding.severity.value, finding.title)
            )

    groups: list[CorrelatedGroup] = []
    duplicate_count = 0
    for key, items in buckets.items():
        tools = tuple(dict.fromkeys(t for _, t, _, _, _, _ in items))
        ids = tuple(i for i, _, _, _, _, _ in items)
        if len(items) > 1:
            duplicate_count += len(items) - 1
        groups.append(
            CorrelatedGroup(
                group_key=key,
                finding_ids=ids,
                source_tools=tools,
                title=items[0][5],
                tags=tuple(dict.fromkeys(t for _, _, tags, _, _, _ in items for t in tags)),
                max_confidence=max(s for _, _, _, s, _, _ in items),
                severity=max((sev for _, _, _, _, sev, _ in items), key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0)),
            )
        )
    groups.sort(key=lambda g: (-len(g.source_tools), -g.max_confidence))
    return CorrelationResult(groups=groups, unique_count=len(groups), duplicate_count=duplicate_count)
