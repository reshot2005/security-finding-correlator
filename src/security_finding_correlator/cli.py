"""CLI."""

from __future__ import annotations

from enum import IntEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from secintel_core import export_json

from security_finding_correlator.core import TOOL_NAME, TOOL_VERSION, AnalysisConfig, analyze_reports

app = typer.Typer(
    name=TOOL_NAME,
    help="De-duplicate and confidence-score findings across web tools.",
    no_args_is_help=True,
)
console = Console()


class ExitCode(IntEnum):
    INPUT_ERROR = 2


@app.command()
def analyze(
    report_files: list[Path] = typer.Argument(..., help="secintel-core JSON report files"),
    json_output: bool = typer.Option(False, "--json"),
    sample: bool = typer.Option(False, "--sample"),
) -> None:
    try:
        result = analyze_reports(report_files, config=AnalysisConfig(base_dir=Path.cwd()), is_sample=sample)
    except (ValueError, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=ExitCode.INPUT_ERROR) from exc
    multi = sum(1 for g in result.correlation.groups if len(g.source_tools) > 1)
    table = Table(title="Finding Correlation")
    table.add_column("Metric")
    table.add_column("Value")
    table.add_row("Source reports", str(len(result.source_reports)))
    table.add_row("Unique groups", str(result.correlation.unique_count))
    table.add_row("Multi-tool confirmed", str(multi))
    console.print(table)
    typer.echo(export_json(result.report))
    raise typer.Exit(code=0)


@app.command()
def version() -> None:
    console.print(f"{TOOL_NAME} v{TOOL_VERSION}")
