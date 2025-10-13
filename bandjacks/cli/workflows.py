"""Integrated workflows for end-to-end processing and analysis."""

import os
import sys
import click
import subprocess
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

console = Console()


@click.group()
@click.pass_context
def workflow(ctx):
    """End-to-end workflows for extraction and analytics."""
    pass


@workflow.command("process-reports")
@click.argument('report_dir', type=click.Path(exists=True))
@click.option('--workers', default=3, help='Number of parallel workers')
@click.option('--analyze', is_flag=True, help='Run analytics after extraction')
@click.option('--export-dir', type=click.Path(), help='Export analytics to directory')
@click.option('--api', is_flag=True, help='Use API for extraction')
@click.option('--neo4j-uri', default=os.getenv("NEO4J_URI", "bolt://localhost:7687"))
@click.option('--neo4j-user', default=os.getenv("NEO4J_USER", "neo4j"))
@click.option('--neo4j-password', default=os.getenv("NEO4J_PASSWORD", ""))
@click.pass_context
def process_reports(ctx, report_dir, workers, analyze, export_dir, api, neo4j_uri, neo4j_user, neo4j_password):
    """
    Process a directory of reports and optionally run analytics.

    Example:
        bandjacks workflow process-reports ./reports/ --analyze --export-dir ./results/
    """
    console.print(Panel("[bold]Report Processing Workflow[/bold]", style="blue"))

    report_path = Path(report_dir)

    # Step 1: Extract reports
    console.print("\n[bold cyan]Step 1: Extracting techniques from reports[/bold cyan]")

    extract_cmd = [
        sys.executable, "-m", "bandjacks.cli.batch_extract",
        str(report_path),
        "--workers", str(workers),
        "--store-in-neo4j",
        "--neo4j-uri", neo4j_uri,
        "--neo4j-user", neo4j_user,
        "--neo4j-password", neo4j_password
    ]

    if api:
        extract_cmd.append("--api")

    console.print(f"[dim]Running: {' '.join(extract_cmd)}[/dim]")
    result = subprocess.run(extract_cmd)

    if result.returncode != 0:
        console.print("[red]✗ Extraction failed[/red]")
        sys.exit(1)

    console.print("[green]✓ Extraction complete[/green]")

    # Step 2: Run analytics if requested
    if analyze:
        console.print("\n[bold cyan]Step 2: Running co-occurrence analytics[/bold cyan]")

        if export_dir:
            export_path = Path(export_dir)
            export_path.mkdir(parents=True, exist_ok=True)

            # Run global co-occurrence analysis
            console.print("[yellow]→ Computing global co-occurrence metrics...[/yellow]")
            global_cmd = [
                "bandjacks", "analytics", "global",
                "--limit", "100",
                "--format", "csv",
                "--output", str(export_path / "global_cooccurrence.csv")
            ]
            subprocess.run(global_cmd)

            # Run bundle analysis
            console.print("[yellow]→ Extracting technique bundles...[/yellow]")
            bundle_cmd = [
                "bandjacks", "analytics", "bundles",
                "--format", "json",
                "--output", str(export_path / "technique_bundles.json")
            ]
            subprocess.run(bundle_cmd)

            console.print(f"[green]✓ Analytics exported to {export_path}[/green]")
        else:
            # Just display analytics
            console.print("[yellow]→ Computing global co-occurrence metrics...[/yellow]")
            subprocess.run(["bandjacks", "analytics", "global", "--limit", "25"])

    console.print("\n[bold green]✓ Workflow complete![/bold green]")


@workflow.command("analyze-actor")
@click.argument('intrusion_set_id')
@click.option('--export-dir', type=click.Path(), help='Export directory')
@click.option('--include-bundles', is_flag=True, help='Export technique bundles')
@click.option('--neo4j-uri', default=os.getenv("NEO4J_URI", "bolt://localhost:7687"))
@click.option('--neo4j-user', default=os.getenv("NEO4J_USER", "neo4j"))
@click.option('--neo4j-password', default=os.getenv("NEO4J_PASSWORD", ""))
@click.pass_context
def analyze_actor(ctx, intrusion_set_id, export_dir, include_bundles, neo4j_uri, neo4j_user, neo4j_password):
    """
    Comprehensive analysis of a specific intrusion set.

    Example:
        bandjacks workflow analyze-actor intrusion-set--<uuid> --export-dir ./actor_analysis/
    """
    console.print(Panel(f"[bold]Actor Analysis: {intrusion_set_id}[/bold]", style="blue"))

    if not export_dir:
        console.print("[red]Error: --export-dir is required[/red]")
        sys.exit(1)

    export_path = Path(export_dir)
    export_path.mkdir(parents=True, exist_ok=True)

    # Run actor co-occurrence analysis
    console.print("\n[bold cyan]Computing actor-specific co-occurrence...[/bold cyan]")
    actor_cmd = [
        "bandjacks", "analytics", "actor",
        intrusion_set_id,
        "--format", "json",
        "--output", str(export_path / "actor_cooccurrence.json")
    ]
    subprocess.run(actor_cmd)

    # Extract bundles if requested
    if include_bundles:
        console.print("\n[bold cyan]Extracting technique bundles...[/bold cyan]")
        bundle_cmd = [
            "bandjacks", "analytics", "bundles",
            "--actor", intrusion_set_id,
            "--format", "json",
            "--output", str(export_path / "actor_bundles.json")
        ]
        subprocess.run(bundle_cmd)

    console.print(f"\n[bold green]✓ Actor analysis exported to {export_path}[/bold green]")


@workflow.command("bulk-export")
@click.option('--export-dir', type=click.Path(), required=True, help='Export directory')
@click.option('--neo4j-uri', default=os.getenv("NEO4J_URI", "bolt://localhost:7687"))
@click.option('--neo4j-user', default=os.getenv("NEO4J_USER", "neo4j"))
@click.option('--neo4j-password', default=os.getenv("NEO4J_PASSWORD", ""))
@click.pass_context
def bulk_export(ctx, export_dir, neo4j_uri, neo4j_user, neo4j_password):
    """
    Export all analytics data (co-occurrence, bundles, actors).

    Example:
        bandjacks workflow bulk-export --export-dir ./analytics_export/
    """
    console.print(Panel("[bold]Bulk Analytics Export[/bold]", style="blue"))

    export_path = Path(export_dir)
    export_path.mkdir(parents=True, exist_ok=True)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:

        # Global co-occurrence
        task1 = progress.add_task("Exporting global co-occurrence...", total=None)
        global_cmd = [
            "bandjacks", "analytics", "global",
            "--limit", "500",
            "--format", "csv",
            "--output", str(export_path / "global_cooccurrence.csv")
        ]
        subprocess.run(global_cmd, capture_output=True)
        progress.update(task1, completed=True)

        # JSON version
        task2 = progress.add_task("Exporting global co-occurrence (JSON)...", total=None)
        global_json_cmd = [
            "bandjacks", "analytics", "global",
            "--limit", "500",
            "--format", "json",
            "--output", str(export_path / "global_cooccurrence.json")
        ]
        subprocess.run(global_json_cmd, capture_output=True)
        progress.update(task2, completed=True)

        # Bundles
        task3 = progress.add_task("Exporting technique bundles...", total=None)
        bundle_cmd = [
            "bandjacks", "analytics", "bundles",
            "--format", "csv",
            "--output", str(export_path / "technique_bundles.csv")
        ]
        subprocess.run(bundle_cmd, capture_output=True)
        progress.update(task3, completed=True)

    console.print(f"\n[bold green]✓ Analytics data exported to {export_path}[/bold green]")
    console.print("\nExported files:")
    for file in export_path.glob("*"):
        console.print(f"  • {file.name}")


if __name__ == "__main__":
    workflow()
