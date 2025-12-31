"""CLI commands for Cloud Forensic Snapshot."""

import logging
import os
import socket
from datetime import datetime
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from cfs import __version__
from cfs.config import load_config, merge_cli_args, get_default_config
from cfs.types import CFSConfig, CloudProvider, CollectionScope, TimeWindow, EvidenceBundle
from cfs.cli.preflight import run_preflight_checks
from cfs.preservation import check_immutability, format_immutability_warning


console = Console()


def setup_logging(verbose: bool) -> None:
    """Configure logging with Rich handler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


@click.group()
@click.version_option(version=__version__, prog_name="Cloud Forensic Snapshot")
def cli() -> None:
    """Cloud Forensic Snapshot - Vendor-neutral cloud forensics acquisition tool.
    
    Collect, preserve, and validate log-based evidence across AWS, Azure, and GCP.
    """
    pass


@cli.command()
@click.option(
    "--provider", "-p",
    type=click.Choice(["aws", "azure", "gcp"], case_sensitive=False),
    help="Cloud provider to collect from",
)
@click.option(
    "--account-id", "-a",
    help="Cloud account/subscription/project ID",
)
@click.option(
    "--time-window", "-t",
    default="24h",
    help="Time window for collection (e.g., 24h, 7d, 30m)",
)
@click.option(
    "--incident-id", "-i",
    help="Incident ID for tracking (e.g., IR-2025-001)",
)
@click.option(
    "--output", "-o",
    type=click.Path(),
    default="./forensic_snapshot",
    help="Output directory for evidence",
)
@click.option(
    "--config", "-c",
    type=click.Path(exists=True),
    help="Path to YAML configuration file",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Simulate collection without actually collecting",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose logging",
)
@click.option(
    "--investigator",
    help="Name of the investigator (for chain of custody)",
)
@click.option(
    "--notes",
    help="Notes to include in chain of custody",
)
def snapshot(
    provider: Optional[str],
    account_id: Optional[str],
    time_window: str,
    incident_id: Optional[str],
    output: str,
    config: Optional[str],
    dry_run: bool,
    verbose: bool,
    investigator: Optional[str],
    notes: Optional[str],
) -> None:
    """Collect forensic evidence from a cloud provider.
    
    Examples:
    
        # Collect last 24 hours from AWS
        cfs snapshot --provider aws --account-id 123456789012 --incident-id IR-2025-001
        
        # Use config file with overrides
        cfs snapshot --config config.yaml --dry-run
        
        # Collect last 7 days with verbose logging
        cfs snapshot -p aws -a 123456789012 -t 7d -v
    """
    setup_logging(verbose)
    logger = logging.getLogger(__name__)
    
    # Print banner
    console.print(Panel.fit(
        f"[bold blue]Cloud Forensic Snapshot[/bold blue] v{__version__}\n"
        "[dim]Vendor-neutral cloud forensics acquisition tool[/dim]",
        border_style="blue",
    ))
    
    # Load and merge configuration
    try:
        if config:
            cfg = load_config(Path(config))
        else:
            from cfs.config import parse_config
            cfg = parse_config(get_default_config())
        
        # Override with CLI args
        cfg = merge_cli_args(
            cfg,
            provider=provider,
            account_id=account_id,
            time_window=time_window,
            incident_id=incident_id,
            output=output,
            dry_run=dry_run,
            verbose=verbose,
        )
    except Exception as e:
        console.print(f"[red]Configuration error:[/red] {e}")
        raise click.Abort()
    
    # Validate required fields
    if not cfg.account_id:
        console.print("[red]Error:[/red] --account-id is required")
        raise click.Abort()
    
    if not cfg.incident_id:
        console.print("[red]Error:[/red] --incident-id is required")
        raise click.Abort()
    
    # Display collection parameters
    _print_collection_params(cfg, dry_run)
    
    # Check immutability
    immutability_result = check_immutability(
        cfg.output_type,
        cfg.bucket_name,
        cfg.provider.value,
    )
    console.print(f"\n{format_immutability_warning(immutability_result)}")
    
    # Run preflight checks
    console.print("\n[bold]Running preflight checks...[/bold]")
    preflight_ok = run_preflight_checks(cfg)
    
    if not preflight_ok:
        console.print("[red]Preflight checks failed. Aborting.[/red]")
        raise click.Abort()
    
    console.print("[green]✓ Preflight checks passed[/green]")
    
    if dry_run:
        console.print("\n[yellow]DRY RUN MODE - No evidence will be collected[/yellow]")
        console.print("[dim]Remove --dry-run to perform actual collection[/dim]")
        context = click.get_current_context()
        context.exit(0)
    
    # Create output directory
    output_path = Path(output)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Create collection scope
    scope = CollectionScope(
        provider=cfg.provider,
        account_id=cfg.account_id,
        incident_id=cfg.incident_id,
    )
    
    # Create time window
    timeframe = TimeWindow.from_duration(cfg.time_window)
    
    # Initialize evidence bundle
    bundle = EvidenceBundle(
        incident_id=cfg.incident_id,
        provider=cfg.provider,
        account_id=cfg.account_id,
        collection_start=datetime.utcnow(),
        collection_end=datetime.utcnow(),  # Will be updated
        time_window=timeframe,
        output_path=output_path,
        collector_version=__version__,
        hostname=socket.gethostname(),
        investigator=investigator or "",
        notes=notes or "",
    )
    
    # Run collection
    console.print(f"\n[bold]Starting evidence collection for {cfg.provider.value.upper()}...[/bold]")
    
    collection_errors = []
    try:
        bundle, collection_errors = _run_collection(cfg, scope, timeframe, output_path, bundle)
        # Attach errors to bundle for manifest
        bundle.errors = collection_errors  # Dynamic attachment for manifest
    except Exception as e:
        logger.exception("Collection failed")
        console.print(f"[red]Collection failed:[/red] {e}")
        raise click.Abort()
    
    # Update collection end time
    bundle.collection_end = datetime.utcnow()
    
    # Generate preservation documents
    console.print("\n[bold]Generating preservation documents...[/bold]")
    _generate_preservation_docs(bundle, output_path)
    
    # Print summary
    _print_collection_summary(bundle, output_path, collection_errors)
    
    # Exit with appropriate code
    if collection_errors:
        console.print(f"\n[yellow]Completed with {len(collection_errors)} errors.[/yellow]")
        context = click.get_current_context()
        context.exit(1)
    else:
        context = click.get_current_context()
        context.exit(0)


def _print_collection_params(cfg: CFSConfig, dry_run: bool) -> None:
    """Print collection parameters table."""
    table = Table(title="Collection Parameters", show_header=False)
    table.add_column("Parameter", style="cyan")
    table.add_column("Value")
    
    table.add_row("Provider", cfg.provider.value.upper())
    table.add_row("Account ID", cfg.account_id)
    table.add_row("Incident ID", cfg.incident_id)
    table.add_row("Time Window", cfg.time_window)
    table.add_row("Output", str(cfg.output_path))
    table.add_row("Dry Run", "Yes" if dry_run else "No")
    
    console.print(table)


def _run_collection(
    cfg: CFSConfig,
    scope: CollectionScope,
    timeframe: TimeWindow,
    output_path: Path,
    bundle: EvidenceBundle,
) -> tuple[EvidenceBundle, list[str]]:
    """Run evidence collection for the specified provider.
    
    Returns:
        Tuple of (Updated EvidenceBundle, List of error messages)
    """
    from cfs.collectors.base import CollectorRegistry
    
    all_errors = []
    
    # Get collectors for this provider
    collectors = CollectorRegistry.get_collectors(cfg.provider.value)
    
    if not collectors:
        console.print(f"[yellow]No collectors registered for {cfg.provider.value}[/yellow]")
        return bundle, ["No collectors registered"]
    
    for name, collector_class in collectors.items():
        collector_config = cfg.collectors.get(name)
        if collector_config and not collector_config.enabled:
            console.print(f"[dim]Skipping {name} (disabled)[/dim]")
            continue
        
        console.print(f"  Collecting: [cyan]{name}[/cyan]...")
        
        try:
            from cfs.types import CollectorConfig
            collector = collector_class(
                scope=scope,
                config=collector_config or CollectorConfig(),
                output_dir=output_path / "provider",
                dry_run=cfg.dry_run,
            )
            
            result = collector.collect(timeframe)
            
            if result.success:
                bundle.artifacts.extend(result.artifacts)
                console.print(f"    [green]✓[/green] Collected {result.artifact_count} artifacts")
            else:
                for error in result.errors:
                    console.print(f"    [red]✗[/red] {error}")
                    all_errors.append(f"{name}: {error}")
            
            # Even on success, collectors might have partial errors
            if result.errors and result.success:
                 for error in result.errors:
                    all_errors.append(f"{name}: {error}")

            for warning in result.warnings:
                console.print(f"    [yellow]⚠[/yellow] {warning}")
                
        except Exception as e:
            error_msg = f"{name}: Unexpected error: {e}"
            console.print(f"    [red]✗[/red] {error_msg}")
            all_errors.append(error_msg)
            # Continue to next collector - do not abort entire run
    
    return bundle, all_errors


def _generate_preservation_docs(bundle: EvidenceBundle, output_path: Path) -> None:
    """Generate manifest and chain of custody documents."""
    from cfs.preservation import generate_manifest, generate_chain_of_custody
    from cfs.preservation.hashing import generate_hash_file
    
    # Generate manifest
    manifest_path = generate_manifest(bundle, output_path)
    console.print(f"  [green]✓[/green] Generated {manifest_path.name}")
    
    # Generate chain of custody
    coc_path = generate_chain_of_custody(bundle, output_path)
    console.print(f"  [green]✓[/green] Generated {coc_path.name}")
    
    # Generate hash file
    hash_path = output_path / "hashes" / "sha256sums.txt"
    artifact_hashes = [(a.file_path, a.sha256_hash) for a in bundle.artifacts]
    if artifact_hashes:
        generate_hash_file(artifact_hashes, hash_path)
        console.print(f"  [green]✓[/green] Generated sha256sums.txt")


def _print_collection_summary(bundle: EvidenceBundle, output_path: Path, errors: list[str]) -> None:
    """Print final collection summary."""
    status_color = "yellow" if errors else "green"
    status_text = "Completed with Errors" if errors else "Collection Complete"
    
    summary_text = (
        f"[bold {status_color}]{status_text}[/bold {status_color}]\n\n"
        f"Incident ID:     {bundle.incident_id}\n"
        f"Artifacts:       {bundle.total_artifacts}\n"
        f"Total Size:      {bundle.total_size_bytes:,} bytes\n"
        f"Output:          {output_path.absolute()}\n"
    )
    
    if errors:
        summary_text += f"\n[bold red]Errors ({len(errors)}):[/bold red]\n"
        for error in errors[:5]:  # Show first 5 errors to avoid spam
            summary_text += f"- {error}\n"
        if len(errors) > 5:
            summary_text += f"... and {len(errors) - 5} more.\n"
    
    summary_text += f"\n[dim]Evidence preserved with SHA-256 hashing.[/dim]"
    
    console.print()
    console.print(Panel.fit(
        summary_text,
        title="Summary",
        border_style=status_color,
    ))


@cli.command()
@click.option("--output", "-o", type=click.Path(), default="./config.yaml")
def init(output: str) -> None:
    """Generate a sample configuration file."""
    import yaml
    
    config = get_default_config()
    config["account_id"] = "YOUR_ACCOUNT_ID"
    config["incident_id"] = "IR-YYYY-NNN"
    
    output_path = Path(output)
    with open(output_path, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)
    
    console.print(f"[green]Generated configuration file: {output_path}[/green]")
    console.print("[dim]Edit the file and run: cfs snapshot --config config.yaml[/dim]")


@cli.command()
@click.option("--output", "-o", type=click.Path(exists=True, file_okay=False, dir_okay=True), required=True, help="Path to evidence directory")
@click.option("--target", "-t", required=True, help="Target URI (e.g., s3://bucket/path, gs://bucket/path, or local path)")
def export(output: str, target: str):
    """Export collected evidence to another location."""
    from cfs.export import export_evidence
    
    from cfs.preservation import check_immutability, format_immutability_warning
    
    console.print(f"[bold]Exporting evidence[/bold]")
    console.print(f"Source: {output}")
    console.print(f"Target: {target}")
    
    # Check target immutability
    output_type = "local"
    bucket_name = None
    provider = "local"
    
    if target.startswith("s3://"):
        output_type = "s3"
        provider = "aws"
        bucket_name = target.replace("s3://", "").split("/")[0]
    elif target.startswith("gs://"):
        output_type = "gcs"
        provider = "gcp"
        bucket_name = target.replace("gs://", "").split("/")[0]
        
    if bucket_name:
        console.print("\n[bold]Checking target immutability...[/bold]")
        res = check_immutability(output_type, bucket_name, provider)
        console.print(format_immutability_warning(res))
    
    confirm = click.confirm("\nProceed with export?")
    if not confirm:
        console.print("[yellow]Export aborted.[/yellow]")
        sys.exit(0)
    
    success = export_evidence(Path(output), target)
    if not success:
        sys.exit(1)


@cli.command()
@click.argument("manifest_path", type=click.Path(exists=True))
def verify(manifest_path: str) -> None:
    """Verify evidence integrity against a manifest file."""
    from cfs.preservation.manifest import verify_manifest_integrity
    
    manifest = Path(manifest_path)
    base_path = manifest.parent
    
    console.print(f"Verifying manifest: {manifest}")
    
    errors = verify_manifest_integrity(manifest, base_path)
    
    if errors:
        console.print("[red]Verification FAILED:[/red]")
        for error in errors:
            console.print(f"  [red]✗[/red] {error}")
    else:
        console.print("[green]✓ All artifacts verified successfully[/green]")


def main() -> None:
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
