"""Export functionality for collected evidence."""

import logging
import shutil
import boto3
from pathlib import Path
from typing import Optional

from rich.console import Console

logger = logging.getLogger(__name__)
console = Console()

def export_evidence(evidence_dir: Path, target_uri: str) -> bool:
    """Export evidence directory to a target destination.
    
    Args:
        evidence_dir: Local path to the forensic_snapshot directory
        target_uri: Destination URI (e.g. s3://bucket/path, or local path)
        
    Returns:
        True if successful, False otherwise.
    """
    if target_uri.startswith("s3://"):
        return _export_to_s3(evidence_dir, target_uri)
    elif target_uri.startswith("gs://"):
        return _export_to_gcs(evidence_dir, target_uri)
    elif target_uri.startswith("https://") and "blob.core.windows.net" in target_uri:
        # Simplification for Azure Blob
        console.print("[yellow]Azure Blob export requires SAS token or specific auth context. Not fully automated in this version.[/yellow]")
        return False
    else:
        # Local copy
        return _export_to_local(evidence_dir, target_uri)

def _export_to_local(source: Path, destination: str) -> bool:
    try:
        dest_path = Path(destination)
        if dest_path.exists():
            console.print(f"[yellow]Destination {dest_path} exists. Merging/Overwriting...[/yellow]")
        
        shutil.copytree(source, dest_path, dirs_exist_ok=True)
        console.print(f"[green]✓ Exported to {dest_path}[/green]")
        return True
    except Exception as e:
        console.print(f"[red]Local export failed: {e}[/red]")
        return False

def _export_to_s3(source: Path, s3_uri: str) -> bool:
    """Upload folder to S3."""
    try:
        # Parse URI s3://bucket/prefix
        parts = s3_uri.replace("s3://", "").split("/", 1)
        bucket_name = parts[0]
        prefix = parts[1] if len(parts) > 1 else ""
        
        s3 = boto3.client("s3")
        
        console.print(f"Uploading to s3://{bucket_name}/{prefix}...")
        
        success = True
        for file_path in source.rglob("*"):
            if file_path.is_file():
                rel_path = file_path.relative_to(source)
                key = f"{prefix}/{rel_path}".replace("//", "/")
                try:
                    s3.upload_file(str(file_path), bucket_name, key)
                    console.print(f"  Uploaded {rel_path}", style="dim")
                except Exception as e:
                    console.print(f"[red]Failed to upload {rel_path}: {e}[/red]")
                    success = False
        
        if success:
            console.print("[green]✓ S3 Export Complete[/green]")
        return success
        
    except Exception as e:
        console.print(f"[red]S3 export failed: {e}[/red]")
        return False

def _export_to_gcs(source: Path, gs_uri: str) -> bool:
    """Upload folder to GCS."""
    try:
        from google.cloud import storage
        
        parts = gs_uri.replace("gs://", "").split("/", 1)
        bucket_name = parts[0]
        prefix = parts[1] if len(parts) > 1 else ""
        
        client = storage.Client()
        bucket = client.bucket(bucket_name)
        
        console.print(f"Uploading to gs://{bucket_name}/{prefix}...")
        
        success = True
        for file_path in source.rglob("*"):
            if file_path.is_file():
                rel_path = file_path.relative_to(source)
                blob_name = f"{prefix}/{rel_path}".replace("//", "/")
                
                try:
                    blob = bucket.blob(blob_name)
                    blob.upload_from_filename(str(file_path))
                    console.print(f"  Uploaded {rel_path}", style="dim")
                except Exception as e:
                    console.print(f"[red]Failed to upload {rel_path}: {e}[/red]")
                    success = False
                    
        if success:
            console.print("[green]✓ GCS Export Complete[/green]")
        return success

    except Exception as e:
        console.print(f"[red]GCS export failed: {e}[/red]")
        return False
