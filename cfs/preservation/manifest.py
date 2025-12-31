"""Manifest generator for evidence bundles."""

import json
import platform
import socket
from datetime import datetime
from pathlib import Path
from typing import Any

from cfs import __version__
from cfs.types import Artifact, EvidenceBundle


def generate_manifest(bundle: EvidenceBundle, output_path: Path) -> Path:
    """Generate manifest.json for an evidence bundle.
    
    The manifest provides a complete inventory of all collected artifacts
    with their hashes, sizes, and collection metadata. This is critical
    for maintaining chain of custody and evidence integrity.
    
    Args:
        bundle: Evidence bundle containing all artifacts
        output_path: Directory to write manifest.json
        
    Returns:
        Path to generated manifest file
    """
    manifest = {
        "schema_version": "1.0",
        "generator": {
            "tool": "cloud-forensic-snapshot",
            "version": __version__,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        },
        "collection": {
            "incident_id": bundle.incident_id,
            "provider": bundle.provider.value,
            "account_id": bundle.account_id,
            "collection_start": bundle.collection_start.isoformat() + "Z",
            "collection_end": bundle.collection_end.isoformat() + "Z",
            "time_window": {
                "start": bundle.time_window.start_time.isoformat() + "Z",
                "end": bundle.time_window.end_time.isoformat() + "Z",
            },
        },
        "environment": {
            "hostname": bundle.hostname or socket.gethostname(),
            "platform": platform.platform(),
            "python_version": platform.python_version(),
        },
        "investigator": bundle.investigator or "Not specified",
        "notes": bundle.notes or "",
        "summary": {
            "total_artifacts": bundle.total_artifacts,
            "total_size_bytes": bundle.total_size_bytes,
            "errors": bundle.errors if hasattr(bundle, 'errors') else [],
            "status": "partial_success" if (hasattr(bundle, 'errors') and bundle.errors) else "success",
        },
        "artifacts": [_artifact_to_dict(a) for a in bundle.artifacts],
    }
    
    manifest_path = output_path / "manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    
    return manifest_path


def _artifact_to_dict(artifact: Artifact) -> dict[str, Any]:
    """Convert Artifact to dictionary for JSON serialization."""
    return {
        "name": artifact.name,
        "source": artifact.source,
        "file_path": str(artifact.file_path),
        "sha256": artifact.sha256_hash,
        "size_bytes": artifact.size_bytes,
        "collected_at": artifact.collected_at.isoformat() + "Z",
        "metadata": artifact.metadata,
    }


def load_manifest(manifest_path: Path) -> dict[str, Any]:
    """Load and parse a manifest.json file.
    
    Args:
        manifest_path: Path to manifest.json
        
    Returns:
        Parsed manifest dictionary
    """
    with open(manifest_path) as f:
        return json.load(f)


def verify_manifest_integrity(manifest_path: Path, base_path: Path) -> list[str]:
    """Verify all artifacts in a manifest against their recorded hashes.
    
    Args:
        manifest_path: Path to manifest.json
        base_path: Base directory containing artifacts
        
    Returns:
        List of error messages (empty if all verified)
    """
    from cfs.preservation.hashing import verify_hash
    
    manifest = load_manifest(manifest_path)
    errors = []
    
    for artifact in manifest.get("artifacts", []):
        artifact_path = base_path / artifact["file_path"]
        
        if not artifact_path.exists():
            errors.append(f"Missing artifact: {artifact['name']}")
            continue
        
        if not verify_hash(artifact_path, artifact["sha256"]):
            errors.append(f"Hash mismatch: {artifact['name']}")
    
    return errors
