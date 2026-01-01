"""Unit tests for manifest generation."""

import json
import socket
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

from cfs.types import EvidenceBundle, Artifact, CollectionScope, TimeWindow, CloudProvider
from cfs.preservation.manifest import generate_manifest

def test_generate_manifest(tmp_path):
    """Test proper manifest JSON generation."""
    output_dir = tmp_path / "forensic_snapshot"
    output_dir.mkdir()
    
    bundle = EvidenceBundle(
        incident_id="TEST-001",
        provider=CloudProvider.AWS,
        account_id="123456789",
        collection_start=datetime.utcnow(),
        collection_end=datetime.utcnow(),
        time_window=TimeWindow.from_duration("24h"),
        output_path=output_dir,
        collector_version="0.2.0",
        hostname=socket.gethostname(),
        investigator="Sherlock",
        notes="Test run"
    )
    
    # Add a dummy artifact
    artifact_path = output_dir / "test.json"
    artifact_path.write_text("{}")
    
    bundle.artifacts.append(Artifact(
        name="test.json",
        source="test_collector",
        file_path=Path("test.json"),
        sha256_hash="dummyhash",
        size_bytes=2,
        collected_at=datetime.utcnow()
    ))
    
    # Generate
    manifest_path = generate_manifest(bundle, output_dir)
    
    assert manifest_path.exists()
    
    with open(manifest_path) as f:
        data = json.load(f)
        
    assert data["schema_version"] == "1.0"
    assert data["metadata"]["incident_id"] == "TEST-001"
    assert data["metadata"]["provider"] == "aws"
    assert len(data["inventory"]) == 1
    assert data["inventory"][0]["name"] == "test.json"
    assert data["integrity"]["file_count"] == 1
    assert data["status"] == "success"
