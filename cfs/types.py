"""Core type definitions for Cloud Forensic Snapshot."""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any


class CloudProvider(Enum):
    """Supported cloud providers."""
    
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


@dataclass
class TimeWindow:
    """Defines the time window for evidence collection."""
    
    start_time: datetime
    end_time: datetime
    
    @classmethod
    def from_duration(cls, duration: str, end_time: datetime | None = None) -> "TimeWindow":
        """Create TimeWindow from duration string like '24h', '7d', '30m'.
        
        Args:
            duration: Duration string (e.g., '24h', '7d', '30m')
            end_time: End time for the window, defaults to now
            
        Returns:
            TimeWindow instance
        """
        if end_time is None:
            end_time = datetime.utcnow()
        
        unit = duration[-1].lower()
        value = int(duration[:-1])
        
        if unit == 'h':
            delta = timedelta(hours=value)
        elif unit == 'd':
            delta = timedelta(days=value)
        elif unit == 'm':
            delta = timedelta(minutes=value)
        else:
            raise ValueError(f"Unknown time unit: {unit}. Use 'h', 'd', or 'm'.")
        
        return cls(start_time=end_time - delta, end_time=end_time)


@dataclass
class CollectionScope:
    """Defines the scope of evidence collection."""
    
    provider: CloudProvider
    account_id: str
    regions: list[str] = field(default_factory=lambda: ["all"])
    incident_id: str | None = None
    
    # Provider-specific options
    aws_options: dict[str, Any] = field(default_factory=dict)
    azure_options: dict[str, Any] = field(default_factory=dict)
    gcp_options: dict[str, Any] = field(default_factory=dict)


@dataclass
class Artifact:
    """Represents a single collected evidence artifact."""
    
    name: str
    source: str  # e.g., "cloudtrail", "vpc_flow_logs"
    file_path: Path
    sha256_hash: str
    size_bytes: int
    collected_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceBundle:
    """Complete evidence bundle from a collection operation."""
    
    incident_id: str
    provider: CloudProvider
    account_id: str
    collection_start: datetime
    collection_end: datetime
    time_window: TimeWindow
    artifacts: list[Artifact] = field(default_factory=list)
    output_path: Path | None = None
    
    # Collection metadata
    collector_version: str = ""
    hostname: str = ""
    investigator: str = ""
    notes: str = ""
    
    @property
    def total_artifacts(self) -> int:
        """Return total number of artifacts."""
        return len(self.artifacts)
    
    @property
    def total_size_bytes(self) -> int:
        """Return total size of all artifacts."""
        return sum(a.size_bytes for a in self.artifacts)


@dataclass
class CollectorConfig:
    """Configuration for a specific collector."""
    
    enabled: bool = True
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class CFSConfig:
    """Main configuration for CFS."""
    
    provider: CloudProvider
    account_id: str
    time_window: str  # e.g., "24h"
    incident_id: str
    output_path: Path
    
    # Collector-specific configs
    collectors: dict[str, CollectorConfig] = field(default_factory=dict)
    
    # Output options
    output_type: str = "local"  # local, s3, azure-blob, gcs
    bucket_name: str | None = None
    
    # Execution options
    dry_run: bool = False
    verbose: bool = False
