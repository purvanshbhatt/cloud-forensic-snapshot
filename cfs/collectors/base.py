"""Abstract base collector interface for cloud evidence acquisition."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from cfs.types import Artifact, CollectionScope, CollectorConfig, EvidenceBundle, TimeWindow


@dataclass
class CollectorResult:
    """Result from a single collector execution."""
    
    collector_name: str
    success: bool
    artifacts: list[Artifact] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    
    @property
    def artifact_count(self) -> int:
        """Return number of artifacts collected."""
        return len(self.artifacts)


@dataclass
class PermissionCheck:
    """Result of a permission preflight check."""
    
    permission: str
    granted: bool
    resource: str = ""
    message: str = ""


class BaseCollector(ABC):
    """Abstract base class for cloud evidence collectors.
    
    All cloud-specific collectors must inherit from this class and implement
    the required abstract methods.
    """
    
    def __init__(
        self,
        scope: CollectionScope,
        config: CollectorConfig,
        output_dir: Path,
        dry_run: bool = False,
    ):
        """Initialize the collector.
        
        Args:
            scope: Collection scope (account, regions, etc.)
            config: Collector-specific configuration
            output_dir: Base output directory for artifacts
            dry_run: If True, simulate collection without writing
        """
        self.scope = scope
        self.config = config
        self.output_dir = output_dir
        self.dry_run = dry_run
        self._errors: list[str] = []
        self._warnings: list[str] = []
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the collector name (e.g., 'cloudtrail', 'vpc_flow_logs')."""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Return a human-readable description of what this collector does."""
        pass
    
    @abstractmethod
    def collect(self, timeframe: TimeWindow) -> CollectorResult:
        """Collect evidence within the specified timeframe.
        
        Args:
            timeframe: Time window for collection
            
        Returns:
            CollectorResult with artifacts and status
        """
        pass
    
    @abstractmethod
    def preflight_check(self) -> list[PermissionCheck]:
        """Verify required permissions before collection.
        
        Returns:
            List of PermissionCheck results
        """
        pass
    
    def add_error(self, message: str) -> None:
        """Record an error during collection."""
        self._errors.append(message)
    
    def add_warning(self, message: str) -> None:
        """Record a warning during collection."""
        self._warnings.append(message)
    
    def get_artifact_path(self, artifact_name: str) -> Path:
        """Get the output path for an artifact.
        
        Args:
            artifact_name: Name of the artifact file
            
        Returns:
            Full path for the artifact
        """
        collector_dir = self.output_dir / self.scope.provider.value / self.name
        collector_dir.mkdir(parents=True, exist_ok=True)
        return collector_dir / artifact_name
    
    def create_result(
        self,
        success: bool,
        artifacts: list[Artifact] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> CollectorResult:
        """Create a CollectorResult with current errors and warnings.
        
        Args:
            success: Whether collection succeeded
            artifacts: List of collected artifacts
            metadata: Additional metadata
            
        Returns:
            CollectorResult instance
        """
        return CollectorResult(
            collector_name=self.name,
            success=success,
            artifacts=artifacts or [],
            errors=self._errors.copy(),
            warnings=self._warnings.copy(),
            metadata=metadata or {},
        )


class CollectorRegistry:
    """Registry for available collectors by provider."""
    
    _collectors: dict[str, dict[str, type[BaseCollector]]] = {
        "aws": {},
        "azure": {},
        "gcp": {},
    }
    
    @classmethod
    def register(cls, provider: str, name: str, collector_class: type[BaseCollector]) -> None:
        """Register a collector.
        
        Args:
            provider: Cloud provider (aws, azure, gcp)
            name: Collector name
            collector_class: Collector class
        """
        if provider not in cls._collectors:
            cls._collectors[provider] = {}
        cls._collectors[provider][name] = collector_class
    
    @classmethod
    def get_collectors(cls, provider: str) -> dict[str, type[BaseCollector]]:
        """Get all collectors for a provider.
        
        Args:
            provider: Cloud provider
            
        Returns:
            Dictionary of collector name to class
        """
        return cls._collectors.get(provider, {})
    
    @classmethod
    def get_collector(cls, provider: str, name: str) -> type[BaseCollector] | None:
        """Get a specific collector.
        
        Args:
            provider: Cloud provider
            name: Collector name
            
        Returns:
            Collector class or None
        """
        return cls._collectors.get(provider, {}).get(name)
