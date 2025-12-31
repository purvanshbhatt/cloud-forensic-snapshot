"""Immutability detection for cloud storage."""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any


class ImmutabilityStatus(Enum):
    """Status of immutability configuration."""
    
    ENABLED = "enabled"         # Object lock or similar is enabled
    DISABLED = "disabled"       # Immutability not configured
    UNKNOWN = "unknown"         # Could not determine status
    NOT_APPLICABLE = "n/a"      # Local storage, no cloud immutability


@dataclass
class ImmutabilityCheckResult:
    """Result of immutability check."""
    
    status: ImmutabilityStatus
    bucket_name: str
    provider: str
    message: str
    details: dict[str, Any]


def check_immutability(
    output_type: str,
    bucket_name: str | None = None,
    provider: str = "local"
) -> ImmutabilityCheckResult:
    """Check if the target storage has immutability enabled.
    
    This is critical for evidence integrity. If immutability is not
    enabled, evidence could be tampered with post-collection.
    
    Args:
        output_type: Type of output (local, s3, azure-blob, gcs)
        bucket_name: Name of the target bucket (if applicable)
        provider: Cloud provider for the bucket
        
    Returns:
        ImmutabilityCheckResult with status and details
    """
    if output_type == "local":
        return ImmutabilityCheckResult(
            status=ImmutabilityStatus.NOT_APPLICABLE,
            bucket_name="",
            provider="local",
            message="Local storage - immutability not applicable. "
                    "Consider using Object Lock-enabled cloud storage for legal hold.",
            details={},
        )
    
    if output_type == "s3":
        return _check_s3_immutability(bucket_name or "")
    
    if output_type == "azure-blob":
        return _check_azure_immutability(bucket_name or "")
    
    if output_type == "gcs":
        return _check_gcs_immutability(bucket_name or "")
    
    return ImmutabilityCheckResult(
        status=ImmutabilityStatus.UNKNOWN,
        bucket_name=bucket_name or "",
        provider=provider,
        message=f"Unknown output type: {output_type}",
        details={},
    )


def _check_s3_immutability(bucket_name: str) -> ImmutabilityCheckResult:
    """Check S3 Object Lock configuration."""
    try:
        import boto3
        from botocore.exceptions import ClientError
        
        s3_client = boto3.client("s3")
        
        try:
            response = s3_client.get_object_lock_configuration(Bucket=bucket_name)
            config = response.get("ObjectLockConfiguration", {})
            
            if config.get("ObjectLockEnabled") == "Enabled":
                return ImmutabilityCheckResult(
                    status=ImmutabilityStatus.ENABLED,
                    bucket_name=bucket_name,
                    provider="aws",
                    message=f"S3 Object Lock is ENABLED on bucket '{bucket_name}'.",
                    details={"config": config},
                )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ObjectLockConfigurationNotFoundError":
                pass  # Object Lock not configured
            else:
                raise
        
        return ImmutabilityCheckResult(
            status=ImmutabilityStatus.DISABLED,
            bucket_name=bucket_name,
            provider="aws",
            message=f"WARNING: S3 bucket '{bucket_name}' does NOT have Object Lock enabled. "
                    f"Evidence integrity cannot be guaranteed.",
            details={},
        )
        
    except ImportError:
        return ImmutabilityCheckResult(
            status=ImmutabilityStatus.UNKNOWN,
            bucket_name=bucket_name,
            provider="aws",
            message="boto3 not available - cannot check S3 immutability",
            details={},
        )
    except Exception as e:
        return ImmutabilityCheckResult(
            status=ImmutabilityStatus.UNKNOWN,
            bucket_name=bucket_name,
            provider="aws",
            message=f"Error checking S3 immutability: {e}",
            details={"error": str(e)},
        )


def _check_azure_immutability(container_name: str) -> ImmutabilityCheckResult:
    """Check Azure Blob immutability policy."""
    try:
        # Azure immutability check would go here
        # Using azure-mgmt-storage to check immutability policies
        return ImmutabilityCheckResult(
            status=ImmutabilityStatus.UNKNOWN,
            bucket_name=container_name,
            provider="azure",
            message="Azure immutability check not yet implemented. "
                    "Verify immutability policy manually.",
            details={},
        )
    except Exception as e:
        return ImmutabilityCheckResult(
            status=ImmutabilityStatus.UNKNOWN,
            bucket_name=container_name,
            provider="azure",
            message=f"Error checking Azure immutability: {e}",
            details={"error": str(e)},
        )


def _check_gcs_immutability(bucket_name: str) -> ImmutabilityCheckResult:
    """Check GCS retention policy."""
    try:
        from google.cloud import storage
        
        client = storage.Client()
        bucket = client.get_bucket(bucket_name)
        
        retention_policy = bucket.retention_policy_effective_time
        retention_period = bucket.retention_period
        
        if retention_period:
            return ImmutabilityCheckResult(
                status=ImmutabilityStatus.ENABLED,
                bucket_name=bucket_name,
                provider="gcp",
                message=f"GCS bucket '{bucket_name}' has retention policy enabled "
                        f"({retention_period} seconds).",
                details={
                    "retention_period_seconds": retention_period,
                    "effective_time": str(retention_policy),
                },
            )
        
        return ImmutabilityCheckResult(
            status=ImmutabilityStatus.DISABLED,
            bucket_name=bucket_name,
            provider="gcp",
            message=f"WARNING: GCS bucket '{bucket_name}' does NOT have a retention policy. "
                    f"Evidence integrity cannot be guaranteed.",
            details={},
        )
        
    except ImportError:
        return ImmutabilityCheckResult(
            status=ImmutabilityStatus.UNKNOWN,
            bucket_name=bucket_name,
            provider="gcp",
            message="google-cloud-storage not available - cannot check GCS immutability",
            details={},
        )
    except Exception as e:
        return ImmutabilityCheckResult(
            status=ImmutabilityStatus.UNKNOWN,
            bucket_name=bucket_name,
            provider="gcp",
            message=f"Error checking GCS immutability: {e}",
            details={"error": str(e)},
        )


def format_immutability_warning(result: ImmutabilityCheckResult) -> str:
    """Format immutability check result as a warning message.
    
    Args:
        result: Immutability check result
        
    Returns:
        Formatted warning string suitable for CLI output
    """
    if result.status == ImmutabilityStatus.ENABLED:
        return f"✓ {result.message}"
    
    if result.status == ImmutabilityStatus.DISABLED:
        return (
            f"⚠️  WARNING: {result.message}\n"
            f"    See: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html"
        )
    
    if result.status == ImmutabilityStatus.NOT_APPLICABLE:
        return f"ℹ️  {result.message}"
    
    return f"❓ {result.message}"
