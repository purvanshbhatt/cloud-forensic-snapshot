"""Configuration loader for Cloud Forensic Snapshot."""

import os
from pathlib import Path
from typing import Any

import yaml

from cfs.types import CFSConfig, CloudProvider, CollectorConfig


def load_config(config_path: Path) -> CFSConfig:
    """Load configuration from YAML file.
    
    Args:
        config_path: Path to YAML configuration file
        
    Returns:
        CFSConfig instance
        
    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config is invalid
    """
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path) as f:
        raw_config = yaml.safe_load(f)
    
    return parse_config(raw_config)


def parse_config(raw_config: dict[str, Any]) -> CFSConfig:
    """Parse raw configuration dictionary into CFSConfig.
    
    Args:
        raw_config: Raw configuration dictionary
        
    Returns:
        CFSConfig instance
    """
    # Parse provider
    provider_str = raw_config.get("provider", "").lower()
    try:
        provider = CloudProvider(provider_str)
    except ValueError:
        raise ValueError(f"Invalid provider: {provider_str}. Must be aws, azure, or gcp.")
    
    # Parse collectors
    collectors: dict[str, CollectorConfig] = {}
    raw_collectors = raw_config.get("collectors", {})
    for name, config in raw_collectors.items():
        if isinstance(config, bool):
            collectors[name] = CollectorConfig(enabled=config)
        elif isinstance(config, dict):
            collectors[name] = CollectorConfig(
                enabled=config.get("enabled", True),
                options=config.get("options", {})
            )
    
    # Parse output
    output_config = raw_config.get("output", {})
    output_path = Path(output_config.get("path", "./forensic_snapshot"))
    output_type = output_config.get("type", "local")
    bucket_name = output_config.get("bucket")
    
    return CFSConfig(
        provider=provider,
        account_id=str(raw_config.get("account_id", "")),
        time_window=raw_config.get("time_window", "24h"),
        incident_id=raw_config.get("incident_id", ""),
        output_path=output_path,
        collectors=collectors,
        output_type=output_type,
        bucket_name=bucket_name,
        dry_run=raw_config.get("dry_run", False),
        verbose=raw_config.get("verbose", False),
    )


def get_default_config() -> dict[str, Any]:
    """Return default configuration template.
    
    Returns:
        Default configuration dictionary
    """
    return {
        "provider": "aws",
        "account_id": "",
        "time_window": "24h",
        "incident_id": "",
        "output": {
            "type": "local",
            "path": "./forensic_snapshot",
        },
        "collectors": {
            "cloudtrail": {"enabled": True, "include_data_events": True},
            "vpc_flow_logs": {"enabled": True},
            "guardduty": {"enabled": True},
            "iam": {"enabled": True},
            "ec2_metadata": {"enabled": True},
            "s3_access_logs": {"enabled": False},
            "lambda_logs": {"enabled": False},
        },
        "dry_run": False,
        "verbose": False,
    }


def merge_cli_args(config: CFSConfig, **cli_args: Any) -> CFSConfig:
    """Merge CLI arguments into existing config (CLI takes precedence).
    
    Args:
        config: Existing CFSConfig
        **cli_args: CLI arguments to merge
        
    Returns:
        Updated CFSConfig
    """
    # CLI args override config file
    if cli_args.get("provider"):
        config.provider = CloudProvider(cli_args["provider"])
    if cli_args.get("account_id"):
        config.account_id = cli_args["account_id"]
    if cli_args.get("time_window"):
        config.time_window = cli_args["time_window"]
    if cli_args.get("incident_id"):
        config.incident_id = cli_args["incident_id"]
    if cli_args.get("output"):
        config.output_path = Path(cli_args["output"])
    if cli_args.get("dry_run") is not None:
        config.dry_run = cli_args["dry_run"]
    if cli_args.get("verbose") is not None:
        config.verbose = cli_args["verbose"]
    
    return config
