"""Preflight permission checks for cloud evidence collection."""

import logging
from typing import Any

from rich.console import Console
from rich.table import Table

from cfs.types import CFSConfig, CloudProvider


console = Console()
logger = logging.getLogger(__name__)


def run_preflight_checks(cfg: CFSConfig) -> bool:
    """Run preflight permission checks for the configured provider.
    
    Args:
        cfg: CFS configuration
        
    Returns:
        True if all critical checks pass, False otherwise
    """
    console.print(f"  Checking {cfg.provider.value.upper()} permissions...")
    
    if cfg.provider == CloudProvider.AWS:
        return _check_aws_permissions(cfg)
    elif cfg.provider == CloudProvider.AZURE:
        return _check_azure_permissions(cfg)
    elif cfg.provider == CloudProvider.GCP:
        return _check_gcp_permissions(cfg)
    
    return False


def _check_aws_permissions(cfg: CFSConfig) -> bool:
    """Check AWS permissions for evidence collection."""
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
        
        results: list[tuple[str, bool, str]] = []
        
        # Check STS identity
        try:
            sts = boto3.client("sts")
            identity = sts.get_caller_identity()
            account = identity.get("Account", "Unknown")
            arn = identity.get("Arn", "Unknown")
            results.append(("STS GetCallerIdentity", True, f"Account: {account}"))
            
            if cfg.account_id and account != cfg.account_id:
                results.append((
                    "Account Verification",
                    False,
                    f"Expected {cfg.account_id}, got {account}"
                ))
        except NoCredentialsError:
            results.append(("AWS Credentials", False, "No credentials found"))
            _print_check_results(results)
            return False
        except ClientError as e:
            results.append(("STS GetCallerIdentity", False, str(e)))
        
        # Check CloudTrail access
        try:
            cloudtrail = boto3.client("cloudtrail")
            cloudtrail.describe_trails(trailNameList=[])
            results.append(("CloudTrail DescribeTrails", True, ""))
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "AccessDeniedException":
                results.append(("CloudTrail DescribeTrails", False, "Access denied"))
            else:
                results.append(("CloudTrail DescribeTrails", False, str(e)))
        
        # Check CloudWatch Logs access
        try:
            logs = boto3.client("logs")
            logs.describe_log_groups(limit=1)
            results.append(("CloudWatch Logs DescribeLogGroups", True, ""))
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "AccessDeniedException":
                results.append(("CloudWatch Logs", False, "Access denied"))
            else:
                results.append(("CloudWatch Logs", False, str(e)))
        
        # Check GuardDuty access
        try:
            guardduty = boto3.client("guardduty")
            guardduty.list_detectors()
            results.append(("GuardDuty ListDetectors", True, ""))
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "AccessDeniedException":
                results.append(("GuardDuty ListDetectors", False, "Access denied"))
            else:
                # GuardDuty may not be enabled
                results.append(("GuardDuty", True, "Not enabled or inaccessible"))
        
        # Check IAM access
        try:
            iam = boto3.client("iam")
            iam.get_credential_report()
            results.append(("IAM GetCredentialReport", True, ""))
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "ReportNotPresent":
                # Need to generate first - that's OK
                results.append(("IAM GetCredentialReport", True, "Report needs generation"))
            elif code == "AccessDeniedException":
                results.append(("IAM GetCredentialReport", False, "Access denied"))
            else:
                results.append(("IAM GetCredentialReport", False, str(e)))
        
        _print_check_results(results)
        
        # Return True if no critical failures
        critical_failures = [r for r in results if not r[1] and "Access denied" in r[2]]
        return len(critical_failures) == 0
        
    except ImportError:
        console.print("  [red]✗[/red] boto3 not installed")
        return False


def _check_azure_permissions(cfg: CFSConfig) -> bool:
    """Check Azure permissions for evidence collection."""
    try:
        from azure.identity import DefaultAzureCredential
        
        results: list[tuple[str, bool, str]] = []
        
        try:
            credential = DefaultAzureCredential()
            # Try to get a token to verify credentials work
            token = credential.get_token("https://management.azure.com/.default")
            results.append(("Azure Authentication", True, "Credentials valid"))
        except Exception as e:
            results.append(("Azure Authentication", False, str(e)))
            _print_check_results(results)
            return False
        
        # Additional Azure checks would go here
        results.append(("Azure Activity Logs", True, "Check skipped - will verify at collection"))
        
        _print_check_results(results)
        return True
        
    except ImportError:
        console.print("  [red]✗[/red] azure-identity not installed")
        return False


def _check_gcp_permissions(cfg: CFSConfig) -> bool:
    """Check GCP permissions for evidence collection."""
    try:
        from google.auth import default
        from google.auth.exceptions import DefaultCredentialsError
        
        results: list[tuple[str, bool, str]] = []
        
        try:
            credentials, project = default()
            results.append(("GCP Authentication", True, f"Project: {project}"))
            
            if cfg.account_id and project != cfg.account_id:
                results.append((
                    "Project Verification",
                    False,
                    f"Expected {cfg.account_id}, got {project}"
                ))
        except DefaultCredentialsError:
            results.append(("GCP Authentication", False, "No credentials found"))
            _print_check_results(results)
            return False
        
        # Additional GCP checks would go here
        results.append(("Cloud Audit Logs", True, "Check skipped - will verify at collection"))
        
        _print_check_results(results)
        return True
        
    except ImportError:
        console.print("  [red]✗[/red] google-auth not installed")
        return False


def _print_check_results(results: list[tuple[str, bool, str]]) -> None:
    """Print preflight check results as a table."""
    table = Table(show_header=True, header_style="bold")
    table.add_column("Check", style="cyan")
    table.add_column("Status")
    table.add_column("Details", style="dim")
    
    for check, passed, details in results:
        status = "[green]✓[/green]" if passed else "[red]✗[/red]"
        table.add_row(check, status, details or "")
    
    console.print(table)
