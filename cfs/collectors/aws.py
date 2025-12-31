"""AWS evidence collector implementation."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError

from cfs.collectors.base import BaseCollector, CollectorResult, CollectorRegistry, PermissionCheck
from cfs.preservation.hashing import compute_sha256
from cfs.types import Artifact, TimeWindow


logger = logging.getLogger(__name__)


class AWSCloudTrailCollector(BaseCollector):
    """Collector for AWS CloudTrail logs."""

    @property
    def name(self) -> str:
        return "cloudtrail"

    @property
    def description(self) -> str:
        return "Collects AWS CloudTrail management and data events"

    def preflight_check(self) -> list[PermissionCheck]:
        checks = []
        try:
            client = boto3.client("cloudtrail")
            client.describe_trails(trailNameList=[])
            checks.append(PermissionCheck("cloudtrail:DescribeTrails", True))
            client.lookup_events(MaxResults=1)
            checks.append(PermissionCheck("cloudtrail:LookupEvents", True))
        except ClientError as e:
            checks.append(PermissionCheck("cloudtrail:DescribeTrails", False, message=str(e)))
        return checks

    def collect(self, timeframe: TimeWindow) -> CollectorResult:
        artifacts = []
        try:
            client = boto3.client("cloudtrail")
            
            # Lookup events for the timeframe
            # Note: CloudTrail lookup only goes back 90 days for management events
            paginator = client.get_paginator("lookup_events")
            
            events = []
            for page in paginator.paginate(
                StartTime=timeframe.start_time,
                EndTime=timeframe.end_time,
            ):
                events.extend(page.get("Events", []))

            if events:
                raw_path = self.get_artifact_path("events.json")
                if not self.dry_run:
                    with open(raw_path, "w") as f:
                        # Ensure serialization handles datetime objects
                        json.dump(events, f, default=str, indent=2)
                    
                    artifact = Artifact(
                        name="events.json",
                        source=self.name,
                        file_path=raw_path.relative_to(self.output_dir.parent),
                        sha256_hash=compute_sha256(raw_path),
                        size_bytes=raw_path.stat().st_size,
                        collected_at=datetime.utcnow(),
                        metadata={"event_count": len(events)}
                    )
                    artifacts.append(artifact)

            return self.create_result(True, artifacts)
        except Exception as e:
            self.add_error(f"CloudTrail collection failed: {e}")
            return self.create_result(False)


class AWSGuardDutyCollector(BaseCollector):
    """Collector for AWS GuardDuty findings."""

    @property
    def name(self) -> str:
        return "guardduty"

    @property
    def description(self) -> str:
        return "Collects GuardDuty findings"

    def preflight_check(self) -> list[PermissionCheck]:
        checks = []
        try:
            client = boto3.client("guardduty")
            client.list_detectors()
            checks.append(PermissionCheck("guardduty:ListDetectors", True))
        except ClientError as e:
            checks.append(PermissionCheck("guardduty:ListDetectors", False, message=str(e)))
        return checks

    def collect(self, timeframe: TimeWindow) -> CollectorResult:
        artifacts = []
        try:
            client = boto3.client("guardduty")
            detectors = client.list_detectors().get("DetectorIds", [])
            
            all_findings = []
            for detector_id in detectors:
                paginator = client.get_paginator("list_findings")
                for page in paginator.paginate(
                    DetectorId=detector_id,
                    FindingCriteria={
                        "Criterion": {
                            "updatedAt": {
                                "GreaterThanOrEqual": int(timeframe.start_time.timestamp() * 1000),
                                "LessThanOrEqual": int(timeframe.end_time.timestamp() * 1000)
                            }
                        }
                    }
                ):
                    finding_ids = page.get("FindingIds", [])
                    if finding_ids:
                        findings = client.get_findings(
                            DetectorId=detector_id,
                            FindingIds=finding_ids
                        ).get("Findings", [])
                        all_findings.extend(findings)

            if all_findings:
                raw_path = self.get_artifact_path("findings.json")
                if not self.dry_run:
                    with open(raw_path, "w") as f:
                        json.dump(all_findings, f, default=str, indent=2)
                    
                    artifact = Artifact(
                        name="findings.json",
                        source=self.name,
                        file_path=raw_path.relative_to(self.output_dir.parent),
                        sha256_hash=compute_sha256(raw_path),
                        size_bytes=raw_path.stat().st_size,
                        collected_at=datetime.utcnow(),
                        metadata={"finding_count": len(all_findings)}
                    )
                    artifacts.append(artifact)

            return self.create_result(True, artifacts)
        except Exception as e:
            self.add_error(f"GuardDuty collection failed: {e}")
            return self.create_result(False)


class AWSIAMCollector(BaseCollector):
    """Collector for AWS IAM configuration and credential reports."""

    @property
    def name(self) -> str:
        return "iam"

    @property
    def description(self) -> str:
        return "Collects IAM credential report and account summary"

    def preflight_check(self) -> list[PermissionCheck]:
        checks = []
        try:
            client = boto3.client("iam")
            client.get_account_summary()
            checks.append(PermissionCheck("iam:GetAccountSummary", True))
        except ClientError as e:
            checks.append(PermissionCheck("iam:GetAccountSummary", False, message=str(e)))
        return checks

    def collect(self, timeframe: TimeWindow) -> CollectorResult:
        artifacts = []
        try:
            client = boto3.client("iam")
            
            # Account Summary
            summary = client.get_account_summary().get("SummaryMap", {})
            summary_path = self.get_artifact_path("account_summary.json")
            if not self.dry_run:
                with open(summary_path, "w") as f:
                    json.dump(summary, f, indent=2)
                artifacts.append(Artifact(
                    name="account_summary.json",
                    source=self.name,
                    file_path=summary_path.relative_to(self.output_dir.parent),
                    sha256_hash=compute_sha256(summary_path),
                    size_bytes=summary_path.stat().st_size,
                    collected_at=datetime.utcnow()
                ))

            # Credential Report
            try:
                # Request report generation
                client.generate_credential_report()
                # Get report
                report = client.get_credential_report()
                content = report.get("Content")
                if content:
                    report_path = self.get_artifact_path("credential_report.csv")
                    if not self.dry_run:
                        with open(report_path, "wb") as f:
                            f.write(content)
                        artifacts.append(Artifact(
                            name="credential_report.csv",
                            source=self.name,
                            file_path=report_path.relative_to(self.output_dir.parent),
                            sha256_hash=compute_sha256(report_path),
                            size_bytes=report_path.stat().st_size,
                            collected_at=datetime.utcnow()
                        ))
            except ClientError as e:
                self.add_warning(f"Could not collect credential report: {e}")

            return self.create_result(True, artifacts)
        except Exception as e:
            self.add_error(f"IAM collection failed: {e}")
            return self.create_result(False)


class AWSVPCFlowLogCollector(BaseCollector):
    """Collector for AWS VPC Flow Log configuration."""

    @property
    def name(self) -> str:
        return "vpc_flow_logs"

    @property
    def description(self) -> str:
        return "Collects VPC Flow Log configuration and metadata"

    def preflight_check(self) -> list[PermissionCheck]:
        checks = []
        try:
            client = boto3.client("ec2")
            client.describe_flow_logs(MaxResults=1)
            checks.append(PermissionCheck("ec2:DescribeFlowLogs", True))
        except ClientError as e:
            checks.append(PermissionCheck("ec2:DescribeFlowLogs", False, message=str(e)))
        return checks

    def collect(self, timeframe: TimeWindow) -> CollectorResult:
        artifacts = []
        try:
            client = boto3.client("ec2")
            
            # Describe all flow logs
            flow_logs = []
            paginator = client.get_paginator("describe_flow_logs")
            for page in paginator.paginate():
                flow_logs.extend(page.get("FlowLogs", []))

            if flow_logs:
                raw_path = self.get_artifact_path("flow_logs.json")
                if not self.dry_run:
                    with open(raw_path, "w") as f:
                        json.dump(flow_logs, f, default=str, indent=2)
                    
                    artifact = Artifact(
                        name="flow_logs.json",
                        source=self.name,
                        file_path=raw_path.relative_to(self.output_dir.parent),
                        sha256_hash=compute_sha256(raw_path),
                        size_bytes=raw_path.stat().st_size,
                        collected_at=datetime.utcnow(),
                        metadata={"flow_log_count": len(flow_logs)}
                    )
                    artifacts.append(artifact)

            return self.create_result(True, artifacts)
        except Exception as e:
            self.add_error(f"VPC Flow Logs collection failed: {e}")
            return self.create_result(False)


class AWSEC2MetadataCollector(BaseCollector):
    """Collector for AWS EC2 instance and EBS snapshot metadata."""

    @property
    def name(self) -> str:
        return "ec2_ebs_metadata"

    @property
    def description(self) -> str:
        return "Collects EC2 instance and EBS snapshot metadata (inventory)"

    def preflight_check(self) -> list[PermissionCheck]:
        checks = []
        try:
            client = boto3.client("ec2")
            client.describe_instances(MaxResults=1)
            checks.append(PermissionCheck("ec2:DescribeInstances", True))
            client.describe_snapshots(OwnerIds=["self"], MaxResults=1)
            checks.append(PermissionCheck("ec2:DescribeSnapshots", True))
        except ClientError as e:
            checks.append(PermissionCheck("ec2:DescribeInstances", False, message=str(e)))
        return checks

    def collect(self, timeframe: TimeWindow) -> CollectorResult:
        artifacts = []
        try:
            client = boto3.client("ec2")
            
            # Instances
            instances = []
            paginator = client.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    instances.extend(reservation.get("Instances", []))

            if instances:
                path = self.get_artifact_path("instances.json")
                if not self.dry_run:
                    with open(path, "w") as f:
                        json.dump(instances, f, default=str, indent=2)
                    artifacts.append(Artifact(
                        name="instances.json",
                        source=self.name,
                        file_path=path.relative_to(self.output_dir.parent),
                        sha256_hash=compute_sha256(path),
                        size_bytes=path.stat().st_size,
                        collected_at=datetime.utcnow()
                    ))

            # Snapshots (owned by self)
            snapshots = []
            paginator = client.get_paginator("describe_snapshots")
            for page in paginator.paginate(OwnerIds=["self"]):
                # Filter by timeframe
                for snap in page.get("Snapshots", []):
                    start_time = snap.get("StartTime")
                    if timeframe.start_time <= start_time <= timeframe.end_time:
                        snapshots.append(snap)

            if snapshots:
                path = self.get_artifact_path("snapshots.json")
                if not self.dry_run:
                    with open(path, "w") as f:
                        json.dump(snapshots, f, default=str, indent=2)
                    artifacts.append(Artifact(
                        name="snapshots.json",
                        source=self.name,
                        file_path=path.relative_to(self.output_dir.parent),
                        sha256_hash=compute_sha256(path),
                        size_bytes=path.stat().st_size,
                        collected_at=datetime.utcnow()
                    ))

            return self.create_result(True, artifacts)
        except Exception as e:
            self.add_error(f"EC2/EBS metadata collection failed: {e}")
            return self.create_result(False)


def get_aws_collectors() -> dict[str, type[BaseCollector]]:
    """Return dictionary of AWS collectors."""
    return {
        "cloudtrail": AWSCloudTrailCollector,
        "guardduty": AWSGuardDutyCollector,
        "iam": AWSIAMCollector,
        "vpc_flow_logs": AWSVPCFlowLogCollector,
        "ec2_ebs_metadata": AWSEC2MetadataCollector,
    }

# Register collectors
CollectorRegistry.register("aws", "cloudtrail", AWSCloudTrailCollector)
CollectorRegistry.register("aws", "guardduty", AWSGuardDutyCollector)
CollectorRegistry.register("aws", "iam", AWSIAMCollector)
CollectorRegistry.register("aws", "vpc_flow_logs", AWSVPCFlowLogCollector)
CollectorRegistry.register("aws", "ec2_ebs_metadata", AWSEC2MetadataCollector)

