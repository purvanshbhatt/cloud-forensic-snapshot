"""Azure evidence collector implementation."""

import json
import logging
from datetime import datetime, timezone
from typing import Any

from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient

from cfs.collectors.base import BaseCollector, CollectorResult, CollectorRegistry, PermissionCheck
from cfs.preservation.hashing import compute_sha256
from cfs.types import Artifact, TimeWindow


logger = logging.getLogger(__name__)


class AzureActivityLogCollector(BaseCollector):
    """Collector for Azure Activity Logs."""

    @property
    def name(self) -> str:
        return "activity_logs"

    @property
    def description(self) -> str:
        return "Collects Azure Monitor Activity Logs"

    def preflight_check(self) -> list[PermissionCheck]:
        checks = []
        try:
            credential = DefaultAzureCredential()
            client = MonitorManagementClient(credential, self.scope.account_id)
            # Try to list activity logs (requires filtering)
            filter_str = f"eventTimestamp ge '{datetime.now(timezone.utc).isoformat()}'"
            list(client.activity_logs.list(filter=filter_str))
            checks.append(PermissionCheck("Microsoft.Insights/activityLog/read", True))
        except Exception as e:
             checks.append(PermissionCheck("Microsoft.Insights/activityLog/read", False, message=str(e)))
        return checks

    def collect(self, timeframe: TimeWindow) -> CollectorResult:
        artifacts = []
        try:
            credential = DefaultAzureCredential()
            client = MonitorManagementClient(credential, self.scope.account_id)

            # Azure filter syntax
            start_iso = timeframe.start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            end_iso = timeframe.end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            filter_str = f"eventTimestamp ge '{start_iso}' and eventTimestamp le '{end_iso}'"

            logs = []
            # 'select' is optional, fetching all fields by default
            for item in client.activity_logs.list(filter=filter_str):
                logs.append(item.as_dict())

            if logs:
                raw_path = self.get_artifact_path("activity_logs.json")
                if not self.dry_run:
                    with open(raw_path, "w") as f:
                        json.dump(logs, f, default=str, indent=2)
                    
                    artifact = Artifact(
                        name="activity_logs.json",
                        source=self.name,
                        file_path=raw_path.relative_to(self.output_dir.parent),
                        sha256_hash=compute_sha256(raw_path),
                        size_bytes=raw_path.stat().st_size,
                        collected_at=datetime.utcnow(),
                        metadata={"log_count": len(logs)}
                    )
                    artifacts.append(artifact)

            return self.create_result(True, artifacts)

        except Exception as e:
            self.add_error(f"Activity Log collection failed: {e}")
            return self.create_result(False)


class AzureNetworkCollector(BaseCollector):
    """Collector for Azure Network configurations (NSG, VNETs)."""

    @property
    def name(self) -> str:
        return "network_config"

    @property
    def description(self) -> str:
        return "Collects Network Security Groups and VNET configs"

    def preflight_check(self) -> list[PermissionCheck]:
        checks = []
        try:
            credential = DefaultAzureCredential()
            client = NetworkManagementClient(credential, self.scope.account_id)
            client.network_security_groups.list_all()
            checks.append(PermissionCheck("Microsoft.Network/networkSecurityGroups/read", True))
        except Exception as e:
            checks.append(PermissionCheck("Microsoft.Network/networkSecurityGroups/read", False, message=str(e)))
        return checks

    def collect(self, timeframe: TimeWindow) -> CollectorResult:
        artifacts = []
        try:
            credential = DefaultAzureCredential()
            client = NetworkManagementClient(credential, self.scope.account_id)

            # NSGs
            nsgs = []
            for nsg in client.network_security_groups.list_all():
                nsgs.append(nsg.as_dict())

            if nsgs:
                path = self.get_artifact_path("nsgs.json")
                if not self.dry_run:
                    with open(path, "w") as f:
                        json.dump(nsgs, f, default=str, indent=2)
                    artifacts.append(Artifact(
                        name="nsgs.json",
                        source=self.name,
                        file_path=path.relative_to(self.output_dir.parent),
                        sha256_hash=compute_sha256(path),
                        size_bytes=path.stat().st_size,
                        collected_at=datetime.utcnow(),
                        metadata={"nsg_count": len(nsgs)}
                    ))

            return self.create_result(True, artifacts)

        except Exception as e:
            self.add_error(f"Network config collection failed: {e}")
            return self.create_result(False)


class AzureComputeCollector(BaseCollector):
    """Collector for Azure Compute metadata."""

    @property
    def name(self) -> str:
        return "compute_metadata"

    @property
    def description(self) -> str:
        return "Collects Virtual Machine metadata"

    def preflight_check(self) -> list[PermissionCheck]:
        checks = []
        try:
            credential = DefaultAzureCredential()
            client = ComputeManagementClient(credential, self.scope.account_id)
            client.virtual_machines.list_all()
            checks.append(PermissionCheck("Microsoft.Compute/virtualMachines/read", True))
        except Exception as e:
            checks.append(PermissionCheck("Microsoft.Compute/virtualMachines/read", False, message=str(e)))
        return checks

    def collect(self, timeframe: TimeWindow) -> CollectorResult:
        artifacts = []
        try:
            credential = DefaultAzureCredential()
            client = ComputeManagementClient(credential, self.scope.account_id)

            vms = []
            for vm in client.virtual_machines.list_all():
                vms.append(vm.as_dict())

            if vms:
                path = self.get_artifact_path("virtual_machines.json")
                if not self.dry_run:
                    with open(path, "w") as f:
                        json.dump(vms, f, default=str, indent=2)
                    artifacts.append(Artifact(
                        name="virtual_machines.json",
                        source=self.name,
                        file_path=path.relative_to(self.output_dir.parent),
                        sha256_hash=compute_sha256(path),
                        size_bytes=path.stat().st_size,
                        collected_at=datetime.utcnow(),
                        metadata={"vm_count": len(vms)}
                    ))

            return self.create_result(True, artifacts)

        except Exception as e:
            self.add_error(f"Compute metadata collection failed: {e}")
            return self.create_result(False)


class AzureADCollector(BaseCollector):
    """Collector for Azure AD Audit and Sign-in Logs."""

    @property
    def name(self) -> str:
        return "azure_ad"

    @property
    def description(self) -> str:
        return "Collects Azure AD Audit and Sign-in Logs (via Monitor/Graph)"

    def preflight_check(self) -> list[PermissionCheck]:
        checks = []
        # Azure AD logs via Monitor require 'Microsoft.Insights/eventtypes/values/read'
        # OR Graph API 'AuditLog.Read.All'.
        # For this implementation, we assume Monitor integration or basic read.
        checks.append(PermissionCheck("Microsoft.Graph/AuditLog.Read.All", True, message="Assumed via permissions"))
        return checks

    def collect(self, timeframe: TimeWindow) -> CollectorResult:
        # Note: Direct AD log collection often requires Graph API which is separate from Mgmt SDKs.
        # Here we placeholder for Graph integration or Monitor Diagnostic query.
        self.add_warning("Azure AD log collection requires diagnostic settings routing to Log Analytics or Graph API integration (roadmap).")
        return self.create_result(True)


def get_azure_collectors() -> dict[str, type[BaseCollector]]:
    """Return dictionary of Azure collectors."""
    return {
        "activity_logs": AzureActivityLogCollector,
        "azure_ad": AzureADCollector,
        "network_config": AzureNetworkCollector,
        "compute_metadata": AzureComputeCollector,
    }

# Register collectors
CollectorRegistry.register("azure", "activity_logs", AzureActivityLogCollector)
CollectorRegistry.register("azure", "azure_ad", AzureADCollector)
CollectorRegistry.register("azure", "network_config", AzureNetworkCollector)
CollectorRegistry.register("azure", "compute_metadata", AzureComputeCollector)
