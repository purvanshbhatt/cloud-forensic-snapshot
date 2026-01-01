"""GCP evidence collector implementation."""

import json
import logging
from datetime import datetime
from typing import Any

from google.api_core import exceptions
from google.cloud import logging as cloud_logging
from google.cloud import compute_v1
from google.cloud.logging_v2.entries import StructEntry, ProtobufEntry

from cfs.collectors.base import BaseCollector, CollectorResult, CollectorRegistry, PermissionCheck
from cfs.preservation.hashing import compute_sha256
from cfs.types import Artifact, TimeWindow
from cfs.utils import with_retry


logger = logging.getLogger(__name__)


class GCPLogCollector(BaseCollector):
    """Collector for GCP Cloud Logging (Audit Logs)."""

    @property
    def name(self) -> str:
        return "audit_logs"

    @property
    def description(self) -> str:
        return "Collects GCP Cloud Audit Logs and system events"

    def preflight_check(self) -> list[PermissionCheck]:
        checks = []
        try:
            client = cloud_logging.Client(project=self.scope.account_id)
            # Try to list entries (limit 1)
            list(client.list_entries(max_results=1))
            checks.append(PermissionCheck("logging.entries.list", True))
        except exceptions.Forbidden:
             checks.append(PermissionCheck("logging.entries.list", False, message="Permission denied"))
        except Exception as e:
             checks.append(PermissionCheck("logging.entries.list", False, message=str(e)))
        return checks

    @with_retry()
    def collect(self, timeframe: TimeWindow) -> CollectorResult:
        artifacts = []
        try:
            client = cloud_logging.Client(project=self.scope.account_id)

            # Filter for timeframe
            start_str = timeframe.start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            end_str = timeframe.end_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            
            filter_str = (
                f'timestamp >= "{start_str}" AND '
                f'timestamp <= "{end_str}"'
            )
            
            # Use 'protoPayload' to target Audit Logs specifically if needed, 
            # but broad collection is often better for forensics.
            
            entries = []
            for entry in client.list_entries(filter_=filter_str, page_size=1000):
                entry_dict = {
                    "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
                    "insert_id": entry.insert_id,
                    "severity": entry.severity,
                    "resource": entry.resource.labels,
                    "payload": entry.payload,
                    "labels": entry.labels,
                }
                entries.append(entry_dict)

            if entries:
                raw_path = self.get_artifact_path("audit_logs.json")
                if not self.dry_run:
                    with open(raw_path, "w") as f:
                        json.dump(entries, f, default=str, indent=2)
                    
                    artifact = Artifact(
                        name="audit_logs.json",
                        source=self.name,
                        file_path=raw_path.relative_to(self.output_dir.parent),
                        sha256_hash=compute_sha256(raw_path),
                        size_bytes=raw_path.stat().st_size,
                        collected_at=datetime.utcnow(),
                        metadata={"entry_count": len(entries)}
                    )
                    artifacts.append(artifact)

            return self.create_result(True, artifacts)

        except Exception as e:
            self.add_error(f"GCP Log collection failed: {e}")
            return self.create_result(False)


class GCPComputeCollector(BaseCollector):
    """Collector for GCP Compute Engine metadata."""

    @property
    def name(self) -> str:
        return "compute_metadata"

    @property
    def description(self) -> str:
        return "Collects GCP Compute Engine instance metadata"

    def preflight_check(self) -> list[PermissionCheck]:
        checks = []
        try:
            # Requires google-cloud-compute
            client = compute_v1.InstancesClient()
            # We need a zone to check permissions typically, or use AggregatedList
            # Using aggregated list to check project-wide read perms
            request = compute_v1.AggregatedListInstancesRequest(project=self.scope.account_id, max_results=1)
            client.aggregated_list(request=request)
            checks.append(PermissionCheck("compute.instances.list", True))
        except exceptions.Forbidden:
             checks.append(PermissionCheck("compute.instances.list", False, message="Permission denied"))
        except Exception as e:
             checks.append(PermissionCheck("compute.instances.list", False, message=str(e)))
        return checks

    def collect(self, timeframe: TimeWindow) -> CollectorResult:
        artifacts = []
        try:
            client = compute_v1.InstancesClient()
            
            request = compute_v1.AggregatedListInstancesRequest(project=self.scope.account_id)
            agg_list = client.aggregated_list(request=request)
            
            instances = []
            for zone, response in agg_list:
                if response.instances:
                    for instance in response.instances:
                        # Convert to dict (protobuf to dict is complex, doing manual simplified extraction)
                        inst_dict = {
                            "name": instance.name,
                            "id": str(instance.id),
                            "zone": zone,
                            "machine_type": instance.machine_type,
                            "status": instance.status,
                            "network_interfaces": [
                                {"network_ip": ni.network_i_p, "name": ni.name} 
                                for ni in instance.network_interfaces
                            ],
                            "disks": [
                                {"source": d.source, "device_name": d.device_name} 
                                for d in instance.disks
                            ],
                            "creation_timestamp": instance.creation_timestamp,
                        }
                        instances.append(inst_dict)

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
                        collected_at=datetime.utcnow(),
                        metadata={"instance_count": len(instances)}
                    ))

            return self.create_result(True, artifacts)

        except Exception as e:
            self.add_error(f"Compute collection failed: {e}")
            return self.create_result(False)


class GCPIAMCollector(BaseCollector):
    """Collector for GCP IAM Policy bindings."""

    @property
    def name(self) -> str:
        return "iam_policy"

    @property
    def description(self) -> str:
        return "Collects Project-level IAM policy bindings"

    def preflight_check(self) -> list[PermissionCheck]:
        checks = []
        try:
            from google.cloud import resourcemanager_v3
            client = resourcemanager_v3.ProjectsClient()
            name = f"projects/{self.scope.account_id}"
            client.get_iam_policy(resource=name)
            checks.append(PermissionCheck("resourcemanager.projects.getIamPolicy", True))
        except Exception as e:
            checks.append(PermissionCheck("resourcemanager.projects.getIamPolicy", False, message=str(e)))
        return checks

    @with_retry()
    def collect(self, timeframe: TimeWindow) -> CollectorResult:
        artifacts = []
        try:
            from google.cloud import resourcemanager_v3
            client = resourcemanager_v3.ProjectsClient()
            name = f"projects/{self.scope.account_id}"
            policy = client.get_iam_policy(resource=name)
            
            # Serialize policy
            policy_dict = {
                "version": policy.version,
                "bindings": [
                    {"role": b.role, "members": list(b.members)} 
                    for b in policy.bindings
                ],
                "etag": str(policy.etag)
            }

            path = self.get_artifact_path("iam_policy.json")
            if not self.dry_run:
                with open(path, "w") as f:
                    json.dump(policy_dict, f, indent=2)
                artifacts.append(Artifact(
                    name="iam_policy.json",
                    source=self.name,
                    file_path=path.relative_to(self.output_dir.parent),
                    sha256_hash=compute_sha256(path),
                    size_bytes=path.stat().st_size,
                    collected_at=datetime.utcnow()
                ))

            return self.create_result(True, artifacts)
        except Exception as e:
            self.add_error(f"IAM policy collection failed: {e}")
            return self.create_result(False)


class GCPNetworkCollector(BaseCollector):
    """Collector for GCP Network configs (VPC Flow Logs)."""

    @property
    def name(self) -> str:
        return "vpc_config"

    @property
    def description(self) -> str:
        return "Collects VPC Network configurations and Flow Log status"

    def preflight_check(self) -> list[PermissionCheck]:
        checks = []
        try:
            client = compute_v1.NetworksClient()
            request = compute_v1.ListNetworksRequest(project=self.scope.account_id, max_results=1)
            client.list(request=request)
            checks.append(PermissionCheck("compute.networks.list", True))
        except Exception as e:
            checks.append(PermissionCheck("compute.networks.list", False, message=str(e)))
        return checks

    @with_retry()
    def collect(self, timeframe: TimeWindow) -> CollectorResult:
        artifacts = []
        try:
            client = compute_v1.NetworksClient()
            request = compute_v1.ListNetworksRequest(project=self.scope.account_id)
            
            networks = []
            for net in client.list(request=request):
                # Manual dict extraction
                net_dict = {
                    "name": net.name,
                    "id": str(net.id),
                    "auto_create_subnetworks": net.auto_create_subnetworks,
                    "subnetworks_link": list(net.subnetworks),
                }
                networks.append(net_dict)

            # Also Subnetworks for Flow Log config
            subnets_client = compute_v1.SubnetworksClient()
            agg_req = compute_v1.AggregatedListSubnetworksRequest(project=self.scope.account_id)
            
            flow_log_configs = []
            for zone, response in subnets_client.aggregated_list(request=agg_req):
                if response.subnetworks:
                    for sub in response.subnetworks:
                        if sub.enable_flow_logs:
                            flow_log_configs.append({
                                "name": sub.name,
                                "region": sub.region,
                                "network": sub.network,
                                "flow_logs_enabled": True,
                                "log_config": {
                                    "aggregation_interval": sub.log_config.aggregation_interval,
                                    "flow_sampling": sub.log_config.flow_sampling,
                                    "metadata": sub.log_config.metadata,
                                }
                            })

            if networks:
                path = self.get_artifact_path("vpc_networks.json")
                if not self.dry_run:
                    with open(path, "w") as f:
                        json.dump(networks, f, default=str, indent=2)
                    artifacts.append(Artifact(
                        name="vpc_networks.json",
                        source=self.name,
                        file_path=path.relative_to(self.output_dir.parent),
                        sha256_hash=compute_sha256(path),
                        size_bytes=path.stat().st_size,
                        collected_at=datetime.utcnow(),
                        metadata={"network_count": len(networks)}
                    ))
            
            if flow_log_configs:
                path = self.get_artifact_path("flow_log_configs.json")
                if not self.dry_run:
                    with open(path, "w") as f:
                        json.dump(flow_log_configs, f, default=str, indent=2)
                    artifacts.append(Artifact(
                        name="flow_log_configs.json",
                        source=self.name,
                        file_path=path.relative_to(self.output_dir.parent),
                        sha256_hash=compute_sha256(path),
                        size_bytes=path.stat().st_size,
                        collected_at=datetime.utcnow()
                    ))

            return self.create_result(True, artifacts)

        except Exception as e:
            self.add_error(f"Network config collection failed: {e}")
            return self.create_result(False)


class GCPCloudFunctionsCollector(BaseCollector):
    """Collector for GCP Cloud Functions metadata."""

    @property
    def name(self) -> str:
        return "cloud_functions"

    @property
    def description(self) -> str:
        return "Collects Cloud Functions inventory and metadata"

    def preflight_check(self) -> list[PermissionCheck]:
        checks = []
        try:
            from google.cloud import functions_v2
            client = functions_v2.FunctionServiceClient()
            request = functions_v2.ListFunctionsRequest(parent=f"projects/{self.scope.account_id}/locations/-")
            client.list_functions(request=request)
            checks.append(PermissionCheck("cloudfunctions.functions.list", True))
        except Exception as e:
            checks.append(PermissionCheck("cloudfunctions.functions.list", False, message=str(e)))
        return checks

    def collect(self, timeframe: TimeWindow) -> CollectorResult:
        artifacts = []
        try:
            from google.cloud import functions_v2
            client = functions_v2.FunctionServiceClient()
            request = functions_v2.ListFunctionsRequest(parent=f"projects/{self.scope.account_id}/locations/-")
            
            functions = []
            # 'locations/-' lists functions in all locations
            for func in client.list_functions(request=request):
                func_dict = {
                    "name": func.name,
                    "environment": func.environment.name,
                    "state": func.state.name,
                    "url": func.service_config.uri,
                    "updated": func.update_time.isoformat() if func.update_time else None,
                    "description": func.description,
                }
                functions.append(func_dict)

            if functions:
                path = self.get_artifact_path("cloud_functions.json")
                if not self.dry_run:
                    with open(path, "w") as f:
                        json.dump(functions, f, default=str, indent=2)
                    artifacts.append(Artifact(
                        name="cloud_functions.json",
                        source=self.name,
                        file_path=path.relative_to(self.output_dir.parent),
                        sha256_hash=compute_sha256(path),
                        size_bytes=path.stat().st_size,
                        collected_at=datetime.utcnow(),
                        metadata={"function_count": len(functions)}
                    ))

            return self.create_result(True, artifacts)

        except Exception as e:
            self.add_error(f"Cloud Functions collection failed: {e}")
            return self.create_result(False)


def get_gcp_collectors() -> dict[str, type[BaseCollector]]:
    """Return dictionary of GCP collectors."""
    return {
        "audit_logs": GCPLogCollector,
        "compute_metadata": GCPComputeCollector,
        "iam_policy": GCPIAMCollector,
        "vpc_config": GCPNetworkCollector,
        "cloud_functions": GCPCloudFunctionsCollector,
    }

# Register collectors
CollectorRegistry.register("gcp", "audit_logs", GCPLogCollector)
CollectorRegistry.register("gcp", "compute_metadata", GCPComputeCollector)
CollectorRegistry.register("gcp", "iam_policy", GCPIAMCollector)
CollectorRegistry.register("gcp", "vpc_config", GCPNetworkCollector)
CollectorRegistry.register("gcp", "cloud_functions", GCPCloudFunctionsCollector)
