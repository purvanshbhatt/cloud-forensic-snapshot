"""Integration tests for GCP collectors using mocks."""

import pytest
import json
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta

from cfs.collectors.gcp import GCPLogCollector, GCPComputeCollector
from cfs.types import CollectionScope, TimeWindow, CollectorConfig, CloudProvider

@pytest.fixture
def gcp_scope():
    return CollectionScope(
        provider=CloudProvider.GCP,
        account_id="test-project-id",
        incident_id="TEST-GCP"
    )

@pytest.fixture
def timeframe():
    end = datetime.utcnow()
    return TimeWindow(start_time=end - timedelta(hours=1), end_time=end)

@patch("cfs.collectors.gcp.cloud_logging.Client")
def test_gcp_log_collector(mock_logging_client, gcp_scope, timeframe, tmp_path):
    """Test GCP Log collector."""
    mock_client_instance = mock_logging_client.return_value
    
    # Mock logging entry
    mock_entry = MagicMock()
    mock_entry.timestamp = datetime.utcnow()
    mock_entry.insert_id = "test-insert-id"
    mock_entry.severity = "NOTICE"
    mock_entry.resource.labels = {"instance_id": "123"}
    mock_entry.payload = {"proto_payload": "test"}
    mock_entry.labels = {"key": "value"}
    
    mock_client_instance.list_entries.return_value = [mock_entry]
    
    collector = GCPLogCollector(
        scope=gcp_scope,
        config=CollectorConfig(enabled=True),
        output_dir=tmp_path,
        dry_run=False
    )
    
    result = collector.collect(timeframe)
    
    assert result.success is True
    assert result.artifact_count == 1
    
    # Verify file
    log_path = list(tmp_path.glob("**/audit_logs.json"))[0]
    with open(log_path) as f:
        data = json.load(f)
    assert len(data) == 1
    assert data[0]["insert_id"] == "test-insert-id"

@patch("cfs.collectors.gcp.compute_v1.InstancesClient")
def test_gcp_compute_collector(mock_instances_client, gcp_scope, timeframe, tmp_path):
    """Test GCP Compute collector."""
    mock_client_instance = mock_instances_client.return_value
    
    # Mock AggregatedList response
    mock_response = MagicMock()
    
    mock_instance = MagicMock()
    mock_instance.name = "instance-1"
    mock_instance.id = 12345
    mock_instance.machine_type = "n1-standard-1"
    mock_instance.status = "RUNNING"
    mock_instance.network_interfaces = []
    mock_instance.disks = []
    mock_instance.creation_timestamp = "2023-01-01T00:00:00.000-07:00"
    
    mock_response.instances = [mock_instance]
    
    # Mock iterator (list of tuples: zone, response)
    mock_client_instance.aggregated_list.return_value = [("zones/us-central1-a", mock_response)]
    
    collector = GCPComputeCollector(
        scope=gcp_scope,
        config=CollectorConfig(enabled=True),
        output_dir=tmp_path,
        dry_run=False
    )
    
    result = collector.collect(timeframe)
    
    assert result.success is True
    assert result.artifact_count == 1
    
    # Verify file
    inst_path = list(tmp_path.glob("**/instances.json"))[0]
    with open(inst_path) as f:
        data = json.load(f)
    assert len(data) == 1
    assert data[0]["name"] == "instance-1"
