"""Integration tests for Azure collectors using mocks."""

import pytest
import json
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta

from cfs.collectors.azure import AzureActivityLogCollector, AzureNetworkCollector
from cfs.types import CollectionScope, TimeWindow, CollectorConfig, CloudProvider

@pytest.fixture
def azure_scope():
    return CollectionScope(
        provider=CloudProvider.AZURE,
        account_id="test-subscription-id",
        incident_id="TEST-AZURE"
    )

@pytest.fixture
def timeframe():
    end = datetime.utcnow()
    return TimeWindow(start_time=end - timedelta(hours=1), end_time=end)

@patch("cfs.collectors.azure.DefaultAzureCredential")
@patch("cfs.collectors.azure.MonitorManagementClient")
def test_activity_log_collector(mock_monitor_client, mock_credential, azure_scope, timeframe, tmp_path):
    """Test Azure Activity Log collector with mocked client."""
    # Setup mock
    mock_client_instance = mock_monitor_client.return_value
    
    # Mock log entry
    mock_log = MagicMock()
    mock_log.as_dict.return_value = {
        "eventTimestamp": datetime.utcnow().isoformat(),
        "operationName": "Write",
        "resourceId": "/subscriptions/test/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
    }
    mock_client_instance.activity_logs.list.return_value = [mock_log]
    
    collector = AzureActivityLogCollector(
        scope=azure_scope,
        config=CollectorConfig(enabled=True),
        output_dir=tmp_path,
        dry_run=False
    )
    
    result = collector.collect(timeframe)
    
    assert result.success is True
    assert result.artifact_count == 1
    
    # Verify file content
    log_path = list(tmp_path.glob("**/activity_logs.json"))[0]
    with open(log_path) as f:
        data = json.load(f)
    assert len(data) == 1
    assert data[0]["operationName"] == "Write"

@patch("cfs.collectors.azure.DefaultAzureCredential")
@patch("cfs.collectors.azure.NetworkManagementClient")
def test_network_collector(mock_network_client, mock_credential, azure_scope, timeframe, tmp_path):
    """Test Azure Network collector."""
    mock_client_instance = mock_network_client.return_value
    
    # Mock NSG
    mock_nsg = MagicMock()
    mock_nsg.as_dict.return_value = {"name": "nsg-1", "id": "id-1"}
    mock_client_instance.network_security_groups.list_all.return_value = [mock_nsg]
    
    collector = AzureNetworkCollector(
        scope=azure_scope,
        config=CollectorConfig(enabled=True),
        output_dir=tmp_path,
        dry_run=False
    )
    
    result = collector.collect(timeframe)
    
    assert result.success is True
    assert result.artifact_count == 1
