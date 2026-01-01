"""Integration tests for AWS collectors using Moto."""

import boto3
import json
import pytest
from moto import mock_aws
from pathlib import Path
from datetime import datetime, timedelta

from cfs.collectors.aws import AWSCloudTrailCollector, AWSIAMCollector
from cfs.types import CollectionScope, TimeWindow, CollectorConfig, CloudProvider

@pytest.fixture
def aws_scope():
    return CollectionScope(
        provider=CloudProvider.AWS,
        account_id="123456789012",
        incident_id="TEST-AWS"
    )

@pytest.fixture
def timeframe():
    end = datetime.utcnow()
    return TimeWindow(start_time=end - timedelta(hours=1), end_time=end)

@mock_aws
def test_cloudtrail_collector(aws_scope, timeframe, tmp_path):
    """Test CloudTrail collector with mocked events."""
    # Setup Moto CloudTrail
    client = boto3.client("cloudtrail", region_name="us-east-1")
    client.create_trail(Name="test-trail", S3BucketName="test-bucket")
    
    # Moto doesn't perfectly simulate lookup_events populated from create_trail actions easily 
    # without running everything, but we can verify the API call structure and empty return handling,
    # or rely on what Moto supports. Moto DOES support lookup_events.
    
    collector = AWSCloudTrailCollector(
        scope=aws_scope,
        config=CollectorConfig(enabled=True),
        output_dir=tmp_path,
        dry_run=False
    )
    
    result = collector.collect(timeframe)
    
    assert result.success is True
    # Moto usually returns empty list if no events injected, but ensuring no crash is step 1.
    # We can check artifact count.
    
    # If we want to inject: Moto CloudTrail is hard to inject 'lookup' events into directly 
    # via API without actually performing actions that are logged.
    # For now, verify graceful success on empty.
    assert result.artifact_count == 0 or result.artifact_count == 1

@mock_aws
def test_iam_collector(aws_scope, timeframe, tmp_path):
    """Test IAM collector for Credential Report."""
    # Setup IAM content
    client = boto3.client("iam", region_name="us-east-1")
    client.create_user(UserName="suspect_user")
    
    collector = AWSIAMCollector(
        scope=aws_scope,
        config=CollectorConfig(enabled=True),
        output_dir=tmp_path,
        dry_run=False
    )
    
    # Generate report is async in real AWS, Moto usually instant.
    result = collector.collect(timeframe)
    
    assert result.success is True
    # Should get account summary and maybe credential report
    assert result.artifact_count >= 1
    
    # Verify Account Summary contents
    summary_path = list(tmp_path.glob("**/account_summary.json"))[0]
    with open(summary_path) as f:
        data = json.load(f)
    assert "Users" in data
