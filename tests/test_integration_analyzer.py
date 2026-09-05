"""
Tests for IntegrationAnalyzer, focused on the S3 integration discovery fix.

Regression: _analyze_s3_integrations() called
connect_client.describe_instance_storage_config(InstanceId=..., ResourceType=...)
without an AssociationId — but DescribeInstanceStorageConfig requires
AssociationId as part of its input shape (it describes ONE specific storage
config, not "all configs of this resource type"). Since no AssociationId
was ever known at this point, the call always raised, got caught by a
bare `except Exception` treating it as "no storage config exists", and S3
integration discovery silently returned an empty list regardless of what
was actually configured.

The fix switches to ListInstanceStorageConfigs (InstanceId + ResourceType
only, no AssociationId needed) — the correct discovery-shaped API — and
checks every resource type supported by that API.
"""

from unittest.mock import Mock

import pytest

from amazon_connect_assessment.analyzers.integration_analyzer import IntegrationAnalyzer


def _factory_with_connect_client(connect_client):
    factory = Mock()
    factory.get_connect_client.return_value = connect_client
    factory.get_client.return_value = connect_client
    factory.list_instance_storage_configs_resilient.side_effect = (
        lambda instance_id, resource_type: connect_client.list_instance_storage_configs(
            InstanceId=instance_id,
            ResourceType=resource_type,
        )
    )
    return factory


class TestS3IntegrationDiscovery:
    def test_uses_list_instance_storage_configs_not_describe(self):
        connect_client = Mock()
        connect_client.list_instance_storage_configs.return_value = {"StorageConfigs": []}

        analyzer = IntegrationAnalyzer(_factory_with_connect_client(connect_client))
        analyzer._analyze_s3_integrations("iid-1")

        connect_client.list_instance_storage_configs.assert_called()
        connect_client.describe_instance_storage_config.assert_not_called()

    def test_discovers_s3_bucket_from_call_recordings(self):
        connect_client = Mock()

        def list_configs(InstanceId, ResourceType):
            if ResourceType == "CALL_RECORDINGS":
                return {
                    "StorageConfigs": [
                        {
                            "StorageType": "S3",
                            "S3Config": {
                                "BucketName": "recordings-bucket",
                                "BucketPrefix": "recordings/",
                            },
                        }
                    ]
                }
            return {"StorageConfigs": []}

        connect_client.list_instance_storage_configs.side_effect = list_configs
        analyzer = IntegrationAnalyzer(_factory_with_connect_client(connect_client))
        # Avoid real S3 calls for bucket detail enrichment.
        analyzer._get_s3_bucket_details = Mock(return_value={})

        integrations = analyzer._analyze_s3_integrations("iid-1")

        assert len(integrations) == 1
        assert integrations[0].integration_type == "s3"
        assert integrations[0].resource_id == "recordings-bucket"

    def test_checks_multiple_resource_types(self):
        connect_client = Mock()
        seen_resource_types = []

        def list_configs(InstanceId, ResourceType):
            seen_resource_types.append(ResourceType)
            return {"StorageConfigs": []}

        connect_client.list_instance_storage_configs.side_effect = list_configs
        analyzer = IntegrationAnalyzer(_factory_with_connect_client(connect_client))
        analyzer._analyze_s3_integrations("iid-1")

        assert "CALL_RECORDINGS" in seen_resource_types
        assert "CHAT_TRANSCRIPTS" in seen_resource_types
        assert "SCHEDULED_REPORTS" in seen_resource_types
        assert "MEDIA_STREAMS" in seen_resource_types
        assert "CONTACT_TRACE_RECORDS" in seen_resource_types
        assert "AGENT_EVENTS" in seen_resource_types

    def test_discovers_s3_bucket_from_media_streams(self):
        connect_client = Mock()

        def list_configs(InstanceId, ResourceType):
            if ResourceType == "MEDIA_STREAMS":
                return {
                    "StorageConfigs": [
                        {
                            "StorageType": "S3",
                            "S3Config": {"BucketName": "media-streams-bucket"},
                        }
                    ]
                }
            return {"StorageConfigs": []}

        connect_client.list_instance_storage_configs.side_effect = list_configs
        analyzer = IntegrationAnalyzer(_factory_with_connect_client(connect_client))
        analyzer._get_s3_bucket_details = Mock(return_value={})

        integrations = analyzer._analyze_s3_integrations("iid-1")

        assert [integration.resource_id for integration in integrations] == ["media-streams-bucket"]

    def test_non_s3_storage_type_is_skipped(self):
        connect_client = Mock()
        connect_client.list_instance_storage_configs.return_value = {
            "StorageConfigs": [{"StorageType": "KINESIS_STREAM"}]
        }
        analyzer = IntegrationAnalyzer(_factory_with_connect_client(connect_client))
        integrations = analyzer._analyze_s3_integrations("iid-1")
        assert integrations == []

    def test_api_error_on_one_resource_type_is_reported(self):
        connect_client = Mock()

        def list_configs(InstanceId, ResourceType):
            if ResourceType == "CALL_RECORDINGS":
                raise Exception("boom")
            if ResourceType == "CHAT_TRANSCRIPTS":
                return {
                    "StorageConfigs": [
                        {"StorageType": "S3", "S3Config": {"BucketName": "transcripts"}}
                    ]
                }
            return {"StorageConfigs": []}

        connect_client.list_instance_storage_configs.side_effect = list_configs
        analyzer = IntegrationAnalyzer(_factory_with_connect_client(connect_client))
        analyzer._get_s3_bucket_details = Mock(return_value={})

        with pytest.raises(Exception, match="boom"):
            analyzer._analyze_s3_integrations("iid-1")

    def test_no_storage_configured_returns_empty_list(self):
        connect_client = Mock()
        connect_client.list_instance_storage_configs.return_value = {"StorageConfigs": []}
        analyzer = IntegrationAnalyzer(_factory_with_connect_client(connect_client))
        assert analyzer._analyze_s3_integrations("iid-1") == []
