"""
Extended coverage tests for aws_client_factory.py (42% → target ~60%).

Tests credential validation, permission probes, network stats, and config.
"""

from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import (
    ClientError,
    NoCredentialsError,
)

from amazon_connect_assessment.aws_client_factory import (
    AWSClientFactory,
    CredentialSource,
)


class TestCredentialValidation:
    def test_valid_credentials(self):
        factory = AWSClientFactory(region="us-east-1")
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test",
        }
        with patch.object(factory, "get_sts_client", return_value=mock_sts):
            result = factory.validate_credentials()
        assert result.is_valid is True
        assert result.account_id == "123456789012"

    def test_no_credentials(self):
        factory = AWSClientFactory(region="us-east-1")
        mock_sts = Mock()
        mock_sts.get_caller_identity.side_effect = NoCredentialsError()
        with patch.object(factory, "get_sts_client", return_value=mock_sts):
            result = factory.validate_credentials()
        assert result.is_valid is False
        assert "credentials" in result.error_message.lower()

    def test_access_denied_on_sts(self):
        factory = AWSClientFactory(region="us-east-1")
        mock_sts = Mock()
        mock_sts.get_caller_identity.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetCallerIdentity"
        )
        with patch.object(factory, "get_sts_client", return_value=mock_sts):
            result = factory.validate_credentials()
        assert result.is_valid is False


class TestCredentialSourceDetection:
    def test_cloudshell(self, monkeypatch):
        monkeypatch.setenv("CLOUDSHELL", "true")
        factory = AWSClientFactory(region="us-east-1")
        assert factory._determine_credential_source() == CredentialSource.CLOUDSHELL

    def test_env_vars(self, monkeypatch):
        monkeypatch.delenv("CLOUDSHELL", raising=False)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "x")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "y")
        factory = AWSClientFactory(region="us-east-1")
        assert factory._determine_credential_source() == CredentialSource.ENVIRONMENT_VARIABLES

    def test_profile(self, monkeypatch):
        monkeypatch.delenv("CLOUDSHELL", raising=False)
        monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
        monkeypatch.setenv("AWS_PROFILE", "myprof")
        factory = AWSClientFactory(region="us-east-1")
        assert factory._determine_credential_source() == CredentialSource.AWS_PROFILE


class TestNetworkResilienceStats:
    def test_get_stats(self):
        factory = AWSClientFactory(region="us-east-1")
        stats = factory.get_network_resilience_statistics()
        assert "retry_statistics" in stats
        assert "configuration" in stats
        assert stats["configuration"]["rate_limiting_enabled"] is True

    def test_reset_stats(self):
        factory = AWSClientFactory(region="us-east-1")
        factory.reset_network_resilience_statistics()
        stats = factory.get_network_resilience_statistics()
        assert stats is not None

    def test_configure_resilience(self):
        factory = AWSClientFactory(region="us-east-1")
        factory.configure_network_resilience(
            max_attempts=10, base_delay=2.0, enable_rate_limiting=False
        )
        assert factory.network_resilience_config.max_attempts == 10
        assert factory.network_resilience_config.base_delay == 2.0
        assert factory.rate_limit_detector is None


class TestClearCache:
    def test_clear_cache_resets_state(self):
        factory = AWSClientFactory(region="us-east-1")
        factory._clients["test"] = Mock()
        factory.clear_cache()
        assert factory._clients == {}
        assert factory._session is None
        assert factory._credential_validation is None


class TestProfileSession:
    def test_invalid_profile_raises(self):
        factory = AWSClientFactory(region="us-east-1", profile_name="nonexistent-xyz")
        with pytest.raises(Exception, match="not found"):
            factory.get_session()
