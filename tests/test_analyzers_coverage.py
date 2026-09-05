"""
Coverage tests for the 5 analyzer modules (~11-18% → target ~70%).

Each analyzer's `analyze()` method makes AWS API calls via the factory.
We mock those calls to return realistic responses and verify the
instance object gets populated correctly.
"""

from unittest.mock import Mock

from amazon_connect_assessment.analyzers.connect_instance_analyzer import (
    ConnectInstanceAnalyzer,
)
from amazon_connect_assessment.analyzers.contact_flow_analyzer import (
    ContactFlowAnalyzer,
)
from amazon_connect_assessment.analyzers.integration_analyzer import (
    IntegrationAnalyzer,
)
from amazon_connect_assessment.analyzers.queue_analyzer import QueueAnalyzer
from amazon_connect_assessment.analyzers.security_profile_analyzer import (
    SecurityProfileAnalyzer,
)
from amazon_connect_assessment.models import ConnectInstance


def _make_instance():
    return ConnectInstance(
        instance_id="inst-test",
        instance_arn="arn:aws:connect:us-east-1:123456789012:instance/inst-test",
        identity_management_type="CONNECT_MANAGED",
        inbound_calls_enabled=True,
        outbound_calls_enabled=True,
        status="ACTIVE",
    )


def _make_factory():
    factory = Mock()
    factory.get_connect_client.return_value = Mock()
    factory.get_cloudwatch_client.return_value = Mock()
    factory.get_s3_client.return_value = Mock()
    factory.get_client.return_value = Mock()
    factory.call_api_with_resilience = Mock()
    factory.list_connect_instances_resilient = Mock()
    factory.describe_connect_instance_resilient = Mock()
    factory.list_contact_flows_resilient = Mock()
    factory.list_queues_resilient = Mock()
    return factory


class TestConnectInstanceAnalyzer:
    def test_resilient_pagination_uses_next_token(self):
        factory = _make_factory()
        factory.call_api_with_resilience.side_effect = [
            {"InstanceSummaryList": [], "NextToken": "page-2"},
            {"InstanceSummaryList": []},
        ]
        analyzer = ConnectInstanceAnalyzer(factory)

        pages = list(
            analyzer.paginate_api_resilient(
                factory.get_connect_client.return_value,
                "list_instances",
                "connect",
            )
        )

        assert len(pages) == 2
        assert factory.call_api_with_resilience.call_args_list[1].kwargs["NextToken"] == "page-2"

    def test_analyze_populates_nothing_on_empty_responses(self):
        factory = _make_factory()
        analyzer = ConnectInstanceAnalyzer(factory)
        instance = _make_instance()
        # analyze() on ConnectInstanceAnalyzer typically doesn't populate
        # sub-resources — it's for instance-level discovery. Exercise safe_analyze.
        result = analyzer.safe_analyze(instance)
        assert result.instance_id == "inst-test"

    def test_safe_analyze_handles_errors_gracefully(self):
        factory = _make_factory()
        factory.call_api_with_resilience.side_effect = Exception("boom")
        analyzer = ConnectInstanceAnalyzer(factory)
        instance = _make_instance()
        result = analyzer.safe_analyze(instance)
        # Should return original instance on failure.
        assert result is instance


class TestContactFlowAnalyzer:
    def test_safe_analyze_on_api_error_returns_original(self):
        factory = _make_factory()
        factory.get_connect_client.return_value.get_paginator.side_effect = Exception("api error")
        analyzer = ContactFlowAnalyzer(factory)
        instance = _make_instance()
        result = analyzer.safe_analyze(instance)
        assert result is instance

    def test_safe_analyze_with_empty_paginator(self):
        factory = _make_factory()
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{"ContactFlowSummaryList": []}]
        factory.get_connect_client.return_value.get_paginator.return_value = mock_paginator
        analyzer = ContactFlowAnalyzer(factory)
        instance = _make_instance()
        result = analyzer.safe_analyze(instance)
        assert result.contact_flows == []


class TestQueueAnalyzer:
    def test_safe_analyze_on_error_returns_original(self):
        factory = _make_factory()
        factory.get_connect_client.return_value.get_paginator.side_effect = Exception("fail")
        analyzer = QueueAnalyzer(factory)
        instance = _make_instance()
        result = analyzer.safe_analyze(instance)
        assert result is instance

    def test_safe_analyze_with_empty_paginator(self):
        factory = _make_factory()
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{"QueueSummaryList": []}]
        factory.get_connect_client.return_value.get_paginator.return_value = mock_paginator
        analyzer = QueueAnalyzer(factory)
        instance = _make_instance()
        result = analyzer.safe_analyze(instance)
        assert result.queues == []


class TestSecurityProfileAnalyzer:
    def test_safe_analyze_on_error_returns_original(self):
        factory = _make_factory()
        factory.get_connect_client.return_value.get_paginator.side_effect = Exception("fail")
        analyzer = SecurityProfileAnalyzer(factory)
        instance = _make_instance()
        result = analyzer.safe_analyze(instance)
        assert result is instance

    def test_safe_analyze_with_empty_paginator(self):
        factory = _make_factory()
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [{"SecurityProfileSummaryList": []}]
        factory.get_connect_client.return_value.get_paginator.return_value = mock_paginator
        analyzer = SecurityProfileAnalyzer(factory)
        instance = _make_instance()
        result = analyzer.safe_analyze(instance)
        assert result.security_profiles == []


class TestIntegrationAnalyzer:
    def test_safe_analyze_on_error_returns_original(self):
        factory = _make_factory()
        factory.get_connect_client.return_value.list_lambda_functions.side_effect = Exception(
            "fail"
        )
        factory.call_api_with_resilience.side_effect = Exception("fail")
        analyzer = IntegrationAnalyzer(factory)
        instance = _make_instance()
        result = analyzer.safe_analyze(instance)
        assert result is instance

    def test_safe_analyze_with_no_integrations(self):
        factory = _make_factory()
        client = factory.get_connect_client.return_value
        client.list_lambda_functions.return_value = {"LambdaFunctions": []}
        # IntegrationAnalyzer may use call_api_with_resilience or direct client.
        factory.call_api_with_resilience.return_value = {
            "LambdaFunctions": [],
            "LexBots": [],
        }
        analyzer = IntegrationAnalyzer(factory)
        instance = _make_instance()
        result = analyzer.safe_analyze(instance)
        # Should not crash; may have empty integrations.
        assert result.instance_id == "inst-test"
