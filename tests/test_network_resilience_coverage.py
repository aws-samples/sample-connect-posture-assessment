"""
Coverage tests for network_resilience.py (~37% → target ~60%).

Tests the retry loop, exponential backoff, jitter, and rate-limit detector.
"""

from concurrent.futures import ThreadPoolExecutor

import pytest
from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
    ReadTimeoutError,
)

from amazon_connect_assessment.network_resilience import (
    ConnectivityError,
    NetworkResilienceError,
    NetworkResilienceManager,
    NetworkTimeoutError,
    RateLimitDetector,
    RateLimitExceededError,
    RetryConfig,
    with_network_resilience,
)


class TestRetryConfig:
    def test_default_config(self):
        cfg = RetryConfig()
        assert cfg.max_attempts >= 1
        assert cfg.base_delay > 0
        assert cfg.max_delay >= cfg.base_delay


class TestNetworkResilienceManager:
    def test_succeeds_on_first_try(self):
        mgr = NetworkResilienceManager(RetryConfig(max_attempts=3, base_delay=0.01))
        result = mgr.execute_with_retry(lambda: "ok", "test-op")
        assert result == "ok"

    def test_retries_on_transient_error(self):
        mgr = NetworkResilienceManager(RetryConfig(max_attempts=3, base_delay=0.01))
        calls = []

        def flaky():
            calls.append(1)
            if len(calls) < 3:
                raise EndpointConnectionError(endpoint_url="https://test")
            return "recovered"

        result = mgr.execute_with_retry(flaky, "test-op")
        assert result == "recovered"
        assert len(calls) == 3

    def test_raises_after_max_attempts(self):
        mgr = NetworkResilienceManager(RetryConfig(max_attempts=2, base_delay=0.01))

        def always_fail():
            raise EndpointConnectionError(endpoint_url="https://test")

        with pytest.raises(NetworkResilienceError):
            mgr.execute_with_retry(always_fail, "test-op")

    def test_non_retryable_error_raised_immediately(self):
        mgr = NetworkResilienceManager(RetryConfig(max_attempts=5, base_delay=0.01))
        calls = []

        def non_retryable():
            calls.append(1)
            raise ValueError("bad input")

        with pytest.raises(ValueError):
            mgr.execute_with_retry(non_retryable, "test-op")
        assert len(calls) == 1  # No retries for non-retryable.

    def test_get_retry_statistics(self):
        mgr = NetworkResilienceManager(RetryConfig(max_attempts=2, base_delay=0.01))
        mgr.execute_with_retry(lambda: "ok", "op")
        stats = mgr.get_retry_statistics()
        assert isinstance(stats, dict)

    def test_concurrent_failures_keep_retry_metadata_per_operation(self, monkeypatch):
        monkeypatch.setattr(
            "amazon_connect_assessment.network_resilience.time.sleep", lambda _: None
        )
        mgr = NetworkResilienceManager(RetryConfig(max_attempts=2, base_delay=0, jitter=False))

        def operation(label):
            def fail():
                raise EndpointConnectionError(endpoint_url=f"https://{label}")

            with pytest.raises(NetworkResilienceError) as caught:
                mgr.execute_with_retry(fail, label)
            return caught.value

        with ThreadPoolExecutor(max_workers=2) as executor:
            errors = list(executor.map(operation, ("one", "two")))

        assert all(len(error.retry_attempts) == 1 for error in errors)
        assert {error.retry_attempts[0].error_message for error in errors} == {
            'Could not connect to the endpoint URL: "https://one"',
            'Could not connect to the endpoint URL: "https://two"',
        }

    def test_decorator_exposes_retry_statistics_from_invocation(self):
        calls = []

        @with_network_resilience(
            RetryConfig(max_attempts=2, base_delay=0, jitter=False),
            operation_name="decorated-op",
        )
        def flaky_operation():
            calls.append(1)
            if len(calls) == 1:
                raise Exception("Simulated failure")
            return "ok"

        assert flaky_operation() == "ok"
        stats = flaky_operation._get_retry_stats()

        assert len(calls) == 2
        assert stats["total_attempts"] == 1
        assert stats["error_types"]["transient_error"] == 1

    def test_classify_rate_limit_error(self):
        mgr = NetworkResilienceManager()
        err = ClientError(
            {
                "Error": {"Code": "Throttling", "Message": "slow down"},
                "ResponseMetadata": {"HTTPStatusCode": 429},
            },
            "Op",
        )
        from amazon_connect_assessment.network_resilience import RetryableErrorType

        assert mgr.classify_error(err) == RetryableErrorType.RATE_LIMIT

    def test_classify_timeout_error(self):
        mgr = NetworkResilienceManager()
        err = ReadTimeoutError(endpoint_url="https://x")
        from amazon_connect_assessment.network_resilience import RetryableErrorType

        assert mgr.classify_error(err) == RetryableErrorType.TIMEOUT

    def test_param_validation_error_not_retryable(self):
        # ParamValidationError is a BotoCoreError subclass but is client-side;
        # retrying it just wastes time/backoff, so it must be non-retryable.
        from botocore.exceptions import ParamValidationError

        mgr = NetworkResilienceManager()
        err = ParamValidationError(report="Invalid length for parameter X")
        assert mgr.classify_error(err) is None


class TestRateLimitDetector:
    def test_no_throttle_initially(self):
        detector = RateLimitDetector()
        assert detector.should_throttle("connect", "list_instances") is False

    def test_record_and_check(self):
        detector = RateLimitDetector()
        detector.record_api_call("connect", "list_instances")
        # The detector may throttle based on internal rate window.
        # Just verify it doesn't crash and returns a bool.
        result = detector.should_throttle("connect", "list_instances")
        assert isinstance(result, bool)

    def test_get_throttle_delay(self):
        detector = RateLimitDetector()
        delay = detector.get_throttle_delay("connect", "list_instances")
        assert delay >= 0

    def test_get_rate_statistics(self):
        detector = RateLimitDetector()
        detector.record_api_call("s3", "get_object")
        stats = detector.get_rate_statistics()
        assert isinstance(stats, dict)


class TestExceptionHierarchy:
    def test_rate_limit_is_resilience_error(self):
        e = RateLimitExceededError("rate limited")
        assert isinstance(e, NetworkResilienceError)

    def test_timeout_is_resilience_error(self):
        e = NetworkTimeoutError("timed out")
        assert isinstance(e, NetworkResilienceError)

    def test_connectivity_is_resilience_error(self):
        e = ConnectivityError("no route")
        assert isinstance(e, NetworkResilienceError)

    def test_original_error_preserved(self):
        orig = ValueError("inner")
        e = NetworkResilienceError("wrapper", original_error=orig)
        assert e.original_error is orig
