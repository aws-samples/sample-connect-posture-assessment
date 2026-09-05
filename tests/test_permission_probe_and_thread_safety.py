"""
Regression tests for two AWSClientFactory fixes:

1. The --check-permissions S3 probe used s3:ListBuckets to pick a bucket
   to test against, but that action is not part of the documented
   assessment IAM policy. A least-privilege role that follows the
   documented policy exactly would fail list_buckets and get both S3
   permissions reported as "missing" even though it was never actually
   exercised against a real bucket — a false negative on a correctly
   provisioned role. The fix discovers a bucket via
   connect:ListInstanceStorageConfigs (already in the documented policy
   and already used by sec-storage-001) instead.

2. get_client()/get_session() did check-then-act on self._clients /
   self._session with no lock, so concurrent first-touch of the same
   service from two worker threads under the parallel engine could race.
   Both now hold per-purpose locks with a double-checked pattern.
"""

import threading
from unittest.mock import Mock, patch

from amazon_connect_assessment.aws_client_factory import AWSClientFactory


class TestS3PermissionProbeDiscovery:
    def test_no_s3_listbuckets_call_is_ever_made(self):
        """
        The whole point of the fix: nothing in the S3 permission probe
        path should call s3:ListBuckets, since it's not in the documented
        policy. Assert on the actual API surface, not just behavior, so a
        future refactor can't quietly reintroduce it.
        """
        factory = AWSClientFactory(region="us-east-1")
        factory.list_connect_instances_resilient = Mock(
            return_value={"InstanceSummaryList": [{"Id": "iid-1"}]}
        )
        factory.list_instance_storage_configs_resilient = Mock(
            return_value={
                "StorageConfigs": [
                    {"StorageType": "S3", "S3Config": {"BucketName": "my-recordings-bucket"}}
                ]
            }
        )
        factory.get_s3_bucket_policy_resilient = Mock(return_value={"Policy": "{}"})
        factory.get_s3_bucket_encryption_resilient = Mock(
            return_value={"ServerSideEncryptionConfiguration": {}}
        )
        factory.call_api_with_resilience = Mock(
            side_effect=AssertionError("s3:ListBuckets must never be called by this path")
        )

        tested, missing = factory._test_s3_permissions()

        assert tested == ["s3:GetBucketPolicy", "s3:GetEncryptionConfiguration"]
        assert missing == []
        factory.call_api_with_resilience.assert_not_called()

    def test_discovers_bucket_from_call_recordings_storage_config(self):
        factory = AWSClientFactory(region="us-east-1")
        factory.list_connect_instances_resilient = Mock(
            return_value={"InstanceSummaryList": [{"Id": "iid-1"}]}
        )

        def storage_configs(instance_id, resource_type):
            if resource_type == "CALL_RECORDINGS":
                return {
                    "StorageConfigs": [
                        {
                            "StorageType": "S3",
                            "S3Config": {"BucketName": "call-recordings-bucket"},
                        }
                    ]
                }
            return {"StorageConfigs": []}

        factory.list_instance_storage_configs_resilient = Mock(side_effect=storage_configs)
        bucket = factory._discover_s3_bucket_for_permission_test()
        assert bucket == "call-recordings-bucket"

    def test_falls_through_resource_types_in_order(self):
        # No CALL_RECORDINGS bucket, but CHAT_TRANSCRIPTS has one — the
        # discovery should keep trying resource types.
        factory = AWSClientFactory(region="us-east-1")
        factory.list_connect_instances_resilient = Mock(
            return_value={"InstanceSummaryList": [{"Id": "iid-1"}]}
        )

        def storage_configs(instance_id, resource_type):
            if resource_type == "CHAT_TRANSCRIPTS":
                return {
                    "StorageConfigs": [
                        {"StorageType": "S3", "S3Config": {"BucketName": "transcripts-bucket"}}
                    ]
                }
            return {"StorageConfigs": []}

        factory.list_instance_storage_configs_resilient = Mock(side_effect=storage_configs)
        bucket = factory._discover_s3_bucket_for_permission_test()
        assert bucket == "transcripts-bucket"

    def test_no_instance_returns_none_not_missing_permissions(self):
        # No Connect instance at all -> nothing to test against. This must
        # be reported as "untested", not "missing" — see
        # validate_permissions, which logs this distinction explicitly.
        factory = AWSClientFactory(region="us-east-1")
        factory.list_connect_instances_resilient = Mock(return_value={"InstanceSummaryList": []})

        bucket = factory._discover_s3_bucket_for_permission_test()
        assert bucket is None

        tested, missing = factory._test_s3_permissions()
        assert tested == []
        assert missing == []

    def test_no_s3_backed_storage_config_returns_none(self):
        factory = AWSClientFactory(region="us-east-1")
        factory.list_connect_instances_resilient = Mock(
            return_value={"InstanceSummaryList": [{"Id": "iid-1"}]}
        )
        factory.list_instance_storage_configs_resilient = Mock(return_value={"StorageConfigs": []})
        assert factory._discover_s3_bucket_for_permission_test() is None

    def test_access_denied_on_bucket_probe_reports_missing(self):
        from botocore.exceptions import ClientError

        factory = AWSClientFactory(region="us-east-1")
        factory.list_connect_instances_resilient = Mock(
            return_value={"InstanceSummaryList": [{"Id": "iid-1"}]}
        )
        factory.list_instance_storage_configs_resilient = Mock(
            return_value={
                "StorageConfigs": [{"StorageType": "S3", "S3Config": {"BucketName": "my-bucket"}}]
            }
        )
        factory.get_s3_bucket_policy_resilient = Mock(
            side_effect=ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetBucketPolicy"
            )
        )
        factory.get_s3_bucket_encryption_resilient = Mock(
            return_value={"ServerSideEncryptionConfiguration": {}}
        )

        tested, missing = factory._test_s3_permissions()
        assert "s3:GetBucketPolicy" in tested
        assert "s3:GetBucketPolicy" in missing
        assert "s3:GetEncryptionConfiguration" not in missing

    def test_required_permissions_includes_list_phone_numbers_v2(self):
        # connect:ListPhoneNumbersV2 underpins the Journey Map, cost
        # checks, and several resilience checks, but was entirely absent
        # from the --check-permissions smoke-test list — a role missing
        # only that permission would pass every probe and then see the
        # Journey Map silently produce nothing.
        assert "connect:ListPhoneNumbersV2" in AWSClientFactory.REQUIRED_PERMISSIONS


class TestClientAndSessionThreadSafety:
    def test_concurrent_get_client_creates_exactly_one_client_per_service(self):
        """
        Simulates the exact race described in review: multiple worker
        threads first-touching the same AWS service concurrently. Without
        the lock, session.client(...) could be invoked more than once for
        the same service_name; with it, exactly one client is created and
        every thread observes the same cached instance.
        """
        factory = AWSClientFactory(region="us-east-1")

        creation_count = {"n": 0}
        creation_lock = threading.Lock()

        class FakeSession:
            def client(self, service_name, config=None):
                with creation_lock:
                    creation_count["n"] += 1
                # Simulate the non-trivial work botocore does when
                # constructing a client, to widen the race window.
                threading.Event().wait(0.01)
                return Mock(name=f"{service_name}-client")

        with patch.object(factory, "get_session", return_value=FakeSession()):
            results = {}

            def worker(name):
                results[name] = factory.get_client("connect")

            threads = [threading.Thread(target=worker, args=(f"t{i}",)) for i in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)

            assert all(not t.is_alive() for t in threads)
            assert creation_count["n"] == 1
            # Every thread must have received the SAME cached client
            # object, not just "a" client.
            first = results["t0"]
            assert all(r is first for r in results.values())

    def test_concurrent_get_session_creates_exactly_one_session(self):
        factory = AWSClientFactory(region="us-east-1")
        creation_count = {"n": 0}
        creation_lock = threading.Lock()

        def fake_create_default_session():
            with creation_lock:
                creation_count["n"] += 1
            threading.Event().wait(0.01)
            return Mock(name="session")

        with patch.object(
            factory, "_create_default_session", side_effect=fake_create_default_session
        ):
            results = {}

            def worker(name):
                results[name] = factory.get_session()

            threads = [threading.Thread(target=worker, args=(f"t{i}",)) for i in range(20)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5)

            assert all(not t.is_alive() for t in threads)
            assert creation_count["n"] == 1
            first = results["t0"]
            assert all(r is first for r in results.values())

    def test_clear_cache_is_lock_guarded(self):
        # Not a concurrency assertion per se — just confirms clear_cache
        # still works correctly after adding locks around the fields it
        # touches.
        factory = AWSClientFactory(region="us-east-1")
        factory._clients["connect"] = Mock()
        factory._session = Mock()
        factory.clear_cache()
        assert factory._clients == {}
        assert factory._session is None
