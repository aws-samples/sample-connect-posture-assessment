"""Tests for the S3 report publisher."""

import boto3
import pytest
from moto import mock_aws

from amazon_connect_assessment.report.s3_publisher import (
    is_valid_bucket_name,
    publish_reports,
    standard_bucket_name,
)


class _FakeFactory:
    """Minimal stand-in exposing get_s3_client()."""

    def __init__(self, region):
        self.region = region

    def get_s3_client(self):
        return boto3.client("s3", region_name=self.region)


@pytest.fixture
def report_file(tmp_path):
    p = tmp_path / "connect_assessment_20260629_123456789012.html"
    p.write_text("<html><body>report</body></html>")
    return str(p)


def test_standard_bucket_name_and_validation():
    name = standard_bucket_name("123456789012")
    assert name == "amazon-connect-assessment-report-123456789012"
    assert is_valid_bucket_name(name)
    assert not is_valid_bucket_name("AB")  # too short / uppercase
    assert not is_valid_bucket_name("-leading-hyphen")


@mock_aws
def test_creates_hardened_bucket_and_uploads(report_file):
    factory = _FakeFactory("us-east-1")
    result = publish_reports(factory, [report_file], account_id="123456789012", region="us-east-1")

    assert result.succeeded
    assert result.bucket_created is True
    assert result.bucket == "amazon-connect-assessment-report-123456789012"
    assert len(result.uploaded_uris) == 1
    assert result.uploaded_uris[0].startswith("s3://")

    s3 = boto3.client("s3", region_name="us-east-1")
    # Hardening applied
    pab = s3.get_public_access_block(Bucket=result.bucket)
    assert pab["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is True
    enc = s3.get_bucket_encryption(Bucket=result.bucket)
    assert enc["ServerSideEncryptionConfiguration"]["Rules"]
    ver = s3.get_bucket_versioning(Bucket=result.bucket)
    assert ver.get("Status") == "Enabled"


@mock_aws
def test_reuses_existing_bucket(report_file):
    bucket = "amazon-connect-assessment-report-123456789012"
    boto3.client("s3", region_name="us-east-1").create_bucket(Bucket=bucket)

    factory = _FakeFactory("us-east-1")
    result = publish_reports(factory, [report_file], account_id="123456789012", region="us-east-1")

    assert result.succeeded
    assert result.bucket_created is False

    s3 = boto3.client("s3", region_name="us-east-1")
    pab = s3.get_public_access_block(Bucket=bucket)
    assert pab["PublicAccessBlockConfiguration"]["RestrictPublicBuckets"] is True
    assert s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"]
    assert s3.get_bucket_versioning(Bucket=bucket).get("Status") == "Enabled"


@mock_aws
def test_non_us_east_1_uses_location_constraint(report_file):
    factory = _FakeFactory("us-west-2")
    result = publish_reports(factory, [report_file], account_id="123456789012", region="us-west-2")
    assert result.succeeded
    assert result.bucket_created is True


def test_invalid_bucket_name_override_errors(report_file):
    factory = _FakeFactory("us-east-1")
    result = publish_reports(
        factory,
        [report_file],
        account_id="123456789012",
        region="us-east-1",
        bucket_name="Invalid_Name_With_Underscores",
    )
    assert not result.succeeded
    assert result.error and "not a valid" in result.error


# ---------------------------------------------------------------------------
# Regression test: bucket left partially hardened on failure.
#
# create_bucket succeeded, but if put_public_access_block / put_bucket_
# encryption / put_bucket_versioning threw, the bucket was left existing
# but un-hardened, and every subsequent run would see _bucket_exists
# return True and skip hardening entirely (hardening only ever runs on
# first creation). _create_hardened_bucket now rolls back (deletes) the
# bucket it just created if any hardening step fails, so the NEXT run
# starts from a clean "does not exist" state and retries the full
# create+harden sequence instead of silently reusing a half-hardened
# bucket forever.
# ---------------------------------------------------------------------------


@mock_aws
def test_hardening_failure_rolls_back_bucket_creation(report_file, monkeypatch):
    import boto3 as boto3_module

    factory = _FakeFactory("us-east-1")
    bucket = "amazon-connect-assessment-report-123456789012"

    real_client = boto3_module.client("s3", region_name="us-east-1")

    class FailingEncryptionClient:
        """Wraps the real moto S3 client but fails put_bucket_encryption."""

        def __getattr__(self, name):
            return getattr(real_client, name)

        def put_bucket_encryption(self, **kwargs):
            raise RuntimeError("simulated throttle on PutBucketEncryption")

    factory.get_s3_client = lambda: FailingEncryptionClient()

    result = publish_reports(factory, [report_file], account_id="123456789012", region="us-east-1")

    assert not result.succeeded
    assert result.error is not None

    # The bucket must NOT exist afterward — the rollback should have
    # deleted it so the next run retries creation+hardening from scratch
    # instead of finding an existing-but-unhardened bucket.
    with pytest.raises(Exception):
        real_client.head_bucket(Bucket=bucket)


@mock_aws
def test_next_run_after_rollback_creates_and_hardens_successfully(report_file):
    """
    Follow-up run after a simulated hardening failure must succeed and
    produce a properly hardened bucket — proving the rollback actually
    left a clean slate rather than a broken partial bucket blocking
    future attempts.
    """
    import boto3 as boto3_module

    bucket = "amazon-connect-assessment-report-123456789012"
    real_client = boto3_module.client("s3", region_name="us-east-1")

    class FailingEncryptionClient:
        def __getattr__(self, name):
            return getattr(real_client, name)

        def put_bucket_encryption(self, **kwargs):
            raise RuntimeError("simulated throttle")

    failing_factory = _FakeFactory("us-east-1")
    failing_factory.get_s3_client = lambda: FailingEncryptionClient()
    first_result = publish_reports(
        failing_factory, [report_file], account_id="123456789012", region="us-east-1"
    )
    assert not first_result.succeeded

    # Second attempt with a working client should succeed cleanly.
    good_factory = _FakeFactory("us-east-1")
    second_result = publish_reports(
        good_factory, [report_file], account_id="123456789012", region="us-east-1"
    )
    assert second_result.succeeded
    assert second_result.bucket_created is True

    pab = real_client.get_public_access_block(Bucket=bucket)
    assert pab["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is True
