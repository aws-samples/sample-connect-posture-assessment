"""
Publish assessment reports to an S3 bucket in the assessed account.

After an assessment runs, the generated report file(s) can be uploaded to a
standard, account-scoped S3 bucket so they can be shared back (for example,
when the tool is deployed into a customer account via CloudFormation and the
customer returns the report).

Design notes:
- Bucket name is deterministic: ``amazon-connect-assessment-report-<account_id>``.
  This keeps one report bucket per account, with a predictable name.
- The bucket is created only if it does not already exist, and is created
  hardened: S3 Block Public Access enabled, default SSE-S3 encryption, and
  versioning enabled. Creating storage is an infrastructure-write side effect,
  so the caller decides whether to invoke this (it is opt-in via --s3-output).
- Upload failures never abort the assessment; they are reported to the caller.

This module is intentionally self-contained so it can evolve independently of
the CLI and report generation.
"""

import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

logger = logging.getLogger(__name__)

# Prefix for the standard per-account report bucket name.
BUCKET_PREFIX = "amazon-connect-assessment-report"

# S3 bucket names: 3-63 chars, lowercase letters, digits, hyphens and dots,
# must start and end with a letter or digit.
_BUCKET_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]$")


@dataclass
class PublishResult:
    """Outcome of an S3 publish attempt."""

    bucket: str
    region: str
    uploaded_uris: List[str] = field(default_factory=list)
    bucket_created: bool = False
    console_url: Optional[str] = None
    error: Optional[str] = None

    @property
    def succeeded(self) -> bool:
        return self.error is None and bool(self.uploaded_uris)


def standard_bucket_name(account_id: str) -> str:
    """Return the standard report bucket name for an account."""
    return f"{BUCKET_PREFIX}-{account_id}"


def is_valid_bucket_name(name: str) -> bool:
    """Validate an S3 bucket name against the core naming rules."""
    if not name or len(name) < 3 or len(name) > 63:
        return False
    if ".." in name or ".-" in name or "-." in name:
        return False
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", name):  # not an IP address
        return False
    return _BUCKET_NAME_RE.match(name) is not None


def _bucket_exists(s3_client, bucket: str) -> bool:
    """Return True if the bucket exists and is accessible to the caller."""
    from botocore.exceptions import ClientError

    try:
        s3_client.head_bucket(Bucket=bucket)
        return True
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("404", "NoSuchBucket"):
            return False
        # 403 means it exists but is owned/locked by someone else; surface that.
        raise


def _create_hardened_bucket(s3_client, bucket: str, region: str) -> None:
    """
    Create a bucket with Block Public Access, default encryption, versioning.

    If any hardening step (public-access-block / encryption / versioning)
    fails after ``create_bucket`` has already succeeded, the bucket would
    otherwise be left existing but un-hardened — and every subsequent run
    would see ``_bucket_exists`` return True and skip hardening entirely,
    since hardening only ever runs on first creation. That's a silent,
    permanent gap: a transient throttle on one PutBucket* call during the
    very first run could leave the report bucket without Block Public
    Access indefinitely.

    To close that gap, if any hardening call fails we attempt to delete
    the bucket we just created (best-effort — the bucket has no objects
    yet since nothing has been uploaded at this point) and re-raise the
    original error. ``publish_reports`` catches the exception and reports
    it to the caller; the next run will see the bucket does not exist and
    try to create+harden it again from scratch, rather than silently
    reusing a half-hardened bucket forever.
    """
    create_kwargs = {"Bucket": bucket}
    # us-east-1 must NOT specify a LocationConstraint; every other region must.
    if region and region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3_client.create_bucket(**create_kwargs)

    try:
        s3_client.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        s3_client.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )
        s3_client.put_bucket_versioning(
            Bucket=bucket,
            VersioningConfiguration={"Status": "Enabled"},
        )
    except Exception:
        logger.error(
            "Hardening failed for newly created bucket %s; attempting to "
            "roll back the bucket so the next run doesn't reuse it "
            "un-hardened.",
            bucket,
        )
        try:
            s3_client.delete_bucket(Bucket=bucket)
            logger.info("Rolled back (deleted) partially-hardened bucket: %s", bucket)
        except Exception as cleanup_error:  # noqa: BLE001
            logger.error(
                "Failed to roll back bucket %s after hardening failure — "
                "it may now exist un-hardened. Manual cleanup or hardening "
                "may be required: %s",
                bucket,
                cleanup_error,
            )
        raise

    logger.info("Created hardened report bucket: %s", bucket)


def _ensure_bucket_hardened(s3_client, bucket: str) -> None:
    """Apply the report-bucket security baseline to an existing bucket."""
    from botocore.exceptions import ClientError

    s3_client.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    try:
        s3_client.get_bucket_encryption(Bucket=bucket)
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "")
        if code not in (
            "ServerSideEncryptionConfigurationNotFoundError",
            "NoSuchBucket",
        ):
            raise
        s3_client.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )

    s3_client.put_bucket_versioning(
        Bucket=bucket,
        VersioningConfiguration={"Status": "Enabled"},
    )


def _content_type(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    return {
        ".html": "text/html",
        ".json": "application/json",
        ".csv": "text/csv",
    }.get(ext, "application/octet-stream")


def publish_reports(
    aws_client_factory,
    report_paths: List[str],
    account_id: str,
    region: str,
    bucket_name: Optional[str] = None,
) -> PublishResult:
    """
    Upload report file(s) to the account's standard report bucket.

    Args:
        aws_client_factory: Factory providing a credentialed S3 client.
        report_paths: Local paths of generated report files to upload.
        account_id: AWS account ID (used for the default bucket name).
        region: AWS region to create/use the bucket in.
        bucket_name: Optional override for the bucket name.

    Returns:
        PublishResult describing what was uploaded (or the error encountered).
    """
    bucket = bucket_name or standard_bucket_name(account_id)
    result = PublishResult(bucket=bucket, region=region)

    if not is_valid_bucket_name(bucket):
        result.error = f"'{bucket}' is not a valid S3 bucket name. Override it with --s3-bucket."
        logger.error(result.error)
        return result

    try:
        s3 = aws_client_factory.get_s3_client()

        if not _bucket_exists(s3, bucket):
            _create_hardened_bucket(s3, bucket, region)
            result.bucket_created = True
        else:
            _ensure_bucket_hardened(s3, bucket)

        prefix = datetime.now(timezone.utc).strftime("%Y/%m/%d/%H%M%SZ")
        for path in report_paths:
            if not path or not os.path.isfile(path):
                continue
            key = f"{prefix}/{os.path.basename(path)}"
            s3.upload_file(
                Filename=path,
                Bucket=bucket,
                Key=key,
                ExtraArgs={
                    "ContentType": _content_type(path),
                    "ServerSideEncryption": "AES256",
                },
            )
            result.uploaded_uris.append(f"s3://{bucket}/{key}")
            logger.info("Uploaded report to s3://%s/%s", bucket, key)

        result.console_url = (
            f"https://s3.console.aws.amazon.com/s3/buckets/{bucket}"
            f"?region={region}&prefix={prefix}/"
        )
    except Exception as e:  # noqa: BLE001 - upload must never abort the run
        result.error = str(e)
        logger.error("Failed to publish reports to S3: %s", e)

    return result
