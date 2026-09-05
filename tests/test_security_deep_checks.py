"""
Tests for deep-inspection security checks (Task 4 / Requirements 7-12).

Uses the mock AWSClientFactory with the real ``is_access_denied`` static method
wired in so the SKIPPED-on-access-denied paths exercise actual logic.
"""

from botocore.exceptions import ClientError

from amazon_connect_assessment.aws_client_factory import AWSClientFactory
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.checks.security_deep_checks import (
    ApprovedOriginsCheck,
    CloudTrailIntegrationCheck,
    IAMServiceRolePolicyCheck,
    IdentityFederationCheck,
    InstanceStorageEncryptionCheck,
    SecurityProfileAuditCheck,
    register_security_deep_checks,
)
from amazon_connect_assessment.models import CheckStatus, Severity


def _denied():
    def _raise(*a, **k):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "Op")

    return _raise


def _wire_real_access_denied(factory):
    # Mock(spec=...) replaces the staticmethod with a Mock; restore the real one.
    factory.is_access_denied = AWSClientFactory.is_access_denied


# --- IAM service role policy (sec-iam-deep-001) ---------------------------


class TestIAMServiceRolePolicyCheck:
    def test_no_service_role_fails(self, make_check_context, sample_connect_instance):
        sample_connect_instance.service_role = None
        finding = IAMServiceRolePolicyCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )
        assert finding.status == CheckStatus.FAIL
        assert finding.structured_remediation is not None

    def test_wildcard_write_on_star_resource_fails(
        self, make_check_context, mock_aws_client_factory
    ):
        _wire_real_access_denied(mock_aws_client_factory)
        f = mock_aws_client_factory
        f.list_role_policies_resilient.return_value = {"PolicyNames": ["inline1"]}
        f.get_role_policy_resilient.return_value = {
            "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": "*"}]
            }
        }
        f.list_attached_role_policies_resilient.return_value = {"AttachedPolicies": []}
        finding = IAMServiceRolePolicyCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "least-privilege" in finding.description.lower()

    def test_out_of_scope_action_fails(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        f = mock_aws_client_factory
        f.list_role_policies_resilient.return_value = {"PolicyNames": ["inline1"]}
        f.get_role_policy_resilient.return_value = {
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["iam:CreateUser"],
                        "Resource": "arn:x",
                    }
                ]
            }
        }
        f.list_attached_role_policies_resilient.return_value = {"AttachedPolicies": []}
        finding = IAMServiceRolePolicyCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "out-of-scope" in finding.description.lower()
        # remediation names the role
        assert finding.structured_remediation.target_resources

    def test_scoped_policy_passes(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        f = mock_aws_client_factory
        f.list_role_policies_resilient.return_value = {"PolicyNames": ["inline1"]}
        f.get_role_policy_resilient.return_value = {
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["connect:DescribeInstance"],
                        "Resource": "arn:aws:connect:us-east-1:123:instance/abc",
                    }
                ]
            }
        }
        f.list_attached_role_policies_resilient.return_value = {"AttachedPolicies": []}
        finding = IAMServiceRolePolicyCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS

    def test_access_denied_skips(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        mock_aws_client_factory.list_role_policies_resilient.side_effect = _denied()
        finding = IAMServiceRolePolicyCheck().execute(make_check_context())
        assert finding.status == CheckStatus.SKIPPED


# --- Storage encryption (sec-storage-001) ---------------------------------


class TestInstanceStorageEncryptionCheck:
    def test_unencrypted_storage_fails(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        f = mock_aws_client_factory

        def _configs(instance_id, resource_type):
            if resource_type == "CALL_RECORDINGS":
                return {"StorageConfigs": [{"StorageType": "S3", "S3Config": {"BucketName": "b"}}]}
            return {"StorageConfigs": []}

        f.list_instance_storage_configs_resilient.side_effect = _configs
        finding = InstanceStorageEncryptionCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "unencrypted" in finding.description.lower()

    def test_customer_managed_key_passes(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        f = mock_aws_client_factory

        def _configs(instance_id, resource_type):
            if resource_type == "CALL_RECORDINGS":
                return {
                    "StorageConfigs": [
                        {
                            "StorageType": "S3",
                            "S3Config": {
                                "BucketName": "b",
                                "EncryptionConfig": {"KeyId": "arn:aws:kms:...:key/abc"},
                            },
                        }
                    ]
                }
            return {"StorageConfigs": []}

        f.list_instance_storage_configs_resilient.side_effect = _configs
        finding = InstanceStorageEncryptionCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS

    def test_aws_managed_key_fails(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        f = mock_aws_client_factory

        def _configs(instance_id, resource_type):
            if resource_type == "CHAT_TRANSCRIPTS":
                return {
                    "StorageConfigs": [
                        {
                            "StorageType": "S3",
                            "S3Config": {
                                "BucketName": "b",
                                "EncryptionConfig": {"KeyId": "alias/aws/connect"},
                            },
                        }
                    ]
                }
            return {"StorageConfigs": []}

        f.list_instance_storage_configs_resilient.side_effect = _configs
        finding = InstanceStorageEncryptionCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "aws-managed" in finding.description.lower()


# --- Approved origins (sec-origins-001) -----------------------------------


class TestApprovedOriginsCheck:
    def test_wildcard_origin_fails(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        mock_aws_client_factory.list_approved_origins_resilient.return_value = {
            "Origins": ["https://app.example.com", "http://*"]
        }
        finding = ApprovedOriginsCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL

    def test_no_origins_is_not_applicable(self, make_check_context, mock_aws_client_factory):
        # Arrange
        _wire_real_access_denied(mock_aws_client_factory)
        mock_aws_client_factory.list_approved_origins_resilient.return_value = {"Origins": []}

        # Act
        finding = ApprovedOriginsCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.NOT_APPLICABLE
        assert "Contact Control Panel" in finding.description
        assert "safe default" in finding.description
        assert finding.structured_remediation is not None
        assert finding.structured_remediation.applies_if == (
            "the CCP is embedded in a custom agent application."
        )

    def test_specific_origins_pass(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        mock_aws_client_factory.list_approved_origins_resilient.return_value = {
            "Origins": ["https://app.example.com"]
        }
        finding = ApprovedOriginsCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS


# --- CloudTrail (sec-cloudtrail-001) --------------------------------------


class TestCloudTrailIntegrationCheck:
    def test_no_trail_fails(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        mock_aws_client_factory.describe_trails_resilient.return_value = {"trailList": []}
        finding = CloudTrailIntegrationCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL

    def test_trail_present_passes(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        mock_aws_client_factory.describe_trails_resilient.return_value = {
            "trailList": [{"Name": "audit", "IsMultiRegionTrail": True}]
        }
        finding = CloudTrailIntegrationCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS

    def test_access_denied_skips(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        mock_aws_client_factory.describe_trails_resilient.side_effect = _denied()
        finding = CloudTrailIntegrationCheck().execute(make_check_context())
        assert finding.status == CheckStatus.SKIPPED


# --- Federation (sec-federation-001) --------------------------------------


class TestIdentityFederationCheck:
    def test_saml_passes(self, make_check_context, sample_connect_instance):
        sample_connect_instance.identity_management_type = "SAML"
        finding = IdentityFederationCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )
        assert finding.status == CheckStatus.PASS

    def test_connect_managed_fails_with_applies_if(
        self, make_check_context, sample_connect_instance
    ):
        sample_connect_instance.identity_management_type = "CONNECT_MANAGED"
        finding = IdentityFederationCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )
        assert finding.status == CheckStatus.FAIL
        assert finding.structured_remediation.applies_if  # contextual qualifier

    def test_severity_is_low_not_medium(self):
        # Reviewer feedback: SAML is one good option, not the only
        # one -- Connect-managed identity paired with a third-party IdP
        # (Okta, Entra ID) for MFA is also viable. Downgraded from MEDIUM.
        assert IdentityFederationCheck().severity == Severity.LOW

    def test_connect_managed_description_mentions_third_party_idp_option(
        self, make_check_context, sample_connect_instance
    ):
        sample_connect_instance.identity_management_type = "CONNECT_MANAGED"
        finding = IdentityFederationCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )
        assert "not necessarily a gap" in finding.description
        assert "Okta" in finding.description or "third-party" in finding.description


# --- Security profile audit (sec-profile-audit-001) -----------------------


class TestSecurityProfileAuditCheck:
    def test_overprivileged_profile_fails(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        f = mock_aws_client_factory
        f.list_security_profiles_resilient.return_value = {
            "SecurityProfileSummaryList": [{"Id": "p1", "Name": "Agent"}]
        }
        f.list_security_profile_permissions_resilient.return_value = {
            "Permissions": ["Users.Create", "Users.Edit"]
        }
        finding = SecurityProfileAuditCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "Agent" in str(finding.structured_remediation.target_resources)

    def test_admin_profile_allowed(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        f = mock_aws_client_factory
        f.list_security_profiles_resilient.return_value = {
            "SecurityProfileSummaryList": [{"Id": "p1", "Name": "Admin"}]
        }
        f.list_security_profile_permissions_resilient.return_value = {
            "Permissions": ["Users.Create", "SecurityProfiles.Edit"]
        }
        finding = SecurityProfileAuditCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS

    def test_agent_profile_without_admin_passes(self, make_check_context, mock_aws_client_factory):
        _wire_real_access_denied(mock_aws_client_factory)
        f = mock_aws_client_factory
        f.list_security_profiles_resilient.return_value = {
            "SecurityProfileSummaryList": [{"Id": "p1", "Name": "Agent"}]
        }
        f.list_security_profile_permissions_resilient.return_value = {
            "Permissions": ["Contacts.View", "Dashboards.View"]
        }
        finding = SecurityProfileAuditCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS


# --- Registration ----------------------------------------------------------


def test_register_security_deep_checks_registers_six():
    registry = CheckRegistry()
    register_security_deep_checks(registry)
    ids = {c.check_id for c in registry.get_all_checks()}
    assert {
        "sec-iam-deep-001",
        "sec-storage-001",
        "sec-origins-001",
        "sec-cloudtrail-001",
        "sec-federation-001",
        "sec-profile-audit-001",
    } <= ids
