"""
Coverage tests for the original 3 MVP check modules that had ~11% coverage.

Exercises pass/fail paths for each of the 10 original checks using
the make_check_context fixture with varying instance configurations.
"""

from amazon_connect_assessment.checks.cost_optimization_checks import (
    InefficientResourceAllocationCheck,
    OversizedConfigurationCheck,
    UnusedResourcesCheck,
)

# MultiAZConfigurationCheck, DisasterRecoveryConfigurationCheck, and
# FailoverMechanismCheck (from resilience_checks) were removed as noise
# generators — see that module's docstring. EncryptionConfigurationCheck and
# NetworkSecurityCheck (from security_checks) went the same way: neither
# actually verified what its name promised. Real security signal now lives in
# security_deep_checks (sec-storage-001, sec-federation-001, sec-origins-001).
from amazon_connect_assessment.checks.security_checks import (
    DataProtectionCheck,
    IAMServiceRoleCheck,
)
from amazon_connect_assessment.models import (
    CheckStatus,
    ContactFlow,
    Queue,
    RoutingProfile,
    SecurityProfile,
    User,
)

# --- Security checks ---


class TestIAMServiceRoleCheckOriginal:
    def test_no_role_fails(self, make_check_context, sample_connect_instance):
        sample_connect_instance.service_role = None
        f = IAMServiceRoleCheck().execute(make_check_context(instance=sample_connect_instance))
        assert f.status == CheckStatus.FAIL

    def test_invalid_arn_fails(self, make_check_context, sample_connect_instance):
        sample_connect_instance.service_role = "not-an-arn"
        f = IAMServiceRoleCheck().execute(make_check_context(instance=sample_connect_instance))
        assert f.status == CheckStatus.FAIL

    def test_valid_role_passes(self, make_check_context, sample_connect_instance):
        f = IAMServiceRoleCheck().execute(make_check_context(instance=sample_connect_instance))
        assert f.status == CheckStatus.PASS


# TestEncryptionCheckOriginal and TestNetworkSecurityCheckOriginal were removed
# alongside their subject checks. Both classes exercised finding-generation
# paths that no longer exist. sec-storage-001 and sec-federation-001 (in
# test_security_deep_checks.py) cover the same customer intents with checks
# that actually inspect AWS state.


class TestDataProtectionCheckOriginal:
    # DataProtectionCheck was rewritten to check exactly one thing: every
    # enabled user has a security profile assigned. The old "no security
    # profiles configured" and "contact flows configured — ensure GDPR
    # compliance" branches were removed — the first was a preference
    # dressed as a defect, the second was CISO-boilerplate that fired on
    # every instance. See the check's docstring for the rationale.

    def test_no_users_configured_passes(self, make_check_context, sample_connect_instance):
        # A brand-new instance with no users has nothing to check —
        # there are no users to lack a profile.
        sample_connect_instance.security_profiles = []
        sample_connect_instance.users = []
        sample_connect_instance.contact_flows = []
        f = DataProtectionCheck().execute(make_check_context(instance=sample_connect_instance))
        assert f.status == CheckStatus.PASS
        assert "no users configured" in f.description.lower()

    def test_users_without_profile_fails(self, make_check_context, sample_connect_instance):
        # The real defect: users exist but at least one has no profile.
        sample_connect_instance.security_profiles = [
            SecurityProfile(id="sp1", arn="a", security_profile_name="Agent"),
        ]
        sample_connect_instance.users = [
            User(id="u1", arn="a", username="alice", security_profile_ids=["sp1"]),
            User(id="u2", arn="a", username="bob", security_profile_ids=[]),
        ]
        sample_connect_instance.contact_flows = []
        f = DataProtectionCheck().execute(make_check_context(instance=sample_connect_instance))
        assert f.status == CheckStatus.FAIL
        assert "bob" in f.description

    def test_all_users_have_profile_passes(self, make_check_context, sample_connect_instance):
        sample_connect_instance.security_profiles = [
            SecurityProfile(id="sp1", arn="a", security_profile_name="Admin"),
            SecurityProfile(id="sp2", arn="a", security_profile_name="Agent"),
        ]
        sample_connect_instance.users = [
            User(id="u1", arn="a", username="alice", security_profile_ids=["sp2"]),
        ]
        sample_connect_instance.contact_flows = []
        f = DataProtectionCheck().execute(make_check_context(instance=sample_connect_instance))
        assert f.status == CheckStatus.PASS


# --- Resilience checks ---


# --- Cost optimization checks ---


class TestUnusedResourcesCheckOriginal:
    def test_users_without_routing_fails(self, make_check_context, sample_connect_instance):
        sample_connect_instance.users = [
            User(id="u1", arn="a", username="bob", routing_profile_id=None),
        ]
        sample_connect_instance.routing_profiles = [RoutingProfile(id="rp1", arn="a", name="RP")]
        sample_connect_instance.security_profiles = []
        sample_connect_instance.queues = []
        sample_connect_instance.contact_flows = []
        f = UnusedResourcesCheck().execute(make_check_context(instance=sample_connect_instance))
        assert f.status == CheckStatus.FAIL

    def test_all_assigned_passes(self, make_check_context, sample_connect_instance):
        sample_connect_instance.users = [
            User(id="u1", arn="a", username="bob", routing_profile_id="rp1"),
        ]
        sample_connect_instance.routing_profiles = [RoutingProfile(id="rp1", arn="a", name="RP")]
        sample_connect_instance.security_profiles = [
            SecurityProfile(id="sp1", arn="a", security_profile_name="Agent")
        ]
        sample_connect_instance.queues = [Queue(id="q1", arn="a", name="Q")]
        sample_connect_instance.contact_flows = [
            ContactFlow(id="cf1", arn="a", name="F", type="CONTACT_FLOW", state="ACTIVE")
        ]
        f = UnusedResourcesCheck().execute(make_check_context(instance=sample_connect_instance))
        assert f.status == CheckStatus.PASS


class TestOversizedCheckOriginal:
    def test_high_ratio_fails(self, make_check_context, sample_connect_instance):
        sample_connect_instance.users = [
            User(id=f"u{i}", arn="a", username=f"u{i}", routing_profile_id="rp1") for i in range(2)
        ]
        sample_connect_instance.security_profiles = [
            SecurityProfile(id=f"sp{i}", arn="a", security_profile_name=f"SP{i}") for i in range(3)
        ]
        sample_connect_instance.routing_profiles = [RoutingProfile(id="rp1", arn="a", name="RP")]
        sample_connect_instance.queues = []
        sample_connect_instance.contact_flows = []
        f = OversizedConfigurationCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )
        assert f.status == CheckStatus.FAIL

    def test_normal_ratios_pass(self, make_check_context, sample_connect_instance):
        sample_connect_instance.users = [
            User(id=f"u{i}", arn="a", username=f"u{i}", routing_profile_id="rp1") for i in range(10)
        ]
        sample_connect_instance.security_profiles = [
            SecurityProfile(id="sp1", arn="a", security_profile_name="Agent")
        ]
        sample_connect_instance.routing_profiles = [RoutingProfile(id="rp1", arn="a", name="RP")]
        sample_connect_instance.queues = [Queue(id="q1", arn="a", name="Q")]
        sample_connect_instance.contact_flows = [
            ContactFlow(id="cf1", arn="a", name="F", type="CONTACT_FLOW", state="ACTIVE")
        ]
        f = OversizedConfigurationCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )
        assert f.status == CheckStatus.PASS


class TestInefficientCheckOriginal:
    def test_unassigned_users_fails(self, make_check_context, sample_connect_instance):
        sample_connect_instance.users = [
            User(id="u1", arn="a", username="u1", routing_profile_id=None),
        ]
        sample_connect_instance.routing_profiles = [RoutingProfile(id="rp1", arn="a", name="RP")]
        sample_connect_instance.queues = [Queue(id="q1", arn="a", name="Q")]
        sample_connect_instance.contact_flows = [
            ContactFlow(id="cf1", arn="a", name="F", type="CONTACT_FLOW", state="ACTIVE")
        ]
        sample_connect_instance.integrations = []
        f = InefficientResourceAllocationCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )
        assert f.status == CheckStatus.FAIL

    def test_balanced_passes(self, make_check_context, sample_connect_instance):
        sample_connect_instance.users = [
            User(id="u1", arn="a", username="u1", routing_profile_id="rp1"),
            User(id="u2", arn="a", username="u2", routing_profile_id="rp1"),
        ]
        sample_connect_instance.routing_profiles = [RoutingProfile(id="rp1", arn="a", name="RP")]
        sample_connect_instance.queues = [Queue(id="q1", arn="a", name="Q")]
        sample_connect_instance.contact_flows = [
            ContactFlow(id="cf1", arn="a", name="F", type="CONTACT_FLOW", state="ACTIVE")
        ]
        sample_connect_instance.integrations = []
        f = InefficientResourceAllocationCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )
        assert f.status == CheckStatus.PASS
