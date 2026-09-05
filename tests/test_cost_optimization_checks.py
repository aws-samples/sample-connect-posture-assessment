"""
Tests for UnusedResourcesCheck and OversizedConfigurationCheck
(cost-unused-001 / cost-oversized-001).

Focused on the reviewer-driven changes:
- Both checks now explicitly frame their findings as operational/
  administrative observations, not cost-savings estimates -- Amazon
  Connect does not charge per security profile, routing profile, or
  queue.
- OversizedConfigurationCheck's "high contact flow count relative to
  other components" heuristic was removed entirely: AWS's own best
  practice recommends *more, smaller* modular flows, so a high flow
  count is the expected shape of a well-built instance, not a defect.
  Detection logic for the remaining ratios (security profile / routing
  profile / queue relative to users) is otherwise unchanged.
"""

from amazon_connect_assessment.checks.cost_optimization_checks import (
    OversizedConfigurationCheck,
    UnusedResourcesCheck,
)
from amazon_connect_assessment.models import (
    CheckStatus,
    ContactFlow,
    Queue,
    RoutingProfile,
    SecurityProfile,
    Severity,
    User,
)
from tests.conftest import build_action, build_contact_flow


def _user(uid, routing_profile_id=None):
    return User(
        id=uid, arn=f"arn:...:agent/{uid}", username=uid, routing_profile_id=routing_profile_id
    )


def _queue(qid):
    return Queue(id=qid, arn=f"arn:...:queue/{qid}", name=qid)


def _routing_profile(rpid):
    return RoutingProfile(id=rpid, arn=f"arn:...:routing-profile/{rpid}", name=rpid)


def _security_profile(spid):
    return SecurityProfile(
        id=spid, arn=f"arn:...:security-profile/{spid}", security_profile_name=spid
    )


def _flow(fid):
    return ContactFlow(
        id=fid,
        arn=f"arn:...:flow/{fid}",
        name=fid,
        type="CONTACT_FLOW",
        state="ACTIVE",
        content=build_contact_flow([build_action("a1", "DisconnectParticipant")]),
    )


class TestUnusedResourcesCheck:
    def test_severity_is_low_not_medium(self):
        # Reviewer feedback: unused configuration is an operational
        # observation, not a cost driver -- downgraded from MEDIUM.
        assert UnusedResourcesCheck().severity == Severity.LOW

    def test_queues_with_no_users_fails_with_operational_framing(
        self, make_check_context, sample_connect_instance
    ):
        sample_connect_instance.queues = [_queue("q1")]
        sample_connect_instance.users = []
        finding = UnusedResourcesCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )
        assert finding.status == CheckStatus.FAIL
        # Reviewer feedback: must not imply this saves money -- Connect
        # doesn't charge per queue/profile.
        assert "not a cost-savings estimate" in finding.description
        assert "cleanup_recommendations" in finding.evidence
        assert "cost_savings_opportunities" not in finding.evidence

    def test_clean_setup_passes(self, make_check_context, sample_connect_instance):
        sample_connect_instance.users = [_user("u1", routing_profile_id="rp1")]
        sample_connect_instance.queues = [_queue("q1")]
        sample_connect_instance.routing_profiles = [_routing_profile("rp1")]
        sample_connect_instance.security_profiles = [_security_profile("sp1")]
        sample_connect_instance.contact_flows = [_flow("f1")]
        finding = UnusedResourcesCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )
        assert finding.status == CheckStatus.PASS


class TestOversizedConfigurationCheck:
    def test_high_contact_flow_count_no_longer_flagged(
        self, make_check_context, sample_connect_instance
    ):
        # Regression test: this used to fail once contact_flows exceeded
        # users + queues + routing_profiles. AWS explicitly recommends
        # building many small modular flows rather than few large ones,
        # so a high flow count must not be treated as oversizing.
        # 10 users keeps every other ratio (security/routing profile per
        # user, queue per routing profile) well under its own threshold,
        # so only the (now-removed) flow-count heuristic could fail this.
        sample_connect_instance.users = [
            _user(f"u{i}", routing_profile_id="rp1") for i in range(10)
        ]
        sample_connect_instance.queues = [_queue("q1")]
        sample_connect_instance.routing_profiles = [_routing_profile("rp1")]
        sample_connect_instance.security_profiles = [_security_profile("sp1")]
        sample_connect_instance.contact_flows = [_flow(f"f{i}") for i in range(20)]
        finding = OversizedConfigurationCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )
        assert finding.status == CheckStatus.PASS
        assert "contact_flow_to_component_ratio" not in finding.evidence

    def test_high_security_profile_ratio_fails_with_operational_framing(
        self, make_check_context, sample_connect_instance
    ):
        sample_connect_instance.users = [_user("u1")]
        sample_connect_instance.security_profiles = [_security_profile(f"sp{i}") for i in range(3)]
        finding = OversizedConfigurationCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )
        assert finding.status == CheckStatus.FAIL
        assert "not a cost-savings estimate" in finding.description
