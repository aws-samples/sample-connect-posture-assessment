"""
Tests for advanced resilience checks.

Covers the ACGR check set (six atomic checks) plus the other resilience
advanced checks (CloudWatch alarm coverage, carrier diversity, hardcoded
routing).
"""

from botocore.exceptions import ClientError

from amazon_connect_assessment.aws_client_factory import AWSClientFactory
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.checks.resilience_advanced_checks import (
    ACGRConfigurationCheck,
    ACGRFailoverTestCheck,
    ACGRIdentityManagementCheck,
    ACGRPhoneNumberBindingCheck,
    ACGRTrafficDistributionCheck,
    ACGRTrafficDistributionGroupStatusCheck,
    CarrierDiversityCheck,
    CloudWatchAlarmMonitoringCheck,
    HardcodedRoutingCheck,
    _reset_acgr_cache,
    register_advanced_resilience_checks,
)
from amazon_connect_assessment.models import CheckStatus, ContactFlow, Severity
from tests.conftest import build_action, build_contact_flow


def _wire(factory):
    factory.is_access_denied = AWSClientFactory.is_access_denied


def _instance_with_flow(instance, flow_json, name="TestFlow"):
    instance.contact_flows = [
        ContactFlow(
            id="f1",
            arn="arn:...:flow/f1",
            name=name,
            type="CONTACT_FLOW",
            state="ACTIVE",
            content=flow_json,
        )
    ]
    return instance


def _instance_with_flows(instance, flows):
    """
    Attach multiple (name, flow_json) pairs as distinct ContactFlow
    objects. Used by the AWS-default-sample-flow-exclusion tests, which
    need both a "Sample ..." flow and a customer-named flow on the same
    instance to prove the sample one is excluded while the customer one
    is still evaluated.
    """
    instance.contact_flows = [
        ContactFlow(
            id=f"f{i}",
            arn=f"arn:...:flow/f{i}",
            name=name,
            type="CONTACT_FLOW",
            state="ACTIVE",
            content=flow_json,
        )
        for i, (name, flow_json) in enumerate(flows)
    ]
    return instance


# ---------------------------------------------------------------------------
# ACGR helpers
#
# The six ACGR checks memoize per-instance API results in a module-level
# cache. Reset it between tests so cases don't leak into each other, and
# provide a helper that programs the factory mock to return whatever TDG
# shape a test needs.
# ---------------------------------------------------------------------------


def _program_acgr_apis(
    factory,
    *,
    tdgs=None,
    tdg_details=None,
    traffic_distributions=None,
    tdg_phone_numbers=None,
    instance_phone_numbers=None,
    cloudtrail_events=None,
    access_denied_on=None,
):
    """
    Route `call_api_with_resilience` responses for the ACGR context probes.

    `access_denied_on` is an optional set of operation names that should raise
    AccessDenied instead of returning a value — used to exercise the SKIPPED
    degradation paths.
    """
    _reset_acgr_cache()
    tdgs = tdgs or []
    tdg_details = tdg_details or {}
    traffic_distributions = traffic_distributions or {}
    tdg_phone_numbers = tdg_phone_numbers or {}
    instance_phone_numbers = instance_phone_numbers or []
    cloudtrail_events = cloudtrail_events or []
    access_denied_on = access_denied_on or set()

    def _side_effect(client, op_name, service, **kwargs):
        if op_name in access_denied_on:
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, op_name)
        if op_name == "list_traffic_distribution_groups":
            return {"TrafficDistributionGroupSummaryList": tdgs}
        if op_name == "describe_traffic_distribution_group":
            tdg_id = kwargs.get("TrafficDistributionGroupId")
            return {"TrafficDistributionGroup": tdg_details.get(tdg_id, {})}
        if op_name == "get_traffic_distribution":
            tdg_id = kwargs.get("Id")
            return traffic_distributions.get(tdg_id, {})
        if op_name == "list_phone_numbers_v2":
            target = kwargs.get("TargetArn", "")
            if "traffic-distribution-group" in target:
                # Match by TDG ARN if provided
                nums = tdg_phone_numbers.get(target, [])
                return {"ListPhoneNumbersSummaryList": nums}
            return {"ListPhoneNumbersSummaryList": instance_phone_numbers}
        if op_name == "lookup_events":
            return {"Events": cloudtrail_events}
        return {}

    factory.call_api_with_resilience.side_effect = _side_effect


# ---------------------------------------------------------------------------
# res-acgr-config-001 — ACGR Configuration Discovery
# ---------------------------------------------------------------------------


class TestACGRConfigurationCheck:
    def test_no_tdg_is_not_applicable(self, make_check_context, mock_aws_client_factory):
        # No TDG configured → NOT_APPLICABLE (previously an informational
        # PASS with remediation; user feedback was that even a soft PASS
        # here cluttered reports for the ~95% who don't need ACGR).
        _wire(mock_aws_client_factory)
        _program_acgr_apis(mock_aws_client_factory, tdgs=[])
        finding = ACGRConfigurationCheck().execute(make_check_context())
        assert finding.status == CheckStatus.NOT_APPLICABLE
        # The reason is carried in the description prefix ("Not applicable: ...")
        assert "not configured" in finding.description.lower()
        # No structured remediation on N/A findings — nothing to fix.
        assert finding.structured_remediation is None

    def test_tdg_present_passes_and_reports_configured(
        self, make_check_context, mock_aws_client_factory
    ):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[
                {
                    "Id": "tdg-1",
                    "Name": "prod-tdg",
                    "Arn": "arn:aws:connect:us-east-1:1:traffic-distribution-group/tdg-1",
                }
            ],
        )
        finding = ACGRConfigurationCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS
        assert "configured" in finding.description.lower()
        assert finding.evidence["traffic_distribution_groups"] == 1

    def test_access_denied_skips(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            access_denied_on={"list_traffic_distribution_groups"},
        )
        finding = ACGRConfigurationCheck().execute(make_check_context())
        assert finding.status == CheckStatus.SKIPPED


# ---------------------------------------------------------------------------
# res-acgr-identity-001 — SAML identity required
# ---------------------------------------------------------------------------


class TestACGRIdentityManagementCheck:
    def test_no_tdg_is_not_applicable(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(mock_aws_client_factory, tdgs=[])
        finding = ACGRIdentityManagementCheck().execute(make_check_context())
        assert finding.status == CheckStatus.NOT_APPLICABLE
        assert "acgr is not configured" in finding.description.lower()

    def test_connect_managed_identity_with_tdg_fails(
        self, make_check_context, mock_aws_client_factory, sample_connect_instance
    ):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
        )
        # Fixture already uses CONNECT_MANAGED.
        assert sample_connect_instance.identity_management_type == "CONNECT_MANAGED"
        finding = ACGRIdentityManagementCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "saml" in finding.description.lower()
        assert finding.severity.value == "high"
        # Remediation must not pretend this is a quick toggle.
        step = finding.structured_remediation.steps[0].instruction.lower()
        assert "cannot be changed in place" in step or "migration" in step

    def test_saml_identity_with_tdg_passes(
        self, make_check_context, mock_aws_client_factory, sample_connect_instance
    ):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
        )
        sample_connect_instance.identity_management_type = "SAML"
        finding = ACGRIdentityManagementCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )
        assert finding.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# res-acgr-tdg-status-001 — TDG in ACTIVE status
# ---------------------------------------------------------------------------


class TestACGRTrafficDistributionGroupStatusCheck:
    def test_no_tdg_is_not_applicable(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(mock_aws_client_factory, tdgs=[])
        finding = ACGRTrafficDistributionGroupStatusCheck().execute(make_check_context())
        assert finding.status == CheckStatus.NOT_APPLICABLE

    def test_all_tdgs_active_passes(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[
                {"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"},
                {"Id": "tdg-2", "Name": "dr-tdg", "Arn": "arn:...:tdg/tdg-2"},
            ],
            tdg_details={
                "tdg-1": {"Id": "tdg-1", "Status": "ACTIVE"},
                "tdg-2": {"Id": "tdg-2", "Status": "ACTIVE"},
            },
        )
        finding = ACGRTrafficDistributionGroupStatusCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS

    def test_non_active_tdg_fails(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[
                {"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"},
                {"Id": "tdg-2", "Name": "dr-tdg", "Arn": "arn:...:tdg/tdg-2"},
            ],
            tdg_details={
                "tdg-1": {"Id": "tdg-1", "Status": "ACTIVE"},
                "tdg-2": {"Id": "tdg-2", "Status": "CREATION_FAILED"},
            },
        )
        finding = ACGRTrafficDistributionGroupStatusCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "not in active status" in finding.description.lower()
        assert "dr-tdg" in finding.description
        assert "creation_failed" in finding.description.lower()


# ---------------------------------------------------------------------------
# res-acgr-traffic-dist-001 — Active-active traffic distribution
# ---------------------------------------------------------------------------


class TestACGRTrafficDistributionCheck:
    def test_no_tdg_is_not_applicable(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(mock_aws_client_factory, tdgs=[])
        finding = ACGRTrafficDistributionCheck().execute(make_check_context())
        assert finding.status == CheckStatus.NOT_APPLICABLE

    def test_100_0_split_fails(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
            traffic_distributions={
                "tdg-1": {
                    "TelephonyConfig": {
                        "Distributions": [
                            {"Region": "us-east-1", "Percentage": 100},
                            {"Region": "us-west-2", "Percentage": 0},
                        ],
                    },
                }
            },
        )
        finding = ACGRTrafficDistributionCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "100%" in finding.description or "single region" in finding.description.lower()

    def test_active_active_passes(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
            traffic_distributions={
                "tdg-1": {
                    "TelephonyConfig": {
                        "Distributions": [
                            {"Region": "us-east-1", "Percentage": 80},
                            {"Region": "us-west-2", "Percentage": 20},
                        ],
                    },
                }
            },
        )
        finding = ACGRTrafficDistributionCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS

    def test_single_region_distribution_fails(self, make_check_context, mock_aws_client_factory):
        # Only one region in the distribution list means no second region
        # is participating — treat the same as a 100/0.
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
            traffic_distributions={
                "tdg-1": {
                    "TelephonyConfig": {
                        "Distributions": [
                            {"Region": "us-east-1", "Percentage": 100},
                        ],
                    },
                }
            },
        )
        finding = ACGRTrafficDistributionCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# res-acgr-failover-test-001 — Tested in the last 90 days
# ---------------------------------------------------------------------------


class TestACGRFailoverTestCheck:
    def test_no_tdg_is_not_applicable(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(mock_aws_client_factory, tdgs=[])
        finding = ACGRFailoverTestCheck().execute(make_check_context())
        assert finding.status == CheckStatus.NOT_APPLICABLE

    def test_recent_events_pass(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
            cloudtrail_events=[
                {"EventName": "UpdateTrafficDistribution", "EventTime": "2026-06-01T10:00:00Z"},
                {"EventName": "UpdateTrafficDistribution", "EventTime": "2026-05-15T10:00:00Z"},
            ],
        )
        finding = ACGRFailoverTestCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["update_traffic_distribution_event_count"] == 2

    def test_no_recent_events_fails(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
            cloudtrail_events=[],
        )
        finding = ACGRFailoverTestCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert (
            "not been tested" in finding.description.lower()
            or "no updatetrafficdistribution" in finding.description.lower()
        )

    def test_cloudtrail_denied_skips(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": "arn:...:tdg/tdg-1"}],
            access_denied_on={"lookup_events"},
        )
        finding = ACGRFailoverTestCheck().execute(make_check_context())
        assert finding.status == CheckStatus.SKIPPED
        assert "cloudtrail:LookupEvents" in finding.evidence.get("required_permission", "")


# ---------------------------------------------------------------------------
# res-acgr-numbers-001 — Phone numbers claimed against TDG
# ---------------------------------------------------------------------------


class TestACGRPhoneNumberBindingCheck:
    def test_no_tdg_is_not_applicable(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        _program_acgr_apis(mock_aws_client_factory, tdgs=[])
        finding = ACGRPhoneNumberBindingCheck().execute(make_check_context())
        assert finding.status == CheckStatus.NOT_APPLICABLE

    def test_zero_numbers_on_tdg_fails(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        tdg_arn = "arn:aws:connect:us-east-1:1:traffic-distribution-group/tdg-1"
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": tdg_arn}],
            tdg_phone_numbers={tdg_arn: []},
            instance_phone_numbers=[{"PhoneNumber": "+18005551234"}],
        )
        finding = ACGRPhoneNumberBindingCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "no phone numbers are claimed" in finding.description.lower()

    def test_paginates_beyond_first_page_of_numbers(
        self, make_check_context, mock_aws_client_factory
    ):
        # Regression test: list_phone_numbers_v2 used to be called once
        # with MaxResults=50 and no NextToken handling, so a TDG or
        # instance with more than 50 claimed numbers would silently
        # undercount (or a 51st+ number bound to the instance would go
        # unnoticed). Program two pages per TargetArn and confirm both
        # are combined into the final evidence counts.
        _wire(mock_aws_client_factory)
        tdg_arn = "arn:aws:connect:us-east-1:1:traffic-distribution-group/tdg-1"
        instance_arn = "arn:aws:connect:us-east-1:1:instance/inst-1"

        def _side_effect(client, op_name, service, **kwargs):
            if op_name == "list_traffic_distribution_groups":
                return {
                    "TrafficDistributionGroupSummaryList": [
                        {"Id": "tdg-1", "Name": "prod-tdg", "Arn": tdg_arn}
                    ]
                }
            if op_name == "list_phone_numbers_v2":
                target = kwargs.get("TargetArn")
                token = kwargs.get("NextToken")
                if target == tdg_arn:
                    if token is None:
                        return {
                            "ListPhoneNumbersSummaryList": [{"PhoneNumber": "+1000000001"}],
                            "NextToken": "tdg-page-2",
                        }
                    return {"ListPhoneNumbersSummaryList": [{"PhoneNumber": "+1000000002"}]}
                if target == instance_arn:
                    return {"ListPhoneNumbersSummaryList": []}
            return {}

        mock_aws_client_factory.call_api_with_resilience.side_effect = _side_effect
        context = make_check_context()
        context.instance.instance_arn = instance_arn

        finding = ACGRPhoneNumberBindingCheck().execute(context)
        assert finding.evidence["numbers_on_tdgs"]["prod-tdg"] == 2
        assert finding.evidence["total_numbers_on_tdgs"] == 2
        assert finding.status == CheckStatus.PASS

    def test_some_numbers_on_instance_fails(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        tdg_arn = "arn:aws:connect:us-east-1:1:traffic-distribution-group/tdg-1"
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": tdg_arn}],
            tdg_phone_numbers={tdg_arn: [{"PhoneNumber": "+18005551234"}]},
            instance_phone_numbers=[
                {"PhoneNumber": "+18005555678"},
                {"PhoneNumber": "+18005559999"},
            ],
        )
        finding = ACGRPhoneNumberBindingCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "directly against the instance" in finding.description.lower()
        assert finding.evidence["numbers_directly_on_instance"] == 2
        assert finding.evidence["total_numbers_on_tdgs"] == 1

    def test_all_numbers_on_tdg_passes(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        tdg_arn = "arn:aws:connect:us-east-1:1:traffic-distribution-group/tdg-1"
        _program_acgr_apis(
            mock_aws_client_factory,
            tdgs=[{"Id": "tdg-1", "Name": "prod-tdg", "Arn": tdg_arn}],
            tdg_phone_numbers={
                tdg_arn: [
                    {"PhoneNumber": "+18005551234"},
                    {"PhoneNumber": "+18005555678"},
                ]
            },
            instance_phone_numbers=[],
        )
        finding = ACGRPhoneNumberBindingCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# CloudWatch alarm coverage (res-cloudwatch-001) — unchanged
# ---------------------------------------------------------------------------


class TestCloudWatchAlarmMonitoringCheck:
    def test_no_alarms_fails(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        mock_aws_client_factory.describe_alarms_resilient.return_value = {"MetricAlarms": []}
        finding = CloudWatchAlarmMonitoringCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL

    def test_partial_coverage_fails(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        mock_aws_client_factory.describe_alarms_resilient.return_value = {
            "MetricAlarms": [
                {"Namespace": "AWS/Connect", "MetricName": "ConcurrentCalls"},
            ]
        }
        finding = CloudWatchAlarmMonitoringCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "missing" in finding.description.lower()

    def test_full_coverage_passes(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        alarms = [
            {"Namespace": "AWS/Connect", "MetricName": m}
            for m in (
                "ConcurrentCalls",
                "ConcurrentCallsPercentage",
                "ThrottledCalls",
                "MissedCalls",
                "CallsPerInterval",
            )
        ]
        mock_aws_client_factory.describe_alarms_resilient.return_value = {"MetricAlarms": alarms}
        finding = CloudWatchAlarmMonitoringCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# Carrier diversity (res-carrier-diversity-001)
# ---------------------------------------------------------------------------


class TestCarrierDiversityCheck:
    def test_single_country_is_not_applicable(self, make_check_context, mock_aws_client_factory):
        # Arrange
        _wire(mock_aws_client_factory)
        mock_aws_client_factory.call_api_with_resilience.return_value = {
            "ListPhoneNumbersSummaryList": [
                {"PhoneNumberCountryCode": "US"},
                {"PhoneNumberCountryCode": "US"},
            ]
        }

        # Act
        finding = CarrierDiversityCheck().execute(make_check_context())

        # Assert
        assert finding.status == CheckStatus.NOT_APPLICABLE
        assert "nothing to fix" in finding.description
        assert "Global Resiliency" in finding.description

    def test_multi_country_passes(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        mock_aws_client_factory.call_api_with_resilience.return_value = {
            "ListPhoneNumbersSummaryList": [
                {"PhoneNumberCountryCode": "US"},
                {"PhoneNumberCountryCode": "GB"},
            ]
        }
        finding = CarrierDiversityCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS

    def test_no_numbers_passes(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        mock_aws_client_factory.call_api_with_resilience.return_value = {
            "ListPhoneNumbersSummaryList": []
        }
        finding = CarrierDiversityCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# Hardcoded routing (res-hardcoded-routing-001)
#
# Reviewer feedback: (1) AWS's built-in "Sample ..." flows ship with
# literal phone numbers by design and shouldn't be flagged as a customer
# defect; (2) hardcoding is a normal pattern in contact centers, so the
# check is now LOW severity with framing as an observation, not a defect
# to fix (status/threshold logic is unchanged).
# ---------------------------------------------------------------------------


class TestHardcodedRoutingCheck:
    def test_many_hardcoded_destinations_fails(self, make_check_context, sample_connect_instance):
        actions = [
            build_action(
                f"a{i}",
                "TransferContactToPhoneNumber",
                {"PhoneNumber": f"+1800555000{i}"},
            )
            for i in range(5)
        ]
        flow = build_contact_flow(actions)
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = HardcodedRoutingCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL
        assert "hardcoded" in finding.description.lower()
        # phone numbers are masked in evidence
        for d in finding.evidence.get("hardcoded_details", []):
            assert d["hardcoded_value"].startswith("***")

    def test_dynamic_references_pass(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "TransferContactToPhoneNumber",
                    {"PhoneNumber": "$.Attributes.Dest"},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = HardcodedRoutingCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS

    def test_few_hardcoded_is_acceptable(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "TransferContactToPhoneNumber",
                    {"PhoneNumber": "+18005551234"},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = HardcodedRoutingCheck().execute(make_check_context(instance=inst))
        # Threshold is >3; 1 hardcoded should pass.
        assert finding.status == CheckStatus.PASS

    def test_sample_flows_excluded_from_hardcoded_count(
        self, make_check_context, sample_connect_instance
    ):
        # A default "Sample ..." flow with 5 hardcoded numbers would trip
        # the >3 threshold on its own — but it's AWS's own demo content,
        # not something the customer authored, so it must not count.
        sample_actions = [
            build_action(
                f"s{i}",
                "TransferContactToPhoneNumber",
                {"PhoneNumber": f"+1800555000{i}"},
            )
            for i in range(5)
        ]
        sample_flow = build_contact_flow(sample_actions)
        customer_flow = build_contact_flow(
            [
                build_action(
                    "c1",
                    "TransferContactToPhoneNumber",
                    {"PhoneNumber": "+18005559999"},
                )
            ]
        )
        inst = _instance_with_flows(
            sample_connect_instance,
            [("Sample AB test", sample_flow), ("My Custom Flow", customer_flow)],
        )
        finding = HardcodedRoutingCheck().execute(make_check_context(instance=inst))
        # Only the 1 hardcoded destination in the customer flow counts;
        # the sample flow's 5 are excluded, so this stays under threshold.
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["flows_analyzed"] == 1
        assert finding.evidence["sample_flows_excluded"] == 1
        assert finding.evidence["hardcoded_count"] == 1

    def test_severity_is_low_not_medium(self):
        # Reviewer feedback: hardcoding is a normal, common pattern in
        # contact center flows, not a defect — downgraded from the
        # original MEDIUM to reflect that.
        assert HardcodedRoutingCheck().severity == Severity.LOW


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_register_advanced_resilience_checks():
    registry = CheckRegistry()
    register_advanced_resilience_checks(registry)
    ids = {c.check_id for c in registry.get_all_checks()}
    # The full ACGR set (six checks) plus the other advanced resilience checks.
    assert {
        "res-acgr-config-001",
        "res-acgr-identity-001",
        "res-acgr-tdg-status-001",
        "res-acgr-traffic-dist-001",
        "res-acgr-failover-test-001",
        "res-acgr-numbers-001",
        "res-cloudwatch-001",
        "res-carrier-diversity-001",
        "res-hardcoded-routing-001",
    } <= ids
    # Old id must be gone — the rename is deliberate.
    assert "res-global-001" not in ids


# ---------------------------------------------------------------------------
# Regression test: ACGR context cache race under the parallel engine.
#
# The original implementation inserted an empty _ACGRContext into the
# module-level cache under the lock, released the lock, and only then made
# the slow API calls to fill it in. A second thread for the SAME instance
# arriving in that window would find the still-empty context and conclude
# "ACGR not configured" even though real TDGs existed and the first
# thread's fetch just hadn't finished yet — a silent false negative on a
# real DR misconfiguration. It was also an unsynchronized read/write race
# on the dataclass fields.
#
# The fix gives each instance its own fetch lock: whichever thread wins
# holds it for the entire fetch, and any other thread for the same
# instance blocks until the fetch is complete, then gets the fully
# populated context. This test simulates two ACGR checks racing for the
# same instance_id by making the mocked API call block (via a
# threading.Event) until both threads have had a chance to reach
# _get_acgr_context, so a broken implementation would very likely
# demonstrate the race; the fixed implementation must not.
# ---------------------------------------------------------------------------


def test_acgr_context_fetch_is_serialized_per_instance():
    import threading
    import time as time_module
    from unittest.mock import Mock

    from amazon_connect_assessment.checks.base import CheckContext
    from amazon_connect_assessment.checks.resilience_advanced_checks import (
        _get_acgr_context,
        _reset_acgr_cache,
    )
    from amazon_connect_assessment.models import ConnectInstance

    _reset_acgr_cache()

    instance = ConnectInstance(
        instance_id="race-instance",
        instance_arn="arn:aws:connect:us-east-1:111:instance/race-instance",
        identity_management_type="SAML",
        inbound_calls_enabled=True,
        outbound_calls_enabled=True,
        status="ACTIVE",
    )

    real_tdgs = [{"Id": "tdg-1", "Name": "Primary TDG"}]

    started_fetch = threading.Event()
    release_fetch = threading.Event()
    fetch_call_count = {"n": 0}

    def slow_list_tdgs(client, op_name, service, **kwargs):
        if op_name == "list_traffic_distribution_groups":
            fetch_call_count["n"] += 1
            started_fetch.set()
            # Simulate a slow API call — block until the test explicitly
            # releases it, giving a second thread time to arrive at
            # _get_acgr_context while the first fetch is still in flight.
            release_fetch.wait(timeout=5)
            return {"TrafficDistributionGroupSummaryList": real_tdgs}
        if op_name == "describe_traffic_distribution_group":
            return {"TrafficDistributionGroup": {"Status": "ACTIVE"}}
        if op_name == "get_traffic_distribution":
            return {}
        return {}

    factory = Mock()
    factory.get_connect_client.return_value = Mock()
    factory.call_api_with_resilience.side_effect = slow_list_tdgs
    factory.is_access_denied = AWSClientFactory.is_access_denied

    results = {}

    def worker(name):
        ctx = CheckContext(instance=instance, aws_client_factory=factory, config={}, logger=None)
        results[name] = _get_acgr_context(ctx)

    t1 = threading.Thread(target=worker, args=("t1",))
    t1.start()

    # Wait until thread 1 has actually entered the slow API call, then
    # start thread 2 — this is the exact window in which the old
    # implementation would have handed thread 2 an empty placeholder.
    assert started_fetch.wait(timeout=5), "thread 1 never reached the API call"

    t2 = threading.Thread(target=worker, args=("t2",))
    t2.start()

    # Give thread 2 a moment to reach _get_acgr_context and block on the
    # per-instance fetch lock (it should NOT proceed to make its own API
    # call while thread 1's fetch is in flight).
    time_module.sleep(0.2)
    assert fetch_call_count["n"] == 1, (
        "a second thread made its own list_traffic_distribution_groups "
        "call instead of waiting for the in-flight fetch — the "
        "per-instance fetch lock did not serialize correctly"
    )

    # Now let the first fetch complete; thread 2 should then get the
    # fully-populated result from the cache rather than fetching again.
    release_fetch.set()
    t1.join(timeout=5)
    t2.join(timeout=5)

    assert not t1.is_alive() and not t2.is_alive()
    assert results["t1"].tdgs == real_tdgs
    assert results["t2"].tdgs == real_tdgs
    assert results["t1"].fetch_complete is True
    assert results["t2"].fetch_complete is True
    # The fetch should have happened exactly once — thread 2 reused the
    # completed context rather than re-fetching.
    assert fetch_call_count["n"] == 1


def test_acgr_context_different_instances_fetch_concurrently():
    """
    The per-instance lock must not serialize *different* instances —
    only concurrent checks against the *same* instance should block on
    each other.
    """
    import threading
    from unittest.mock import Mock

    from amazon_connect_assessment.checks.base import CheckContext
    from amazon_connect_assessment.checks.resilience_advanced_checks import (
        _get_acgr_context,
        _reset_acgr_cache,
    )
    from amazon_connect_assessment.models import ConnectInstance

    _reset_acgr_cache()

    def _instance(iid):
        return ConnectInstance(
            instance_id=iid,
            instance_arn=f"arn:aws:connect:us-east-1:111:instance/{iid}",
            identity_management_type="SAML",
            inbound_calls_enabled=True,
            outbound_calls_enabled=True,
            status="ACTIVE",
        )

    factory = Mock()
    factory.get_connect_client.return_value = Mock()
    factory.call_api_with_resilience.return_value = {"TrafficDistributionGroupSummaryList": []}
    factory.is_access_denied = AWSClientFactory.is_access_denied

    results = {}

    def worker(iid):
        ctx = CheckContext(
            instance=_instance(iid), aws_client_factory=factory, config={}, logger=None
        )
        results[iid] = _get_acgr_context(ctx)

    threads = [threading.Thread(target=worker, args=(f"iid-{i}",)) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert all(not t.is_alive() for t in threads)
    assert len(results) == 5
    for r in results.values():
        assert r.fetch_complete is True
