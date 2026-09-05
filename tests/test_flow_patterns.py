"""
Tests for amazon_connect_assessment.parsers.flow_patterns.is_default_sample_flow.

Added in response to reviewer feedback that res-hardcoded-routing-001 and
sec-flow-auth-001 were flagging AWS's own built-in sample flows ("Sample
AB test", "Sample secure input with no agent", etc) as if they were
customer defects.
"""

from amazon_connect_assessment.models import ContactFlow
from amazon_connect_assessment.parsers.flow_patterns import is_default_sample_flow


def _flow(name):
    return ContactFlow(
        id="f1",
        arn="arn:...:flow/f1",
        name=name,
        type="CONTACT_FLOW",
        state="ACTIVE",
    )


class TestIsDefaultSampleFlow:
    def test_matches_real_aws_sample_flow_names(self):
        # Names taken verbatim from
        # https://docs.aws.amazon.com/connect/latest/adminguide/contact-flow-samples.html
        real_sample_names = [
            "Sample inbound flow (first contact experience)",
            "Sample AB test",
            "Sample recording behavior",
            "Sample Lambda integration",
            "Sample secure input with no agent",
            "Sample queued callback",
        ]
        for name in real_sample_names:
            assert is_default_sample_flow(_flow(name)), name

    def test_customer_flow_names_do_not_match(self):
        customer_names = [
            "EmployeeBooking_Authentication",
            "PDNYC Customer disconnect flow v1",
            "My Support Flow",
            "Main IVR",
        ]
        for name in customer_names:
            assert not is_default_sample_flow(_flow(name)), name

    def test_case_insensitive(self):
        assert is_default_sample_flow(_flow("SAMPLE inbound flow"))
        assert is_default_sample_flow(_flow("sample ab test"))

    def test_leading_whitespace_tolerated(self):
        assert is_default_sample_flow(_flow("  Sample AB test"))

    def test_none_or_empty_name_does_not_match(self):
        assert not is_default_sample_flow(_flow(None))
        assert not is_default_sample_flow(_flow(""))

    def test_word_containing_sample_but_not_prefix_does_not_match(self):
        # Only a name that *starts with* "Sample " should match -- a
        # customer flow that happens to mention "sample" elsewhere in its
        # name should not be excluded.
        assert not is_default_sample_flow(_flow("Customer Sample Survey Flow"))
