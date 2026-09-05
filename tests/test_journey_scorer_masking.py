"""Tests for phone-number masking in journey finding evidence."""

from amazon_connect_assessment.journey.journey_scorer import _mask_number


class TestMaskNumber:
    def test_masks_e164_number_keeping_last_four(self):
        assert _mask_number("+18005551212") == "***-***-1212"

    def test_masks_formatted_number_keeping_last_four(self):
        assert _mask_number("(800) 555-6789") == "***-***-6789"

    def test_short_number_is_fully_masked(self):
        assert _mask_number("911") == "***"

    def test_empty_string_returned_unchanged(self):
        assert _mask_number("") == ""

    def test_full_number_is_never_present_in_output(self):
        number = "+441632960123"
        masked = _mask_number(number)
        assert number not in masked
        assert masked.endswith("0123")
