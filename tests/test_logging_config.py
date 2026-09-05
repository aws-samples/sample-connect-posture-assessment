"""
Coverage tests for logging_config.py (43% → target ~80%).
"""

import logging

from amazon_connect_assessment.logging_config import (
    ContextFilter,
    add_context_filter,
    configure_aws_logging,
    get_logger,
    set_log_level,
    setup_logging,
)


class TestSetupLogging:
    def test_standard_format(self):
        setup_logging(level="INFO", format_type="standard")

    def test_detailed_format(self):
        setup_logging(level="DEBUG", format_type="detailed")

    def test_json_format(self):
        setup_logging(level="WARNING", format_type="json")

    def test_with_log_file(self, tmp_path):
        log_file = str(tmp_path / "test.log")
        setup_logging(level="DEBUG", log_file=log_file)
        logger = get_logger("test.file")
        logger.info("test message")
        with open(log_file) as f:
            assert "test message" in f.read()

    def test_unknown_format_falls_back(self):
        # Should not raise, falls back to standard.
        setup_logging(format_type="unknown_format")


class TestGetLogger:
    def test_returns_logger(self):
        logger = get_logger("mytest")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "mytest"


class TestSetLogLevel:
    def test_set_debug(self):
        set_log_level("DEBUG")
        logger = logging.getLogger("assessment_engine")
        assert logger.level == logging.DEBUG

    def test_set_error(self):
        set_log_level("ERROR")
        logger = logging.getLogger("check_registry")
        assert logger.level == logging.ERROR

    def test_invalid_level_raises(self):
        import pytest

        with pytest.raises(ValueError):
            set_log_level("INVALID")


class TestConfigureAWSLogging:
    def test_sets_warning(self):
        configure_aws_logging("WARNING")
        assert logging.getLogger("boto3").level == logging.WARNING
        assert logging.getLogger("botocore").level == logging.WARNING

    def test_sets_error(self):
        configure_aws_logging("ERROR")
        assert logging.getLogger("urllib3").level == logging.ERROR


class TestContextFilter:
    def test_adds_context(self):
        f = ContextFilter(assessment_id="a-123", instance_id="i-456")
        record = logging.LogRecord("test", logging.INFO, "", 0, "msg", (), None)
        assert f.filter(record) is True
        assert record.assessment_id == "a-123"
        assert record.instance_id == "i-456"

    def test_no_context(self):
        f = ContextFilter()
        record = logging.LogRecord("test", logging.INFO, "", 0, "msg", (), None)
        assert f.filter(record) is True
        assert not hasattr(record, "assessment_id")


class TestAddContextFilter:
    def test_adds_filter_to_logger(self):
        logger = get_logger("context.test")
        add_context_filter(logger, assessment_id="a-789")
        assert len(logger.filters) >= 1
