"""
Logging configuration for the Amazon Connect Assessment Tool.

Provides configurable logging setup with different verbosity levels
and output formats for various execution environments.
"""

import logging
import logging.config
import sys
from typing import Optional


def setup_logging(
    level: str = "INFO",
    format_type: str = "standard",
    log_file: Optional[str] = None,
    disable_existing_loggers: bool = False,
) -> None:
    """
    Configure logging for the assessment tool.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_type: Format type ('standard', 'detailed', 'json')
        log_file: Optional file path for log output
        disable_existing_loggers: Whether to disable existing loggers
    """
    # Define log formats
    formats = {
        "standard": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        "detailed": "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(funcName)s - %(message)s",
        "json": '{"timestamp": "%(asctime)s", "logger": "%(name)s", "level": "%(levelname)s", "message": "%(message)s", "module": "%(filename)s", "line": %(lineno)d}',
    }

    # Get the appropriate format
    log_format = formats.get(format_type, formats["standard"])

    # Configure handlers
    handlers = ["console"]
    handler_config = {
        "console": {
            "class": "logging.StreamHandler",
            "level": level,
            "formatter": "standard",
            "stream": sys.stdout,
        }
    }

    # Add file handler if specified
    if log_file:
        handlers.append("file")
        handler_config["file"] = {
            "class": "logging.FileHandler",
            "level": level,
            "formatter": "standard",
            "filename": log_file,
            "mode": "a",
        }

    # Logging configuration
    config = {
        "version": 1,
        "disable_existing_loggers": disable_existing_loggers,
        "formatters": {"standard": {"format": log_format, "datefmt": "%Y-%m-%d %H:%M:%S"}},
        "handlers": handler_config,
        "loggers": {
            "amazon_connect_assessment": {
                "level": level,
                "handlers": handlers,
                "propagate": False,
            },
            "assessment_engine": {
                "level": level,
                "handlers": handlers,
                "propagate": False,
            },
            "check_registry": {
                "level": level,
                "handlers": handlers,
                "propagate": False,
            },
            "analyzer": {"level": level, "handlers": handlers, "propagate": False},
            "check": {"level": level, "handlers": handlers, "propagate": False},
        },
        "root": {"level": level, "handlers": handlers},
    }

    # Apply configuration
    logging.config.dictConfig(config)


def get_logger(name: str) -> logging.Logger:
    """
    Get a configured logger instance.

    Args:
        name: Logger name

    Returns:
        logging.Logger: Configured logger instance
    """
    return logging.getLogger(name)


def set_log_level(level: str) -> None:
    """
    Change the log level for all assessment tool loggers.

    Args:
        level: New logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {level}")

    # Update all assessment tool loggers
    logger_names = [
        "amazon_connect_assessment",
        "assessment_engine",
        "check_registry",
        "analyzer",
        "check",
    ]

    for logger_name in logger_names:
        logger = logging.getLogger(logger_name)
        logger.setLevel(numeric_level)

        # Update handler levels too
        for handler in logger.handlers:
            handler.setLevel(numeric_level)


def configure_aws_logging(level: str = "WARNING") -> None:
    """
    Configure AWS SDK logging to reduce noise.

    Args:
        level: Logging level for AWS SDK loggers
    """
    aws_loggers = ["boto3", "botocore", "urllib3", "s3transfer"]

    for logger_name in aws_loggers:
        logger = logging.getLogger(logger_name)
        logger.setLevel(getattr(logging, level.upper()))


class ContextFilter(logging.Filter):
    """
    Custom logging filter to add assessment context to log records.

    Adds assessment_id and instance_id to log records when available.
    """

    def __init__(self, assessment_id: str = None, instance_id: str = None):
        """
        Initialize the context filter.

        Args:
            assessment_id: Optional assessment ID to add to records
            instance_id: Optional instance ID to add to records
        """
        super().__init__()
        self.assessment_id = assessment_id
        self.instance_id = instance_id

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Add context information to the log record.

        Args:
            record: Log record to modify

        Returns:
            bool: Always True to allow the record through
        """
        if self.assessment_id:
            record.assessment_id = self.assessment_id
        if self.instance_id:
            record.instance_id = self.instance_id
        return True


def add_context_filter(
    logger: logging.Logger, assessment_id: str = None, instance_id: str = None
) -> None:
    """
    Add context filter to a logger.

    Args:
        logger: Logger to add filter to
        assessment_id: Optional assessment ID
        instance_id: Optional instance ID
    """
    context_filter = ContextFilter(assessment_id, instance_id)
    logger.addFilter(context_filter)


# Default logging setup for module import
setup_logging()
