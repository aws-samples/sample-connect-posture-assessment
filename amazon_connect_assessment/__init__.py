"""
Amazon Connect Assessment Tool

A Python application that evaluates AWS Connect deployments against
AWS Well-Architected Framework best practices for Resilience, Security,
and Cost Optimization.
"""

__version__ = "0.1.0"
__author__ = "Amazon Connect Assessment Team"

from .analyzers import BaseAnalyzer
from .checks import BaseCheck
from .engine import AssessmentEngine
from .models import AssessmentResult, ConnectInstance, Finding


def __getattr__(name):
    if name == "ReportGenerator":
        from .report_generator import ReportGenerator

        return ReportGenerator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AssessmentResult",
    "Finding",
    "ConnectInstance",
    "AssessmentEngine",
    "BaseCheck",
    "BaseAnalyzer",
    "ReportGenerator",
]
