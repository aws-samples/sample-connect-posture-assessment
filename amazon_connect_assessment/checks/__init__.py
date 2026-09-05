"""
Check framework for Amazon Connect assessments.

This module provides the base interfaces and registry system for implementing
assessment checks across different AWS Well-Architected Framework pillars.
"""

# Import all check modules. The original resilience_checks module (Multi-AZ,
# DR, and Failover checks) was removed after user feedback — those checks
# fired on trivially-true conditions rather than detecting real problems.
from . import cost_optimization_checks, mvp_checks, security_checks
from .base import BaseCheck, CheckContext
from .config import AssessmentConfig, CheckConfig, CheckConfigurationManager
from .registry import CheckRegistry

__all__ = [
    "BaseCheck",
    "CheckContext",
    "CheckRegistry",
    "CheckConfig",
    "AssessmentConfig",
    "CheckConfigurationManager",
    "security_checks",
    "cost_optimization_checks",
    "mvp_checks",
]
