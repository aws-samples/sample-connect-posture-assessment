"""
Analyzer framework for Amazon Connect component analysis.

This module provides base interfaces for analyzing different Amazon Connect
components and extracting configuration data for assessment.
"""

from .base import BaseAnalyzer
from .connect_instance_analyzer import ConnectInstanceAnalyzer
from .contact_flow_analyzer import ContactFlowAnalyzer
from .integration_analyzer import IntegrationAnalyzer
from .queue_analyzer import QueueAnalyzer
from .security_profile_analyzer import SecurityProfileAnalyzer

__all__ = [
    "BaseAnalyzer",
    "ConnectInstanceAnalyzer",
    "ContactFlowAnalyzer",
    "QueueAnalyzer",
    "SecurityProfileAnalyzer",
    "IntegrationAnalyzer",
]
