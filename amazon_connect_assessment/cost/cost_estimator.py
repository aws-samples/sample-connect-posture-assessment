"""
Cost impact estimation module (Task 10 / Requirement 41).

Provides deterministic, pricing-constant-based estimates for cost findings.
All estimates are clearly labeled approximate and based on published AWS
pricing, never on actual invoices.

Pricing constants are centralized here so they evolve independently of check
logic and can be updated without touching check modules.
"""

from dataclasses import dataclass
from typing import Optional

# Published Connect pricing constants (approximate, USD).
# Source: https://aws.amazon.com/connect/pricing/
DID_DAILY_COST_US = 0.06  # US DID per day
DID_DAILY_COST_INTL = 0.10  # Generic international DID per day (varies by country)
TELEPHONY_PER_MINUTE = 0.018  # Inbound per-minute (US)
AGENT_HANDLED_COST_AVG = 6.0  # Industry average cost per agent-handled contact

DISCLAIMER = "Estimate based on published AWS pricing and detected metrics, not actual invoices."


@dataclass
class CostImpactEstimate:
    """Estimated dollar-cost impact for a finding."""

    monthly_estimate_usd: Optional[float] = None
    calculation_basis: str = ""
    confidence: str = "approximate"  # "approximate" | "unable_to_calculate"
    disclaimer: str = DISCLAIMER


def estimate_unused_numbers_cost(
    unused_count: int,
    country_code: str = "US",
) -> CostImpactEstimate:
    """Estimate monthly cost of unused phone numbers (Req 41.1)."""
    daily = DID_DAILY_COST_US if country_code == "US" else DID_DAILY_COST_INTL
    monthly = unused_count * daily * 30
    return CostImpactEstimate(
        monthly_estimate_usd=round(monthly, 2),
        calculation_basis=(f"{unused_count} unused DID(s) x ${daily}/day x 30 days"),
    )


def estimate_containment_savings(
    monthly_call_volume: int,
    containment_rate: float,
) -> CostImpactEstimate:
    """Estimate deflection savings from improved containment (Req 41.2)."""
    if monthly_call_volume <= 0:
        return CostImpactEstimate(
            confidence="unable_to_calculate",
            calculation_basis="Call volume metrics unavailable",
        )
    deflectable = int(monthly_call_volume * (1.0 - containment_rate))
    monthly = deflectable * AGENT_HANDLED_COST_AVG
    return CostImpactEstimate(
        monthly_estimate_usd=round(monthly, 2),
        calculation_basis=(
            f"{deflectable} deflectable calls x ${AGENT_HANDLED_COST_AVG} avg agent cost"
        ),
    )


def estimate_callback_savings(
    avg_hold_minutes: float,
    calls_per_month: int,
) -> CostImpactEstimate:
    """Estimate hold-time telephony savings from callbacks (Req 41.3)."""
    if calls_per_month <= 0 or avg_hold_minutes <= 0:
        return CostImpactEstimate(
            confidence="unable_to_calculate",
            calculation_basis="Hold-time or volume metrics unavailable",
        )
    monthly = calls_per_month * avg_hold_minutes * TELEPHONY_PER_MINUTE
    return CostImpactEstimate(
        monthly_estimate_usd=round(monthly, 2),
        calculation_basis=(
            f"{calls_per_month} calls x {avg_hold_minutes:.1f} min hold "
            f"x ${TELEPHONY_PER_MINUTE}/min"
        ),
    )
