"""
Verification Agent — Historical Attack Consistency Validator

Sits inside the classification pipeline between ML prediction and Kibana push.
When the ML model flags an attack it verifies whether the source IP is historically
consistent with the predicted attack type by querying confirmed_attack_history.

Score formula (classification_agent.md §10):
    score = 0.4 * ip_history_score
          + 0.4 * same_attack_type_score
          + 0.2 * recent_recurrence_score

Verdict:
    score > 0.80  →  Confirmed Historically Consistent Attack
    score ≥ 0.50  →  Suspicious Attack with Partial History
    score < 0.50  →  Newly Observed Attack / Low Historical Evidence

Severity and recommended-action adjustments:
    Confirmed   → severity=high,   keep original actions
    Suspicious  → severity=medium, downgrade block_immediately → rate_limit
    Low evidence→ severity=low,    actions reduced to monitor + log

Usage (chained with MitigationAgent):
    verification_agent = VerificationAgent(kibana_adapter)
    mitigation_agent   = MitigationAgent()

    classification_agent = DetectionClassificationAgent(
        ...,
        verification_agent=verification_agent,
        on_attack=mitigation_agent.mitigate,
    )
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional

try:
    from src.shared.schemas import ClassificationResult
    from src.agents.classification_agent.kibana_adapter import KibanaAdapterBase
except ModuleNotFoundError:
    from shared.schemas import ClassificationResult
    from agents.classification_agent.kibana_adapter import KibanaAdapterBase

logger = logging.getLogger(__name__)

# Saturation thresholds — values at which each sub-score reaches 1.0
_IP_HISTORY_SAT = 10   # 10+ confirmed attacks from this IP
_SAME_TYPE_SAT  = 5    # 5+ attacks of the same predicted type
_RECENT_SAT     = 3    # 3+ attacks in the past 7 days


def _norm(value: int, saturation: int) -> float:
    return min(value / saturation, 1.0) if saturation > 0 else 0.0


def _verdict(score: float) -> str:
    if score > 0.80:
        return "Confirmed Historically Consistent Attack"
    if score >= 0.50:
        return "Suspicious Attack with Partial History"
    return "Newly Observed Attack / Low Historical Evidence"


class VerificationAgent:
    """
    Enriches a ClassificationResult with historical IP reputation data and
    adjusts severity / recommended actions to reflect the evidence strength.
    """

    def __init__(self, kibana: KibanaAdapterBase):
        self.kibana = kibana

    # ------------------------------------------------------------------
    # Core verification
    # ------------------------------------------------------------------

    def verify(self, result: ClassificationResult) -> ClassificationResult:
        """
        Query Elasticsearch history for the predicted attacker IP, compute a
        verification score, and enrich the result in-place.  Returns the same
        object so callers can chain: result = agent.verify(result).
        """
        if not result.is_attack:
            return result

        ip          = result.src_ip
        attack_type = result.attack_type

        # ---- gather evidence from confirmed_attack_history ----
        history         = self.kibana.get_ip_history(ip)
        same_type_count = self.kibana.get_same_attack_type_count(ip, attack_type, days=30)
        recent_count    = self.kibana.count_recent_ip_attacks(ip, days=7)

        # ---- score components ----
        ip_history_score        = _norm(history["previous_attack_count"], _IP_HISTORY_SAT)
        same_attack_type_score  = _norm(same_type_count,                  _SAME_TYPE_SAT)
        recent_recurrence_score = _norm(recent_count,                     _RECENT_SAT)

        score = round(
            0.4 * ip_history_score
            + 0.4 * same_attack_type_score
            + 0.2 * recent_recurrence_score,
            4,
        )
        verdict = _verdict(score)

        breakdown: dict[str, Any] = {
            "ip_history_score":         round(ip_history_score, 4),
            "same_attack_type_score":   round(same_attack_type_score, 4),
            "recent_recurrence_score":  round(recent_recurrence_score, 4),
            "previous_attack_count":    history["previous_attack_count"],
            "same_type_count":          same_type_count,
            "recent_count":             recent_count,
            "first_seen":               history["first_seen"],
            "last_seen":                history["last_seen"],
            "known_attack_types":       history["attack_types"],
        }

        # ---- severity ----
        if score > 0.80:
            result.severity = "high"
        elif score >= 0.50:
            result.severity = "medium"
        else:
            result.severity = "low"

        # ---- gate recommended actions ----
        if score < 0.50:
            # No supporting history — observe only, do not block
            result.recommended_actions = ["monitor_closely", "log_for_investigation"]
        elif score < 0.80 and "block_immediately" in result.recommended_actions:
            # Partial evidence — downgrade block to rate-limit
            result.recommended_actions = [
                "rate_limit" if a == "block_immediately" else a
                for a in result.recommended_actions
            ]
        # score > 0.80 → keep original actions from ReasoningEngine

        # ---- extend reasoning text ----
        result.reasoning += (
            f" | Verification [{verdict}]: score={score:.2f}, "
            f"{history['previous_attack_count']} historical attacks on this IP"
            + (f", {same_type_count} matching {attack_type}" if same_type_count else "")
            + (f", {recent_count} in last 7 d" if recent_count else "")
            + "."
        )

        # ---- stamp result fields ----
        result.verification_score   = score
        result.verification_verdict = verdict
        result.metadata["verification"] = {"score": score, "verdict": verdict, "breakdown": breakdown}

        logger.info(
            "[VerificationAgent] ip=%-15s type=%-14s score=%.3f  %s",
            ip, attack_type, score, verdict,
        )
        return result

    # ------------------------------------------------------------------
    # Chaining helper
    # ------------------------------------------------------------------

    def verify_then(
        self, callback: Callable[[ClassificationResult], None]
    ) -> Callable[[ClassificationResult], None]:
        """
        Returns a single callable that runs verify() and then passes the
        enriched result to `callback`.  Use as the on_attack argument when
        you want verification to gate mitigation decisions:

            on_attack=verification_agent.verify_then(mitigation_agent.mitigate)

        Note: this is only needed when VerificationAgent is NOT injected
        directly into DetectionClassificationAgent (i.e. no verification_agent=
        constructor arg).  When it IS injected, verification runs before the
        Kibana push, which is the preferred approach.
        """
        def _chain(result: ClassificationResult) -> None:
            callback(self.verify(result))

        return _chain
