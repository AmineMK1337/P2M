"""
ANDS — MitigationAgent (Deterministic Executor)

Receives a ClassificationResult from the ClassificationAgent and applies
the appropriate automated response by invoking mitigation tools directly
in the order defined by strategy_map.py.

No LLM is required in the hot path. Every execution is deterministic:
the same attack type and confidence always produce the same tool sequence.

Usage
-----
Callback mode (real-time):

    from src.agents.mitigation_agent.agent import MitigationAgent

    mitigation_agent = MitigationAgent()
    classification_agent = DetectionClassificationAgent(
        ...,
        on_attack=mitigation_agent.mitigate,
    )
    classification_agent.run(input_config)

Batch mode:

    results = classification_agent.run(input_config)
    mitigation_agent.run_batch(results)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional


try:
    from src.shared.schemas import ClassificationResult
    from src.agents.mitigation_agent.strategy_map import get_strategies
    from src.agents.mitigation_agent.tools import (
        alert_soc,
        block_ip,
        clear_action_log,
        get_action_log,
        isolate_host,
        null_route_ip,
        quarantine_host,
        rate_limit_ip,
        throttle_connections,
    )
except ModuleNotFoundError:
    from shared.schemas import ClassificationResult
    from agents.mitigation_agent.strategy_map import get_strategies
    from agents.mitigation_agent.tools import (
        alert_soc,
        block_ip,
        clear_action_log,
        get_action_log,
        isolate_host,
        null_route_ip,
        quarantine_host,
        rate_limit_ip,
        throttle_connections,
    )

logger = logging.getLogger(__name__)

_ALL_TOOLS = [
    block_ip,
    rate_limit_ip,
    null_route_ip,
    throttle_connections,
    quarantine_host,
    isolate_host,
    alert_soc,
]

_TOOL_REGISTRY = {t.name: t for t in _ALL_TOOLS}


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------

@dataclass
class MitigationResult:
    """
    Output produced by the MitigationAgent for a single ClassificationResult.
    """
    src_ip:               str
    attack_type:          str
    confidence:           float
    severity:             str
    strategies_attempted: list[str]
    actions_taken:        list[str]
    success:              bool
    agent_response:       str
    timestamp:            str  = field(default_factory=lambda: datetime.utcnow().isoformat())
    notes:                str  = ""

    def summary(self) -> str:
        status = "✓ MITIGATED" if self.success else "✗ FAILED"
        return "\n".join([
            "=" * 55,
            "  MitigationAgent — Result",
            "=" * 55,
            f"  Status        : {status}",
            f"  Source IP     : {self.src_ip}",
            f"  Attack type   : {self.attack_type}",
            f"  Confidence    : {self.confidence:.3f}",
            f"  Severity      : {self.severity}",
            f"  Strategies    : {', '.join(self.strategies_attempted) or 'none'}",
            f"  Actions taken : {len(self.actions_taken)}",
            "=" * 55,
        ])


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class MitigationAgent:
    """
    Automated response agent for the ANDS pipeline.

    For each confirmed attack it:
    1. Selects the mitigation strategy from strategy_map.py.
    2. Invokes each tool directly in order (deterministic — no LLM).
    3. Calls alert_soc unconditionally as the final step.
    4. Mutates the incoming ClassificationResult in-place:
           classification.mitigated          → bool
           classification.mitigation_status  → "mitigated" | "failed" | "skipped"
           classification.mitigation_actions → list[str]
    5. Calls on_mitigated callback if provided.
    """

    def __init__(
        self,
        on_mitigated: Optional[Callable[[MitigationResult], None]] = None,
    ):
        self.on_mitigated = on_mitigated

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def mitigate(self, classification: ClassificationResult) -> MitigationResult:
        """
        Process a single ClassificationResult.
        Pass this method directly as on_attack= to the ClassificationAgent.
        """
        if not classification.is_attack:
            logger.info(
                "[MitigationAgent] Skipping BENIGN flow from %s", classification.src_ip
            )
            return self._build_result(
                classification,
                strategies=[],
                actions=[],
                success=True,
                agent_response="Flow is BENIGN — no action required.",
                notes="skipped",
            )

        attack_type = classification.mitigation_attack_type
        strategies  = get_strategies(attack_type, classification.confidence)

        if not strategies:
            logger.warning(
                "[MitigationAgent] No strategy defined for '%s', defaulting to alert_soc.",
                attack_type,
            )
            strategies = ["alert_soc"]

        logger.warning(
            "[MitigationAgent] Starting mitigation  attack=%s  ip=%s  confidence=%.3f  plan=%s",
            attack_type, classification.src_ip, classification.confidence, strategies,
        )

        clear_action_log()
        agent_response = self._run_deterministic(classification, strategies)
        actions        = [
            f"{e['tool']}({e['ip']}) — {e['detail']}"
            for e in get_action_log()
        ]
        success = bool(actions)

        result = self._build_result(
            classification,
            strategies=strategies,
            actions=actions,
            success=success,
            agent_response=agent_response,
        )

        # Mutate ClassificationResult so Kibana / downstream agents see full state
        classification.mitigation_actions  = actions
        classification.mitigated           = success
        classification.mitigation_status   = "mitigated" if success else "failed"

        self._log(result)

        if self.on_mitigated:
            self.on_mitigated(result)

        return result

    def run_batch(
        self, classifications: list[ClassificationResult]
    ) -> list[MitigationResult]:
        """
        Process a list of ClassificationResults.
        Benign flows are skipped automatically.
        """
        attacks = [c for c in classifications if c.is_attack]
        logger.info(
            "[MitigationAgent] Batch: %d total flows, %d to mitigate",
            len(classifications), len(attacks),
        )
        results = [self.mitigate(c) for c in classifications]
        self._print_summary(results)
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_deterministic(
        self,
        classification: ClassificationResult,
        strategies: list[str],
    ) -> str:
        """
        Execute mitigation tools in order without an LLM.
        alert_soc is always invoked last to guarantee an audit trail.
        Tool failures are caught, logged, and included in the SOC message.
        """
        ip  = classification.src_ip
        sev = classification.severity
        executed: list[str] = []
        failed:   list[str] = []

        for tool_name in strategies:
            if tool_name == "alert_soc":
                continue  # called explicitly at the end
            tool = _TOOL_REGISTRY.get(tool_name)
            if tool is None:
                logger.warning("[MitigationAgent] Unknown tool '%s' — skipping.", tool_name)
                failed.append(f"unknown_tool({tool_name})")
                continue
            try:
                out = tool.invoke({"ip_address": ip})
                executed.append(f"{tool_name}: {out}")
                logger.info("[MitigationAgent] %s OK — %s", tool_name, out)
            except Exception as exc:
                logger.error("[MitigationAgent] %s FAILED — %s", tool_name, exc)
                failed.append(f"{tool_name}: {exc}")

        summary = (
            f"Deterministic mitigation for {ip} "
            f"({classification.mitigation_attack_type}, conf={classification.confidence:.2f}). "
            f"Executed={executed or 'none'}. "
            f"Failed={failed or 'none'}."
        )
        alert_soc.invoke({"message": summary, "severity": sev})
        return summary

    @staticmethod
    def _build_result(
        classification: ClassificationResult,
        strategies: list[str],
        actions: list[str],
        success: bool,
        agent_response: str,
        notes: str = "",
    ) -> MitigationResult:
        return MitigationResult(
            src_ip               = classification.src_ip,
            attack_type          = classification.mitigation_attack_type,
            confidence           = classification.confidence,
            severity             = classification.severity,
            strategies_attempted = strategies,
            actions_taken        = actions,
            success              = success,
            agent_response       = agent_response,
            notes                = notes,
        )

    @staticmethod
    def _log(result: MitigationResult) -> None:
        if result.success:
            logger.warning(
                "[MitigationAgent] MITIGATED  attack=%s  ip=%s  actions=%d",
                result.attack_type, result.src_ip, len(result.actions_taken),
            )
        else:
            logger.error(
                "[MitigationAgent] MITIGATION FAILED  attack=%s  ip=%s",
                result.attack_type, result.src_ip,
            )

    @staticmethod
    def _print_summary(results: list[MitigationResult]) -> None:
        mitigated = [r for r in results if r.success     and r.notes != "skipped"]
        failed    = [r for r in results if not r.success]
        skipped   = [r for r in results if r.notes == "skipped"]
        print("\n" + "=" * 55)
        print("  MitigationAgent — Batch Summary")
        print("=" * 55)
        print(f"  Total processed : {len(results)}")
        print(f"  Mitigated       : {len(mitigated)}")
        print(f"  Failed          : {len(failed)}")
        print(f"  Skipped (benign): {len(skipped)}")
        print("=" * 55 + "\n")