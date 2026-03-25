"""
ANDS — MitigationAgent

Receives a ClassificationResult from the ClassificationAgent and applies
the appropriate automated response via a LangGraph ReAct agent.

Usage
-----
Callback mode (real-time, fires on every attack the ClassificationAgent detects):

    from src.agents.mitigation_agent.agent import MitigationAgent

    mitigation_agent = MitigationAgent()

    classification_agent = DetectionClassificationAgent(
        ...,
        on_attack=mitigation_agent.mitigate,   # wire here
    )
    classification_agent.run(input_config)

Batch mode (offline analysis):

    results = classification_agent.run(input_config)
    mitigation_agent.run_batch(results)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from langchain_ollama import ChatOllama
from langgraph.prebuilt import create_react_agent

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
    2. Builds a LangGraph ReAct agent with only the relevant tools.
    3. Runs the agent and collects actions from the audit log.
    4. Mutates the incoming ClassificationResult in-place so the rest
       of the pipeline always has a unified state object:
           classification.mitigated          → bool
           classification.mitigation_status  → "mitigated" | "failed" | "skipped"
           classification.mitigation_actions → list[str]
    5. Calls on_mitigated callback if provided.
    """

    def __init__(
        self,
        model_name: str = "llama3",
        on_mitigated: Optional[Callable[[MitigationResult], None]] = None,
    ):
        self.model_name   = model_name
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
        agent_response = self._run_react_agent(classification, strategies)
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

    def _run_react_agent(
        self,
        classification: ClassificationResult,
        strategies: list[str],
    ) -> str:
        # Only expose tools relevant to this attack to keep the agent focused
        active_tools = [
            _TOOL_REGISTRY[name]
            for name in strategies
            if name in _TOOL_REGISTRY
        ] or [alert_soc]

        llm   = ChatOllama(model=self.model_name)
        agent = create_react_agent(llm, active_tools)

        try:
            response = agent.invoke(
                {"messages": [("user", self._build_prompt(classification, strategies))]}
            )
            messages = response.get("messages", [])
            for msg in reversed(messages):
                if hasattr(msg, "content") and isinstance(msg.content, str):
                    return msg.content
            return "Agent completed with no text response."

        except Exception as exc:
            logger.error("[MitigationAgent] ReAct agent error: %s", exc)
            # Guarantee the event is never silently dropped
            alert_soc.invoke({
                "message": (
                    f"MitigationAgent error for {classification.src_ip} "
                    f"({classification.attack_type}): {exc}"
                ),
                "severity": "high",
            })
            return f"Agent error — fallback SOC alert sent. Error: {exc}"

    @staticmethod
    def _build_prompt(
        classification: ClassificationResult,
        strategies: list[str],
    ) -> str:
        return f"""You are the MitigationAgent of the Adaptive Network Defense System (ANDS).
The ClassificationAgent has confirmed a network attack. Your job is to neutralise it
using the tools available to you.

== Attack Details ==
Source IP       : {classification.src_ip}
Attack type     : {classification.mitigation_attack_type}
Confidence      : {classification.confidence:.3f}
Severity        : {classification.severity}
Decision source : {classification.decision_source}
Anomaly score   : {classification.metadata.get('anomaly_score', 'N/A')}

== Recommended Strategy ==
Execute these tools in order: {strategies}

== Instructions ==
1. Apply each recommended tool against the source IP shown above.
2. After all countermeasures are applied, call alert_soc with a concise
   summary of the actions taken, using severity="{classification.severity}".
3. Act immediately — do not ask for confirmation.
4. If a tool fails, continue with the next one and note the failure in the SOC alert.
"""

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