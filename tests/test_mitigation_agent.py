"""
Tests for the ANDS MitigationAgent — deterministic executor path.

Coverage:
- Strategy selection by attack type and confidence
- High-confidence override for DDoS
- Unknown attack type fallback
- Benign flow skipping
- Deterministic tool execution order
- ClassificationResult field mutation
- MitigationResult shape
- Block-IP idempotency
- Tool failure handling (loop continues, SOC alert still fires)
- End-to-end on_mitigated callback contract
- Batch run benign/attack counts
"""

from __future__ import annotations

import pytest

import src.agents.mitigation_agent.tools.tools as tools_module
from src.agents.mitigation_agent.agent import MitigationAgent, MitigationResult, _TOOL_REGISTRY
from src.agents.mitigation_agent.strategy_map import (
    HIGH_CONFIDENCE_THRESHOLD,
    get_strategies,
)
from src.shared.schemas import ClassificationResult, FlowRecord


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_classification(
    src_ip: str = "10.0.0.1",
    attack_type: str = "DDoS",
    confidence: float = 0.80,
    is_attack: bool = True,
) -> ClassificationResult:
    return ClassificationResult(
        flow=FlowRecord(features={"Src IP": src_ip}),
        is_attack=is_attack,
        attack_type=attack_type,
        confidence=confidence,
        model_confidence=confidence,
        siem_confidence=0.0,
        siem_alert_count=0,
        decision_source="model",
    )


@pytest.fixture(autouse=True)
def reset_tool_state():
    """Clear idempotency set and action log before and after every test."""
    tools_module._blocked_ips.clear()
    tools_module.clear_action_log()
    yield
    tools_module._blocked_ips.clear()
    tools_module.clear_action_log()


@pytest.fixture()
def simulated_os(monkeypatch):
    """Force all OS-dispatching tools to take the simulated branch (no subprocess)."""
    monkeypatch.setattr(tools_module.platform, "system", lambda: "TestOS")


# ---------------------------------------------------------------------------
# 1. Strategy map — selection by attack type
# ---------------------------------------------------------------------------

def test_strategy_selection_ddos():
    strategies = get_strategies("DDoS", 0.70)
    assert "block_ip" in strategies
    assert "rate_limit_ip" in strategies
    assert strategies[-1] == "alert_soc"


def test_high_confidence_ddos_uses_aggressive_override():
    normal     = get_strategies("DDoS", 0.80)
    aggressive = get_strategies("DDoS", HIGH_CONFIDENCE_THRESHOLD)
    # Standard path includes rate-limiting; aggressive override skips it
    assert "rate_limit_ip" in normal
    assert "rate_limit_ip" not in aggressive
    # Both still end with alert_soc
    assert aggressive[-1] == "alert_soc"


def test_unknown_attack_type_falls_back_to_alert_soc():
    strategies = get_strategies("AlienProbe", 0.90)
    assert strategies == ["alert_soc"]


# ---------------------------------------------------------------------------
# 2. Benign flow is skipped
# ---------------------------------------------------------------------------

def test_benign_flow_is_skipped(simulated_os):
    agent = MitigationAgent()
    classification = _make_classification(is_attack=False, attack_type="BENIGN")

    result = agent.mitigate(classification)

    assert result.notes == "skipped"
    assert result.success is True
    assert tools_module.get_action_log() == []


# ---------------------------------------------------------------------------
# 3. Deterministic execution — tools called in order, alert_soc last
# ---------------------------------------------------------------------------

def test_deterministic_mitigate_executes_tools_and_calls_alert_soc_last(simulated_os):
    agent = MitigationAgent()
    classification = _make_classification(attack_type="PortScan", confidence=0.80)

    agent.mitigate(classification)

    log = tools_module.get_action_log()
    tool_names = [e["tool"] for e in log]

    assert "block_ip" in tool_names
    assert "alert_soc" in tool_names
    assert tool_names[-1] == "alert_soc"


# ---------------------------------------------------------------------------
# 4. ClassificationResult fields are mutated after mitigate()
# ---------------------------------------------------------------------------

def test_mitigate_sets_classification_result_fields(simulated_os):
    agent = MitigationAgent()
    classification = _make_classification(attack_type="PortScan", confidence=0.78)

    agent.mitigate(classification)

    assert classification.mitigated is True
    assert classification.mitigation_status == "mitigated"
    assert isinstance(classification.mitigation_actions, list)
    assert len(classification.mitigation_actions) > 0


# ---------------------------------------------------------------------------
# 5. MitigationResult has correct shape
# ---------------------------------------------------------------------------

def test_mitigate_returns_correct_mitigation_result(simulated_os):
    agent = MitigationAgent()
    classification = _make_classification(attack_type="BruteForce", confidence=0.70)

    result = agent.mitigate(classification)

    assert isinstance(result, MitigationResult)
    assert result.src_ip == "10.0.0.1"
    assert result.attack_type == "BruteForce"
    assert result.success is True
    assert isinstance(result.agent_response, str)
    assert len(result.agent_response) > 0


# ---------------------------------------------------------------------------
# 6. Block-IP idempotency — second call on same IP is a no-op
# ---------------------------------------------------------------------------

def test_block_ip_idempotency(simulated_os):
    agent = MitigationAgent()
    classification = _make_classification(attack_type="PortScan", confidence=0.80)

    agent.mitigate(classification)
    agent.mitigate(classification)  # same IP second time

    block_entries = [e for e in tools_module.get_action_log() if e["tool"] == "block_ip"]
    skip_entries  = [e for e in block_entries if "skipped" in e["detail"].lower()]

    # The second block on the same IP must be recorded as a skip, not a duplicate rule
    assert len(skip_entries) >= 1


# ---------------------------------------------------------------------------
# 7. Tool failure — loop continues, alert_soc still fires
# ---------------------------------------------------------------------------

def test_tool_failure_continues_and_soc_alert_still_fires(simulated_os):
    # Replace block_ip in the registry with a fake that raises on invoke.
    # _TOOL_REGISTRY is a plain dict so mutation is safe.
    class _FailingTool:
        name = "block_ip"

        def invoke(self, _payload):
            raise RuntimeError("Simulated tool failure")

    original = _TOOL_REGISTRY["block_ip"]
    _TOOL_REGISTRY["block_ip"] = _FailingTool()

    try:
        agent = MitigationAgent()
        classification = _make_classification(attack_type="PortScan", confidence=0.80)

        result = agent.mitigate(classification)

        # SOC alert must still be logged despite the tool failure
        log = tools_module.get_action_log()
        assert any(e["tool"] == "alert_soc" for e in log)
        # Agent response must mention the failure
        assert "Failed" in result.agent_response
    finally:
        _TOOL_REGISTRY["block_ip"] = original


# ---------------------------------------------------------------------------
# 8. End-to-end on_mitigated callback contract
# ---------------------------------------------------------------------------

def test_on_mitigated_callback_fires_with_correct_result(simulated_os):
    received: list[MitigationResult] = []
    agent = MitigationAgent(on_mitigated=received.append)
    classification = _make_classification(attack_type="DDoS", confidence=0.80)

    agent.mitigate(classification)

    assert len(received) == 1
    assert received[0].src_ip == "10.0.0.1"
    assert received[0].attack_type is not None


# ---------------------------------------------------------------------------
# 9. Batch run — benign skipped, attacks mitigated
# ---------------------------------------------------------------------------

def test_batch_run_skips_benign_and_mitigates_attacks(simulated_os):
    agent = MitigationAgent()
    classifications = [
        _make_classification(src_ip="10.0.0.1", attack_type="DDoS",   confidence=0.80, is_attack=True),
        _make_classification(src_ip="10.0.0.2", attack_type="BENIGN", confidence=0.90, is_attack=False),
        _make_classification(src_ip="10.0.0.3", attack_type="PortScan", confidence=0.75, is_attack=True),
    ]

    results = agent.run_batch(classifications)

    skipped   = [r for r in results if r.notes == "skipped"]
    mitigated = [r for r in results if r.notes != "skipped" and r.success]

    assert len(results) == 3
    assert len(skipped) == 1
    assert len(mitigated) == 2
