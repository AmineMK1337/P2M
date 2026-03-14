"""
src/agents/intrusion_classification_agent/agent.py
───────────────────────────────────────────────────
Intrusion Classification Agent — Agent 2 in ANDS.

Inputs  (from Agent 1 or pipeline):
  - flow:             dict  — 80 CIC-IDS network flow features
  - model_label:      str   — prediction from the trained supervised model
  - model_confidence: float — model confidence (0.0 – 1.0)

Output (for Agent 3 or pipeline):
  - ClassificationResult dataclass with:
      is_attack, attack_type, confidence, severity,
      history_signal, is_multi_stage,
      mitre_technique_id, mitre_tactic,
      key_evidence, reasoning

No alerts. No blocking. No actions. Classification only.
"""

import os
import re
import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from langchain_anthropic import ChatAnthropic
from langgraph.prebuilt import create_react_agent
from langgraph.checkpoint.memory import MemorySaver

from src.agents.tools.tools import TOOLS
from src.agents.prompts.system_prompt import SYSTEM_PROMPT
from src.db.history_store import store_classification

load_dotenv()
logger = logging.getLogger(__name__)


# ─── Output schema ────────────────────────────────────────────────────────────

@dataclass
class ClassificationResult:
    """
    The agent's output. Consumed by Agent 3 (DDoS Prevention Agent).
    Serializable to dict via asdict(result).
    """
    is_attack:          bool
    attack_type:        str            # e.g. "DDoS", "PortScan", "BENIGN"
    confidence:         int            # 0–100
    severity:           str            # CRITICAL | HIGH | MEDIUM | LOW | INFO
    history_signal:     str            # CONFIRMS | CONTRADICTS | ESCALATES | NEUTRAL | NO_HISTORY
    is_multi_stage:     bool
    mitre_technique_id: str
    mitre_tactic:       str
    key_evidence:       list[str]      = field(default_factory=list)
    reasoning:          str            = ""

    # Passthrough — not part of classification, just for pipeline traceability
    src_ip:             str            = ""
    dst_ip:             str            = ""
    protocol:           str            = ""
    model_label:        str            = ""
    model_confidence:   float          = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    def __str__(self) -> str:
        status = "ATTACK" if self.is_attack else "BENIGN"
        return (
            f"[IntrusionClassificationAgent] {status} | "
            f"type={self.attack_type} | conf={self.confidence}% | "
            f"severity={self.severity} | history={self.history_signal}"
        )


# ─── LLM factory ──────────────────────────────────────────────────────────────

def _build_llm():
    provider = os.getenv("LLM_PROVIDER", "anthropic").lower()
    model    = os.getenv("LLM_MODEL", "claude-opus-4-6")

    if provider == "anthropic":
        return ChatAnthropic(
            model=model,
            temperature=0,
            max_tokens=2048,
            api_key=os.getenv("ANTHROPIC_API_KEY"),
        )
    elif provider == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(model=model, temperature=0,
                          api_key=os.getenv("OPENAI_API_KEY"))
    elif provider == "ollama":
        from langchain_community.chat_models import ChatOllama
        return ChatOllama(
            model=model,
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            temperature=0,
        )
    else:
        raise ValueError(f"Unknown LLM_PROVIDER: '{provider}'")


# ─── Verdict parser ───────────────────────────────────────────────────────────

def _parse_result(agent_output: str, flow: dict,
                  model_label: str, model_confidence: float) -> ClassificationResult:
    """Extract the <classification> JSON block from the agent's output."""

    raw = None

    # Primary: <classification>...</classification> tags
    match = re.search(r"<classification>(.*?)</classification>", agent_output, re.DOTALL)
    if match:
        try:
            raw = json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # Fallback: any JSON block with "is_attack" key
    if raw is None:
        match = re.search(r"\{[\s\S]*\"is_attack\"[\s\S]*\}", agent_output)
        if match:
            try:
                raw = json.loads(match.group(0))
            except json.JSONDecodeError:
                pass

    if raw is None:
        logger.warning("Could not parse <classification> block — returning UNCERTAIN.")
        return ClassificationResult(
            is_attack=False,
            attack_type="PARSE_ERROR",
            confidence=0,
            severity="LOW",
            history_signal="NEUTRAL",
            is_multi_stage=False,
            mitre_technique_id="",
            mitre_tactic="",
            key_evidence=[],
            reasoning="Agent output could not be parsed. Manual review required.",
            src_ip=flow.get("src_ip", ""),
            dst_ip=flow.get("dst_ip", ""),
            protocol=flow.get("protocol", ""),
            model_label=model_label,
            model_confidence=model_confidence,
        )

    return ClassificationResult(
        is_attack          = bool(raw.get("is_attack", False)),
        attack_type        = str(raw.get("attack_type", "UNKNOWN")),
        confidence         = int(raw.get("confidence", 0)),
        severity           = str(raw.get("severity", "LOW")),
        history_signal     = str(raw.get("history_signal", "NEUTRAL")),
        is_multi_stage     = bool(raw.get("is_multi_stage", False)),
        mitre_technique_id = str(raw.get("mitre_technique_id", "")),
        mitre_tactic       = str(raw.get("mitre_tactic", "")),
        key_evidence       = list(raw.get("key_evidence", [])),
        reasoning          = str(raw.get("reasoning", "")),
        src_ip             = flow.get("src_ip", ""),
        dst_ip             = flow.get("dst_ip", ""),
        protocol           = flow.get("protocol", ""),
        model_label        = model_label,
        model_confidence   = model_confidence,
    )


# ─── Agent class ──────────────────────────────────────────────────────────────

class IntrusionClassificationAgent:
    """
    Agent 2 in the ANDS pipeline.

    Usage:
        agent = IntrusionClassificationAgent()
        result = agent.classify(flow, model_label, model_confidence)
        # result is a ClassificationResult — pass it to Agent 3
    """

    def __init__(self):
        llm = _build_llm().bind_tools(TOOLS)
        self._graph = create_react_agent(
            model=llm,
            tools=TOOLS,
            checkpointer=MemorySaver(),
            state_modifier=SYSTEM_PROMPT,
        )
        logger.info("IntrusionClassificationAgent initialized.")

    def classify(
        self,
        flow: dict,
        model_label: str,
        model_confidence: float,
        session_id: Optional[str] = None,
    ) -> ClassificationResult:
        """
        Classify a network flow.

        Args:
            flow:             All 80 CIC-IDS flow features as a dict
            model_label:      Prediction from your trained model
            model_confidence: Confidence score from your trained model (0.0–1.0)
            session_id:       Optional — keeps memory across calls in same session

        Returns:
            ClassificationResult — pass directly to Agent 3
        """
        src_ip = flow.get("src_ip", "unknown")

        # Build the compact feature summary for the prompt
        KEY_FEATURES = [
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp",
            "flow_byts_s", "flow_pkts_s", "fwd_pkts_s", "bwd_pkts_s",
            "tot_fwd_pkts", "tot_bwd_pkts",
            "syn_flag_cnt", "ack_flag_cnt", "rst_flag_cnt",
            "psh_flag_cnt", "urg_flag_cnt", "fin_flag_cnt",
            "pkt_len_mean", "flow_iat_mean", "flow_iat_std",
            "init_fwd_win_byts", "init_bwd_win_byts",
            "down_up_ratio", "flow_duration",
        ]
        summary = "\n".join(
            f"  {k}: {flow[k]}" for k in KEY_FEATURES if k in flow
        )

        message = f"""Classify the following network flow.

## Flow summary
{summary}

## Full features (for classify_flow_features tool)
{json.dumps(flow)}

## Trained model prediction
  Label:      {model_label}
  Confidence: {model_confidence:.1%}

Steps:
1. Call fetch_ip_history("{src_ip}")
2. Call classify_flow_features with the full features JSON
3. Call lookup_mitre with the most likely attack type
4. Output your <classification> JSON
"""

        config = {"configurable": {"thread_id": session_id or src_ip}}

        try:
            output = self._graph.invoke(
                {"messages": [HumanMessage(content=message)]},
                config=config,
            )
            final_text = output["messages"][-1].content
            result = _parse_result(final_text, flow, model_label, model_confidence)

            # Persist to DB (feeds future history lookups)
            store_classification(flow, model_label, model_confidence, result)

            logger.info(str(result))
            return result

        except Exception as e:
            logger.error(f"Agent error: {e}", exc_info=True)
            return ClassificationResult(
                is_attack=False,
                attack_type="AGENT_ERROR",
                confidence=0,
                severity="LOW",
                history_signal="NEUTRAL",
                is_multi_stage=False,
                mitre_technique_id="",
                mitre_tactic="",
                key_evidence=[],
                reasoning=f"Agent error: {e}",
                src_ip=src_ip,
                model_label=model_label,
                model_confidence=model_confidence,
            )
