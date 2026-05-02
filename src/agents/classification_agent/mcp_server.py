"""
MCP server exposing threat-intelligence tools for the classification agent.

Tools:
  check_ip_history         — full attack history for an IP
  check_same_attack_type   — count of past attacks matching a predicted type
  count_recent_ip_attacks  — count of attacks in the last N days
  compute_ip_reputation    — weighted verification score + verdict

Transport:
  stdio (default, for subprocess use):
      python -m src.agents.classification_agent.mcp_server

  SSE / HTTP (for persistent service on port 8765):
      python -m src.agents.classification_agent.mcp_server --transport sse
      python -m src.agents.classification_agent.mcp_server --transport sse --port 9000
"""

import argparse
import logging
import os
import sys
from pathlib import Path

# Allow both `python mcp_server.py` and `python -m src.agents...` invocations
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from mcp.server.fastmcp import FastMCP

try:
    from src.agents.classification_agent.kibana_adapter import KibanaAdapter, KibanaConfig
except ModuleNotFoundError:
    from agents.classification_agent.kibana_adapter import KibanaAdapter, KibanaConfig

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Server instance
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "ands-threat-intel",
    instructions=(
        "You are a cybersecurity threat-intelligence tool server. "
        "Use these tools to verify whether a machine-learning attack prediction "
        "is consistent with the historical behaviour of the suspected source IP."
    ),
)

# ---------------------------------------------------------------------------
# Lazy adapter — created once on first tool call
# ---------------------------------------------------------------------------
_adapter: KibanaAdapter | None = None


def _get_adapter() -> KibanaAdapter:
    global _adapter
    if _adapter is None:
        config = KibanaConfig(
            host=os.getenv("ES_HOST", "http://localhost:9200"),
            username=os.getenv("ES_USERNAME") or None,
            password=os.getenv("ES_PASSWORD") or None,
        )
        _adapter = KibanaAdapter(config)
    return _adapter


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------
def _norm(value: int, saturation: int) -> float:
    """Linear normalisation capped at 1.0."""
    return min(value / saturation, 1.0) if saturation > 0 else 0.0


def _verdict(score: float) -> str:
    if score > 0.80:
        return "Confirmed Historically Consistent Attack"
    if score >= 0.50:
        return "Suspicious Attack with Partial History"
    return "Newly Observed Attack / Low Historical Evidence"


# ---------------------------------------------------------------------------
# Tool 1 — check_ip_history
# ---------------------------------------------------------------------------
@mcp.tool()
def check_ip_history(ip: str) -> dict:
    """
    Return the full confirmed-attack history for a source IP address.

    Returns a dict with:
      previous_attack_count  — total confirmed attacks from this IP
      first_seen             — ISO timestamp of earliest attack
      last_seen              — ISO timestamp of most recent attack
      attack_types           — list of distinct attack types observed
      recent_attack_count    — attacks in the last 7 days
    """
    return _get_adapter().get_ip_history(ip)


# ---------------------------------------------------------------------------
# Tool 2 — check_same_attack_type
# ---------------------------------------------------------------------------
@mcp.tool()
def check_same_attack_type(ip: str, attack_type: str, days: int = 30) -> dict:
    """
    Count how many times an IP was previously involved in the same attack type.

    Args:
      ip          — source IP address to look up
      attack_type — predicted attack type from the ML model (e.g. "PortScan")
      days        — how far back to search (default 30 days)

    Returns a dict with:
      ip, attack_type, days, count
    """
    count = _get_adapter().get_same_attack_type_count(ip, attack_type, days)
    return {"ip": ip, "attack_type": attack_type, "days": days, "count": count}


# ---------------------------------------------------------------------------
# Tool 3 — count_recent_ip_attacks
# ---------------------------------------------------------------------------
@mcp.tool()
def count_recent_ip_attacks(ip: str, days: int = 7) -> dict:
    """
    Count all confirmed attacks from an IP in the last N days.

    Args:
      ip   — source IP address to look up
      days — lookback window in days (default 7)

    Returns a dict with:
      ip, days, count
    """
    count = _get_adapter().count_recent_ip_attacks(ip, days)
    return {"ip": ip, "days": days, "count": count}


# ---------------------------------------------------------------------------
# Tool 4 — compute_ip_reputation
# ---------------------------------------------------------------------------
@mcp.tool()
def compute_ip_reputation(ip: str, attack_type: str) -> dict:
    """
    Compute a verification score (0.0–1.0) for an ML-predicted attack by
    correlating the predicted source IP against historical attack memory.

    Score formula (from classification_agent.md):
      score = 0.4 * ip_history_score
            + 0.4 * same_attack_type_score
            + 0.2 * recent_recurrence_score

    Verdict thresholds:
      > 0.80  → Confirmed Historically Consistent Attack
      ≥ 0.50  → Suspicious Attack with Partial History
      < 0.50  → Newly Observed Attack / Low Historical Evidence

    Args:
      ip          — source IP address predicted by the ML model
      attack_type — predicted attack type (e.g. "PortScan", "DoS Hulk")

    Returns a dict with:
      ip, attack_type, verification_score, verdict, breakdown
    """
    adapter = _get_adapter()
    history = adapter.get_ip_history(ip)
    same_type_count = adapter.get_same_attack_type_count(ip, attack_type, days=30)
    recent_count = adapter.count_recent_ip_attacks(ip, days=7)

    total_attacks = history["previous_attack_count"]

    # Normalise each component (saturation points chosen for typical SOC context)
    ip_history_score       = _norm(total_attacks,    saturation=10)  # 10+ attacks → 1.0
    same_attack_type_score = _norm(same_type_count,  saturation=5)   # 5+ same-type → 1.0
    recent_recurrence_score = _norm(recent_count,    saturation=3)   # 3+ recent → 1.0

    verification_score = round(
        0.4 * ip_history_score
        + 0.4 * same_attack_type_score
        + 0.2 * recent_recurrence_score,
        4,
    )

    return {
        "ip": ip,
        "attack_type": attack_type,
        "verification_score": verification_score,
        "verdict": _verdict(verification_score),
        "breakdown": {
            "ip_history_score":        round(ip_history_score, 4),
            "same_attack_type_score":  round(same_attack_type_score, 4),
            "recent_recurrence_score": round(recent_recurrence_score, 4),
            "previous_attack_count":   total_attacks,
            "same_type_count":         same_type_count,
            "recent_count":            recent_count,
            "first_seen":              history["first_seen"],
            "last_seen":               history["last_seen"],
            "known_attack_types":      history["attack_types"],
        },
    }


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="ANDS Threat-Intel MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="Transport mode: stdio (subprocess) or sse (HTTP, default port 8765)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="HTTP port when --transport sse is used (default 8765)",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind host when --transport sse is used (default 127.0.0.1)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    args = _parse_args()

    if args.transport == "sse":
        logger.info("Starting MCP server (SSE) on http://%s:%s", args.host, args.port)
        mcp.run(transport="sse", host=args.host, port=args.port)
    else:
        logger.info("Starting MCP server (stdio)")
        mcp.run(transport="stdio")
