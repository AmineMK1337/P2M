"""
Mitigation tools for the ANDS MitigationAgent.

Each function is decorated with @tool so LangGraph's create_react_agent
discovers and invokes them automatically.

State: stubs that log every action.
To go live: uncomment the subprocess / API call inside each tool and
remove the `success = True` stub line above it.
"""

import logging
from datetime import datetime

from langchain_core.tools import tool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Session-scoped audit log — every tool call appends here so MitigationAgent
# can report what actually happened.
# ---------------------------------------------------------------------------
_action_log: list[dict] = []


def get_action_log() -> list[dict]:
    return list(_action_log)


def clear_action_log() -> None:
    _action_log.clear()


def _record(tool_name: str, ip: str, detail: str, success: bool) -> None:
    _action_log.append({
        "timestamp": datetime.utcnow().isoformat(),
        "tool":      tool_name,
        "ip":        ip,
        "detail":    detail,
        "success":   success,
    })


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@tool
def block_ip(ip_address: str, duration_minutes: int = 60) -> str:
    """
    Block ALL inbound traffic from ip_address for duration_minutes minutes
    using an iptables DROP rule. Use duration_minutes=0 for a permanent block.
    """
    logger.warning("[MitigationAgent] block_ip  ip=%s  duration=%d min", ip_address, duration_minutes)

    # --- Uncomment to go live ---
    # import subprocess
    # cmd = ["iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"]
    # r = subprocess.run(cmd, capture_output=True, text=True)
    # success = r.returncode == 0
    # if not success:
    #     logger.error("[MitigationAgent] iptables block_ip failed: %s", r.stderr)
    # ----------------------------
    success = True  # stub

    _record("block_ip", ip_address, f"duration={duration_minutes}m", success)
    return f"[block_ip] {'OK' if success else 'FAILED'} — blocked {ip_address} for {duration_minutes} min."


@tool
def rate_limit_ip(ip_address: str, max_connections_per_second: int = 10) -> str:
    """
    Rate-limit inbound connections from ip_address to max_connections_per_second
    using the iptables hashlimit module.
    """
    logger.warning(
        "[MitigationAgent] rate_limit_ip  ip=%s  max_cps=%d",
        ip_address, max_connections_per_second,
    )

    # --- Uncomment to go live ---
    # import subprocess
    # cmd = [
    #     "iptables", "-I", "INPUT",
    #     "-s", ip_address,
    #     "-m", "hashlimit",
    #     "--hashlimit-name", f"rl_{ip_address.replace('.', '_')}",
    #     "--hashlimit-above", f"{max_connections_per_second}/sec",
    #     "--hashlimit-mode", "srcip",
    #     "-j", "DROP",
    # ]
    # r = subprocess.run(cmd, capture_output=True, text=True)
    # success = r.returncode == 0
    # ----------------------------
    success = True  # stub

    _record("rate_limit_ip", ip_address, f"max_cps={max_connections_per_second}", success)
    return (
        f"[rate_limit_ip] {'OK' if success else 'FAILED'} — "
        f"rate-limited {ip_address} to {max_connections_per_second} conn/s."
    )


@tool
def null_route_ip(ip_address: str) -> str:
    """
    Black-hole all traffic from ip_address via a kernel null route
    (ip route add blackhole). More effective than iptables for volumetric
    DDoS because the drop happens at the routing layer before packet inspection.
    """
    logger.warning("[MitigationAgent] null_route_ip  ip=%s", ip_address)

    # --- Uncomment to go live ---
    # import subprocess
    # cmd = ["ip", "route", "add", "blackhole", f"{ip_address}/32"]
    # r = subprocess.run(cmd, capture_output=True, text=True)
    # success = r.returncode == 0
    # ----------------------------
    success = True  # stub

    _record("null_route_ip", ip_address, "blackhole", success)
    return f"[null_route_ip] {'OK' if success else 'FAILED'} — null-routed {ip_address}."


@tool
def throttle_connections(ip_address: str, max_new_per_minute: int = 5) -> str:
    """
    Throttle new TCP connections from ip_address to max_new_per_minute.
    Effective against brute-force and credential-stuffing attacks.
    Uses the iptables recent module.
    """
    logger.warning(
        "[MitigationAgent] throttle_connections  ip=%s  max_new=%d/min",
        ip_address, max_new_per_minute,
    )

    # --- Uncomment to go live ---
    # import subprocess
    # subprocess.run([
    #     "iptables", "-I", "INPUT", "-p", "tcp", "-s", ip_address, "--syn",
    #     "-m", "recent", "--name", "BF", "--set",
    # ])
    # subprocess.run([
    #     "iptables", "-I", "INPUT", "-p", "tcp", "-s", ip_address, "--syn",
    #     "-m", "recent", "--name", "BF", "--update",
    #     "--seconds", "60", "--hitcount", str(max_new_per_minute), "-j", "DROP",
    # ])
    # success = True  # iptables never fails silently here
    # ----------------------------
    success = True  # stub

    _record("throttle_connections", ip_address, f"max_new={max_new_per_minute}/min", success)
    return (
        f"[throttle_connections] {'OK' if success else 'FAILED'} — "
        f"throttled {ip_address} to {max_new_per_minute} new conn/min."
    )


@tool
def quarantine_host(ip_address: str) -> str:
    """
    Quarantine an internal host by moving it to a restricted VLAN segment.
    Intended for botnet-infected internal machines.
    Requires an SDN controller or managed switch with an accessible API.
    """
    logger.warning("[MitigationAgent] quarantine_host  ip=%s", ip_address)

    # --- Uncomment to go live ---
    # Push VLAN reassignment via NETCONF, OpenFlow, or vendor REST API
    # ----------------------------
    success = True  # stub

    _record("quarantine_host", ip_address, "vlan_quarantine", success)
    return (
        f"[quarantine_host] {'OK' if success else 'FAILED'} — "
        f"{ip_address} moved to quarantine VLAN."
    )


@tool
def isolate_host(ip_address: str) -> str:
    """
    Fully isolate a host by blocking ALL inbound AND outbound traffic.
    Used for confirmed infiltration / APT scenarios to stop lateral movement.
    """
    logger.warning("[MitigationAgent] isolate_host  ip=%s", ip_address)

    # --- Uncomment to go live ---
    # import subprocess
    # subprocess.run(["iptables", "-I", "INPUT",  "-s", ip_address, "-j", "DROP"])
    # subprocess.run(["iptables", "-I", "OUTPUT", "-d", ip_address, "-j", "DROP"])
    # success = True
    # ----------------------------
    success = True  # stub

    _record("isolate_host", ip_address, "full_isolation", success)
    return (
        f"[isolate_host] {'OK' if success else 'FAILED'} — "
        f"{ip_address} fully isolated (inbound + outbound blocked)."
    )


@tool
def alert_soc(message: str, severity: str = "medium") -> str:
    """
    Send a structured alert to the SOC (Wazuh active-response or webhook).
    Always call this as the final step to guarantee an audit trail.
    severity must be one of: low, medium, high, critical.
    """
    logger.warning("[MitigationAgent] alert_soc  severity=%s  msg=%s", severity, message)

    # --- Uncomment to go live ---
    # import requests
    # requests.post(
    #     WAZUH_WEBHOOK_URL,
    #     json={"severity": severity, "message": message},
    #     timeout=5,
    # )
    # ----------------------------

    _record("alert_soc", "N/A", f"severity={severity} | {message}", True)
    return f"[alert_soc] Alert sent — severity={severity}: {message}"
