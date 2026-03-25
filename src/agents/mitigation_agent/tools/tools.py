# src/agents/mitigation/tools.py
from langchain_core.tools import tool

@tool
def block_ip(ip_address: str, duration_minutes: int = 60) -> str:
    """Block an IP address using iptables or pfSense API."""
    # stub: replace with actual iptables/pfSense/firewall call
    print(f"[TOOL] Blocking {ip_address} for {duration_minutes} min")
    return f"Blocked {ip_address} for {duration_minutes} minutes"

@tool
def rate_limit_ip(ip_address: str, max_rps: int = 10) -> str:
    """Apply rate limiting to an IP via tc or firewall rule."""
    print(f"[TOOL] Rate-limiting {ip_address} to {max_rps} req/s")
    return f"Rate-limited {ip_address} to {max_rps} req/s"

@tool
def alert_soc(message: str) -> str:
    """Send an alert to the SOC dashboard or Wazuh."""
    print(f"[ALERT] {message}")
    return "Alert sent"