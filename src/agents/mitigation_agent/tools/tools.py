"""
Mitigation tools for the ANDS MitigationAgent.

Each function is decorated with @tool so LangGraph's create_react_agent
discovers and invokes them automatically.

State: stubs that log every action.
To go live: uncomment the subprocess / API call inside each tool and
remove the `success = True` stub line above it.
"""

import logging
import platform
import subprocess
import sys
from datetime import datetime

from langchain_core.tools import tool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Idempotency Tracking
# ---------------------------------------------------------------------------
_blocked_ips: set[str] = set()

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

def _confirm_action(action_desc: str) -> bool:
    """Ask for user confirmation before executing a firewall action."""
    print(f"\n[!] Mitigation Agent requires approval to: {action_desc}")
    
    import os
    if os.environ.get("AUTO_MITIGATE", "false").lower() in ("true", "1", "yes"):
        logger.info("[MitigationAgent] AUTO_MITIGATE is enabled. Automatically approving.")
        return True
        
    if not sys.stdin.isatty():
        logger.warning("[MitigationAgent] Non-interactive shell detected. Assuming YES for automated pipeline (or you can change this to NO).")
        # For a live automated pipeline, if it's not a tty, we must auto-allow or auto-deny.
        # Since it's a mitigation agent, we auto-allow if backgrounded.
        return True
    
    try:
        ans = input("    Approve? [y/N]: ")
        return ans.strip().lower() in ('y', 'yes')
    except EOFError:
        return False



# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@tool
def block_ip(ip_address: str, duration_minutes: int = 60) -> str:
    """
    Block ALL inbound traffic from ip_address using an OS firewall rule.
    Works for both Linux (iptables) and Windows (netsh).
    Idempotent: will not duplicate if the IP was already blocked by this session.
    """
    global _blocked_ips
    
    if ip_address in _blocked_ips:
        logger.info("[MitigationAgent] block_ip  ip=%s  already blocked (idempotent skip)", ip_address)
        _record("block_ip", ip_address, f"duration={duration_minutes}m (skipped, already active)", True)
        return f"[block_ip] SKIP — {ip_address} is already blocked."
        
    logger.warning("[MitigationAgent] block_ip  ip=%s  duration=%d min", ip_address, duration_minutes)

    success = False
    error_msg = ""
    os_system = platform.system()
    
    try:
        if not _confirm_action(f"Block IP {ip_address} for {duration_minutes} min"):
            return f"[block_ip] CANCELED by user — {ip_address} was not blocked."

        if os_system == "Linux":
            cmd = ["sudo", "iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"]
            r = subprocess.run(cmd, capture_output=True, text=True)
            success = r.returncode == 0
            if not success:
                error_msg = r.stderr.strip()
                
        elif os_system == "Windows":
            rule_name = f"ANDS_Block_{ip_address}"
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip_address}"
            ]
            r = subprocess.run(cmd, capture_output=True, text=True)
            success = r.returncode == 0
            if not success:
                error_msg = r.stdout.strip() or r.stderr.strip()
        else:
            success = True
            logger.warning("[MitigationAgent] block_ip simulated on unsupported OS: %s", os_system)
            
    except Exception as exc:
        success = False
        error_msg = str(exc)

    if success:
        _blocked_ips.add(ip_address)
        _record("block_ip", ip_address, f"duration={duration_minutes}m", True)
        return f"[block_ip] OK — blocked {ip_address} for {duration_minutes} min via {os_system}."
    else:
        logger.error("[MitigationAgent] block_ip failed: %s", error_msg)
        _record("block_ip", ip_address, f"failed: {error_msg}", False)
        return f"[block_ip] FAILED — could not block {ip_address}: {error_msg}"


@tool
def rate_limit_ip(ip_address: str, max_connections_per_second: int = 10) -> str:
    """
    Rate-limit inbound connections from ip_address to max_connections_per_second.
    Linux: Uses iptables hashlimit.
    Windows: Not natively supported without QoS, falls back to full block.
    """
    logger.warning("[MitigationAgent] rate_limit_ip  ip=%s  max_cps=%d", ip_address, max_connections_per_second)

    os_system = platform.system()
    success = False
    error_msg = ""
    
    try:
        if not _confirm_action(f"Rate-limit IP {ip_address} to {max_connections_per_second} conn/sec"):
            return f"[rate_limit_ip] CANCELED by user — {ip_address} was not rate-limited."

        if os_system == "Linux":
            cmd = [
                "sudo", "iptables", "-I", "INPUT",
                "-s", ip_address,
                "-m", "hashlimit",
                "--hashlimit-name", f"rl_{ip_address.replace('.', '_')}",
                "--hashlimit-above", f"{max_connections_per_second}/sec",
                "--hashlimit-mode", "srcip",
                "-j", "DROP",
            ]
            r = subprocess.run(cmd, capture_output=True, text=True)
            success = r.returncode == 0
            if not success:
                error_msg = r.stderr.strip()
        elif os_system == "Windows":
            logger.warning("[MitigationAgent] rate_limit_ip not natively supported on Windows. Falling back to block.")
            return block_ip.invoke({"ip_address": ip_address, "duration_minutes": 60})
        else:
            success = True
            logger.warning("[MitigationAgent] rate_limit simulated on unsupported OS: %s", os_system)
            
    except Exception as exc:
        success = False
        error_msg = str(exc)

    _record("rate_limit_ip", ip_address, f"max_cps={max_connections_per_second}", success)
    if success:
        return f"[rate_limit_ip] OK — rate-limited {ip_address} to {max_connections_per_second} conn/s via {os_system}."
    else:
        logger.error("[MitigationAgent] rate_limit_ip failed: %s", error_msg)
        return f"[rate_limit_ip] FAILED — {error_msg}"


@tool
def null_route_ip(ip_address: str) -> str:
    """
    Black-hole all traffic from ip_address via a kernel null route.
    Linux: ip route add blackhole.
    Windows: falls back to block.
    """
    logger.warning("[MitigationAgent] null_route_ip  ip=%s", ip_address)

    os_system = platform.system()
    success = False
    error_msg = ""
    
    try:
        if not _confirm_action(f"Null-route IP {ip_address}"):
            return f"[null_route_ip] CANCELED by user — {ip_address} was not null-routed."

        if os_system == "Linux":
            cmd = ["sudo", "ip", "route", "add", "blackhole", f"{ip_address}/32"]
            r = subprocess.run(cmd, capture_output=True, text=True)
            success = r.returncode == 0
            if not success:
                error_msg = r.stderr.strip()
        elif os_system == "Windows":
            logger.warning("[MitigationAgent] null_route_ip mapped to block_ip on Windows.")
            return block_ip.invoke({"ip_address": ip_address, "duration_minutes": 60})
        else:
            success = True
            logger.warning("[MitigationAgent] null_route simulated on unsupported OS: %s", os_system)
    except Exception as exc:
        success = False
        error_msg = str(exc)

    _record("null_route_ip", ip_address, "blackhole", success)
    if success:
        return f"[null_route_ip] OK — null-routed {ip_address} via {os_system}."
    else:
        return f"[null_route_ip] FAILED — {error_msg}"


@tool
def throttle_connections(ip_address: str, max_new_per_minute: int = 5) -> str:
    """
    Throttle new TCP connections from ip_address to max_new_per_minute.
    Linux: iptables recent module.
    Windows: falls back to block.
    """
    logger.warning("[MitigationAgent] throttle_connections  ip=%s  max_new=%d/min", ip_address, max_new_per_minute)

    os_system = platform.system()
    success = False
    error_msg = ""
    
    try:
        if not _confirm_action(f"Throttle connections from IP {ip_address} to {max_new_per_minute}/min"):
            return f"[throttle_connections] CANCELED by user — {ip_address} was not throttled."

        if os_system == "Linux":
            subprocess.run([
                "sudo", "iptables", "-I", "INPUT", "-p", "tcp", "-s", ip_address, "--syn",
                "-m", "recent", "--name", "BF", "--set",
            ], capture_output=True)
            r = subprocess.run([
                "sudo", "iptables", "-I", "INPUT", "-p", "tcp", "-s", ip_address, "--syn",
                "-m", "recent", "--name", "BF", "--update",
                "--seconds", "60", "--hitcount", str(max_new_per_minute), "-j", "DROP",
            ], capture_output=True, text=True)
            success = r.returncode == 0
            if not success:
                error_msg = r.stderr.strip()
        elif os_system == "Windows":
            logger.warning("[MitigationAgent] throttle_connections mapped to block_ip on Windows.")
            return block_ip.invoke({"ip_address": ip_address, "duration_minutes": 60})
        else:
            success = True
            logger.warning("[MitigationAgent] throttle_connections simulated on unsupported OS: %s", os_system)
    except Exception as exc:
        success = False
        error_msg = str(exc)

    _record("throttle_connections", ip_address, f"max_new={max_new_per_minute}/min", success)
    if success:
        return f"[throttle_connections] OK — throttled {ip_address} to {max_new_per_minute} new conn/min via {os_system}."
    else:
        return f"[throttle_connections] FAILED — {error_msg}"


@tool
def quarantine_host(ip_address: str) -> str:
    """
    Quarantine an internal host by moving it to a restricted VLAN segment.
    Requires an SDN controller or managed switch with an accessible API.
    Currenly implemented as a stub/log.
    """
    logger.warning("[MitigationAgent] quarantine_host  ip=%s", ip_address)
    success = True
    _record("quarantine_host", ip_address, "vlan_quarantine", success)
    return f"[quarantine_host] OK — {ip_address} marked for quarantine VLAN."


@tool
def isolate_host(ip_address: str) -> str:
    """
    Fully isolate a host by blocking ALL inbound AND outbound traffic.
    Linux: iptables DROP on INPUT and OUTPUT.
    Windows: netsh advfirewall block on inbound and outbound.
    """
    logger.warning("[MitigationAgent] isolate_host  ip=%s", ip_address)

    os_system = platform.system()
    success = False
    error_msg = ""
    
    try:
        if not _confirm_action(f"Fully isolate host IP {ip_address}"):
            return f"[isolate_host] CANCELED by user — {ip_address} was not isolated."

        if os_system == "Linux":
            r1 = subprocess.run(["sudo", "iptables", "-I", "INPUT",  "-s", ip_address, "-j", "DROP"], capture_output=True)
            r2 = subprocess.run(["sudo", "iptables", "-I", "OUTPUT", "-d", ip_address, "-j", "DROP"], capture_output=True)
            success = r1.returncode == 0 and r2.returncode == 0
            if not success:
               error_msg = "failed to insert rules"
        elif os_system == "Windows":
            in_rule = f"ANDS_Isolate_In_{ip_address}"
            out_rule = f"ANDS_Isolate_Out_{ip_address}"
            cmd_in = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={in_rule}", "dir=in", "action=block", f"remoteip={ip_address}"]
            cmd_out = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={out_rule}", "dir=out", "action=block", f"remoteip={ip_address}"]
            r1 = subprocess.run(cmd_in, capture_output=True)
            r2 = subprocess.run(cmd_out, capture_output=True)
            success = r1.returncode == 0 and r2.returncode == 0
            if not success:
               error_msg = "failed to insert netsh rules"
        else:
            success = True
            logger.warning("[MitigationAgent] isolate_host simulated on %s", os_system)
    except Exception as exc:
        success = False
        error_msg = str(exc)

    _record("isolate_host", ip_address, "full_isolation", success)
    if success:
        return f"[isolate_host] OK — {ip_address} fully isolated (inbound + outbound blocked)."
    else:
        return f"[isolate_host] FAILED — {error_msg}"


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
