"""LangChain tool functions for the Intrusion Classification Agent."""

import json
import os

from langchain_core.tools import tool

from src.db.history_store import get_history_for_ip

HISTORY_WINDOW_HOURS = int(os.getenv("HISTORY_WINDOW_HOURS", 24))
MAX_HISTORY_RECORDS = int(os.getenv("MAX_HISTORY_RECORDS", 20))


@tool
def fetch_ip_history(src_ip: str) -> str:
    """Fetch recent classification history for a source IP."""
    if not src_ip or src_ip in ("", "unknown", "0.0.0.0"):
        return "No valid source IP - skipping history lookup."

    records = get_history_for_ip(
        src_ip,
        hours=HISTORY_WINDOW_HOURS,
        limit=MAX_HISTORY_RECORDS,
    )

    if not records:
        return (
            f"NO_HISTORY: {src_ip} has no records in the last "
            f"{HISTORY_WINDOW_HOURS}h. First-seen source."
        )

    lines = [f"History for {src_ip} - {len(records)} record(s):\n"]
    for r in records:
        ts = r["timestamp"].strftime("%H:%M:%S") if hasattr(r["timestamp"], "strftime") else str(r["timestamp"])
        lines.append(
            f"  [{ts}] model={r['model_label']}({r['model_confidence']:.0%})"
            f" | verdict={r.get('is_attack', '?')}"
            f" | type={r.get('attack_type', '?')}"
            f" | conf={r.get('confidence', '?')}%"
        )

    attack_labels = [r["model_label"] for r in records if r["model_label"] != "BENIGN"]
    unique_labels = list(dict.fromkeys(attack_labels))

    if len(attack_labels) >= 3 and len(set(attack_labels)) == 1:
        lines.append(
            f"\nPATTERN: REPETITION - '{attack_labels[0]}' seen "
            f"{len(attack_labels)} times from this IP."
        )
    elif len(unique_labels) >= 2:
        lines.append(
            f"\nPATTERN: ESCALATION - attack chain detected: {' -> '.join(unique_labels)}"
        )
    elif not attack_labels and len(records) >= 3:
        lines.append("\nPATTERN: CLEAN_HISTORY - all past records were BENIGN.")

    return "\n".join(lines)


@tool
def classify_flow_features(flow_features_json: str) -> str:
    """Apply simple rule-based anomaly checks to flow features."""
    try:
        f = json.loads(flow_features_json)
    except Exception:
        return "ERROR: Could not parse flow features JSON."

    findings = []

    def fv(key, default=0.0):
        try:
            return float(f.get(key, default) or 0)
        except (ValueError, TypeError):
            return 0.0

    if fv("flow_byts_s") > 1_000_000:
        findings.append(
            f"DDoS/Flood indicator: flow_byts_s={fv('flow_byts_s'):.0f} (threshold >1,000,000)"
        )
    if fv("flow_pkts_s") > 10_000:
        findings.append(
            f"DDoS/Flood indicator: flow_pkts_s={fv('flow_pkts_s'):.0f} (threshold >10,000)"
        )

    syn = fv("syn_flag_cnt")
    ack = fv("ack_flag_cnt")
    bwd = fv("tot_bwd_pkts")
    if syn > 10 and ack == 0 and bwd == 0:
        findings.append("SYN Flood: many SYNs with no ACK and no backward packets")

    if fv("pkt_len_mean") < 60 and fv("rst_flag_cnt") > 5:
        findings.append("Port Scan: tiny packets with high RST count")

    dst_port = int(fv("dst_port"))
    auth_ports = {22: "SSH", 21: "FTP", 3389: "RDP", 23: "Telnet", 25: "SMTP"}
    if dst_port in auth_ports and fv("flow_pkts_s") > 5:
        findings.append(
            f"Brute Force candidate: dst_port={dst_port} ({auth_ports[dst_port]}), flow_pkts_s={fv('flow_pkts_s'):.0f}"
        )

    if 0 < fv("flow_iat_mean") and fv("flow_iat_std") < 10:
        findings.append("Scripted/Bot traffic: near-zero inter-arrival time variance")

    if fv("idle_max") > 10_000_000 and fv("active_mean") < 100_000:
        findings.append("C2 Beaconing: long idle periods and short active bursts")

    if fv("init_bwd_win_byts") == 0 and syn > 0:
        findings.append("Abnormal handshake: server window zero while SYN present")

    if fv("urg_flag_cnt") > 0:
        findings.append("URG flag abuse: rare in normal traffic")

    fwd_mean = fv("fwd_pkt_len_mean")
    bwd_mean = fv("bwd_pkt_len_mean")
    if bwd_mean > 500 and fwd_mean < 100 and fv("tot_bwd_pkts") > 10:
        findings.append("Exfiltration indicator: large backward packets and small forward packets")

    if not findings:
        return "No rule-based anomalies detected. Feature values appear consistent with normal traffic."

    return "Feature anomalies detected:\n" + "\n".join(f"  - {item}" for item in findings)


@tool
def lookup_mitre(attack_label: str) -> str:
    """Map a CIC-IDS attack label to MITRE ATT&CK."""
    label = attack_label.lower().strip()

    mitre_map = {
        "ddos": ("Impact", "T1498", "Network Denial of Service"),
        "dos hulk": ("Impact", "T1499", "Endpoint Denial of Service"),
        "dos goldeneye": ("Impact", "T1499", "Endpoint Denial of Service"),
        "dos slowloris": ("Impact", "T1499", "Endpoint Denial of Service"),
        "dos slowhttptest": ("Impact", "T1499", "Endpoint Denial of Service"),
        "portscan": ("Discovery", "T1046", "Network Service Discovery"),
        "port scan": ("Discovery", "T1046", "Network Service Discovery"),
        "ftp-patator": ("Credential Access", "T1110", "Brute Force"),
        "ssh-patator": ("Credential Access", "T1110", "Brute Force"),
        "bot": ("Command and Control", "T1071", "Application Layer Protocol"),
        "web attack - brute force": ("Credential Access", "T1110", "Brute Force"),
        "web attack - xss": ("Execution", "T1059.007", "JavaScript"),
        "web attack - sql injection": ("Initial Access", "T1190", "Exploit Public-Facing Application"),
        "infiltration": ("Exfiltration", "T1041", "Exfiltration Over C2 Channel"),
        "heartbleed": ("Initial Access", "T1190", "Exploit Public-Facing Application"),
        "benign": ("", "", ""),
    }

    for key, (tactic, tid, name) in mitre_map.items():
        if key in label or label in key:
            if not tid:
                return "BENIGN - no MITRE mapping applicable."
            return (
                f"MITRE ATT&CK: {tactic} / {tid} - {name}\n"
                f"  URL: https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            )

    return f"No exact MITRE match for '{attack_label}'. Use closest available."


TOOLS = [fetch_ip_history, classify_flow_features, lookup_mitre]
"""
src/agents/intrusion_classification_agent/tools/tools.py
─────────────────────────────────────────────────────────
LangChain @tool functions for the Intrusion Classification Agent.

Three tools only — no alerting, no blocking, no actions:
  1. fetch_ip_history         — query past classifications from the DB
  2. classify_flow_features   — rule-based feature anomaly detector
  3. lookup_mitre             — maps attack label to MITRE ATT&CK
"""

import json
import os
from langchain_core.tools import tool

# Import DB helper (lives in src/db/history_store.py)
from src.db.history_store import get_history_for_ip

HISTORY_WINDOW_HOURS = int(os.getenv("HISTORY_WINDOW_HOURS", 24))
MAX_HISTORY_RECORDS  = int(os.getenv("MAX_HISTORY_RECORDS", 20))


# ─── Tool 1: SIEM history lookup ──────────────────────────────────────────────

@tool
def fetch_ip_history(src_ip: str) -> str:
    """
    Fetch past classification records for a given source IP address.

    Returns all known classifications from the last 24 hours for this source,
    including model labels, agent verdicts, and attack types. Used to detect
    repetition, escalation chains, and contradictions with the current prediction.

    Args:
        src_ip: Source IP address to look up (e.g. "192.168.1.100")
    """
    if not src_ip or src_ip in ("", "unknown", "0.0.0.0"):
        return "No valid source IP — skipping history lookup."

    records = get_history_for_ip(
        src_ip,
        hours=HISTORY_WINDOW_HOURS,
        limit=MAX_HISTORY_RECORDS
    )

    if not records:
        return (
            f"NO_HISTORY: {src_ip} has no records in the last "
            f"{HISTORY_WINDOW_HOURS}h. First-seen source."
        )

    lines = [f"History for {src_ip} — {len(records)} record(s):\n"]
    for r in records:
        ts = r["timestamp"].strftime("%H:%M:%S") if hasattr(r["timestamp"], "strftime") else str(r["timestamp"])
        lines.append(
            f"  [{ts}] model={r['model_label']}({r['model_confidence']:.0%})"
            f" | verdict={r.get('is_attack','?')}"
            f" | type={r.get('attack_type','?')}"
            f" | conf={r.get('confidence','?')}%"
        )

    # Detect patterns
    attack_labels = [
        r["model_label"] for r in records if r["model_label"] != "BENIGN"
    ]
    unique_labels = list(dict.fromkeys(attack_labels))

    if len(attack_labels) >= 3 and len(set(attack_labels)) == 1:
        lines.append(
            f"\nPATTERN: REPETITION — '{attack_labels[0]}' seen "
            f"{len(attack_labels)} times from this IP."
        )
    elif len(unique_labels) >= 2:
        lines.append(
            f"\nPATTERN: ESCALATION — attack chain detected: "
            f"{' → '.join(unique_labels)}"
        )
    elif not attack_labels and len(records) >= 3:
        lines.append("\nPATTERN: CLEAN_HISTORY — all past records were BENIGN.")

    return "\n".join(lines)


# ─── Tool 2: Feature-level anomaly validation ──────────────────────────────────

@tool
def classify_flow_features(flow_features_json: str) -> str:
    """
    Perform rule-based anomaly detection on raw network flow features.

    Validates whether the feature values are consistent with the model's predicted
    attack label. Detects DDoS, SYN flood, port scanning, brute force, C2 beaconing,
    and data exfiltration indicators from the raw CIC-IDS feature values.

    Args:
        flow_features_json: JSON string of flow features (CIC-IDS format, 80 fields).
    """
    try:
        f = json.loads(flow_features_json)
    except Exception:
        return "ERROR: Could not parse flow features JSON."

    findings = []

    def fv(key, default=0.0):
        try:
            return float(f.get(key, default) or 0)
        except (ValueError, TypeError):
            return 0.0

    # DDoS / flood
    if fv("flow_byts_s") > 1_000_000:
        findings.append(
            f"DDoS/Flood indicator: flow_byts_s={fv('flow_byts_s'):.0f} "
            f"(threshold >1,000,000)"
        )
    if fv("flow_pkts_s") > 10_000:
        findings.append(
            f"DDoS/Flood indicator: flow_pkts_s={fv('flow_pkts_s'):.0f} "
            f"(threshold >10,000)"
        )

    # SYN flood — many SYN, zero ACK, zero bwd packets
    syn = fv("syn_flag_cnt")
    ack = fv("ack_flag_cnt")
    bwd = fv("tot_bwd_pkts")
    if syn > 10 and ack == 0 and bwd == 0:
        findings.append(
            f"SYN Flood: syn_flag_cnt={syn:.0f}, ack_flag_cnt=0, "
            f"tot_bwd_pkts=0 — no completed handshakes"
        )

    # Port scan — tiny packets + high RST
    if fv("pkt_len_mean") < 60 and fv("rst_flag_cnt") > 5:
        findings.append(
            f"Port Scan: pkt_len_mean={fv('pkt_len_mean'):.1f}B (very small), "
            f"rst_flag_cnt={fv('rst_flag_cnt'):.0f}"
        )

    # Brute force on common auth ports
    dst_port = int(fv("dst_port"))
    AUTH_PORTS = {22: "SSH", 21: "FTP", 3389: "RDP", 23: "Telnet", 25: "SMTP"}
    if dst_port in AUTH_PORTS and fv("flow_pkts_s") > 5:
        findings.append(
            f"Brute Force candidate: dst_port={dst_port} "
            f"({AUTH_PORTS[dst_port]}), flow_pkts_s={fv('flow_pkts_s'):.0f}"
        )

    # Bot / scripted traffic — near-zero IAT variance
    if 0 < fv("flow_iat_mean") and fv("flow_iat_std") < 10:
        findings.append(
            f"Scripted/Bot traffic: flow_iat_std={fv('flow_iat_std'):.2f} "
            f"(near-zero → automated tool)"
        )

    # C2 beaconing — long idle, short active periods
    if fv("idle_max") > 10_000_000 and fv("active_mean") < 100_000:
        findings.append(
            f"C2 Beaconing: idle_max={fv('idle_max'):.0f}µs, "
            f"active_mean={fv('active_mean'):.0f}µs"
        )

    # Abnormal TCP handshake
    if "init_bwd_win_byts" in f and fv("init_bwd_win_byts") == 0 and syn > 0:
        findings.append(
            "Abnormal handshake: init_bwd_win_byts=0 with SYN present "
            "— server not responding"
        )

    # URG flag abuse
    if fv("urg_flag_cnt") > 0:
        findings.append(
            f"URG flag abuse: urg_flag_cnt={fv('urg_flag_cnt'):.0f} "
            f"(rare in normal traffic)"
        )

    # Data exfiltration — large bwd, tiny fwd
    fwd_mean = fv("fwd_pkt_len_mean")
    bwd_mean = fv("bwd_pkt_len_mean")
    if bwd_mean > 500 and fwd_mean < 100 and fv("tot_bwd_pkts") > 10:
        findings.append(
            f"Exfiltration indicator: bwd_pkt_len_mean={bwd_mean:.0f}B, "
            f"fwd_pkt_len_mean={fwd_mean:.0f}B — large outbound, tiny inbound"
        )

    if not findings:
        return (
            "No rule-based anomalies detected. "
            "Feature values appear consistent with normal traffic."
        )

    return "Feature anomalies detected:\n" + "\n".join(f"  • {x}" for x in findings)


# ─── Tool 3: MITRE ATT&CK mapping ────────────────────────────────────────────

@tool
def lookup_mitre(attack_label: str) -> str:
    """
    Map an attack label (CIC-IDS vocabulary) to MITRE ATT&CK tactic and technique.

    Args:
        attack_label: Attack category string from CIC-IDS vocabulary,
                      e.g. "DDoS", "PortScan", "SSH-Patator", "Bot", etc.
    """
    label = attack_label.lower().strip()

    MITRE_MAP = {
        "ddos":                       ("Impact",             "T1498", "Network Denial of Service"),
        "dos hulk":                   ("Impact",             "T1499", "Endpoint Denial of Service"),
        "dos goldeneye":              ("Impact",             "T1499", "Endpoint Denial of Service"),
        "dos slowloris":              ("Impact",             "T1499", "Endpoint Denial of Service"),
        "dos slowhttptest":           ("Impact",             "T1499", "Endpoint Denial of Service"),
        "portscan":                   ("Discovery",          "T1046", "Network Service Discovery"),
        "port scan":                  ("Discovery",          "T1046", "Network Service Discovery"),
        "ftp-patator":                ("Credential Access",  "T1110", "Brute Force"),
        "ssh-patator":                ("Credential Access",  "T1110", "Brute Force"),
        "bot":                        ("Command and Control","T1071", "Application Layer Protocol"),
        "web attack – brute force":   ("Credential Access",  "T1110", "Brute Force"),
        "web attack – xss":           ("Execution",          "T1059.007", "JavaScript"),
        "web attack – sql injection": ("Initial Access",     "T1190", "Exploit Public-Facing Application"),
        "infiltration":               ("Exfiltration",       "T1041", "Exfiltration Over C2 Channel"),
        "heartbleed":                 ("Initial Access",     "T1190", "Exploit Public-Facing Application"),
        "benign":                     ("",                   "",      ""),
    }

    for key, (tactic, tid, tname) in MITRE_MAP.items():
        if key in label or label in key:
            if not tid:
                return "BENIGN — no MITRE mapping applicable."
            return (
                f"MITRE ATT&CK: {tactic} / {tid} — {tname}\n"
                f"  URL: https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            )

    return f"No exact MITRE match for '{attack_label}'. Use closest available."


# ─── Export ───────────────────────────────────────────────────────────────────

TOOLS = [fetch_ip_history, classify_flow_features, lookup_mitre]
