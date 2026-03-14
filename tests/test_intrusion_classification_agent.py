"""
tests/test_intrusion_classification_agent.py
─────────────────────────────────────────────
Unit tests for Agent 2 — Intrusion Classification Agent.
Run with: pytest tests/test_intrusion_classification_agent.py -v
"""

import json
import pytest
from unittest.mock import patch

from src.agents.tools.tools import (
    classify_flow_features,
    lookup_mitre,
    fetch_ip_history,
)
from src.agents.intrusion_classification_agent import _parse_result


# ─── classify_flow_features ───────────────────────────────────────────────────

class TestClassifyFlowFeatures:

    def test_ddos_detected(self):
        flow = json.dumps({"flow_byts_s": 9_000_000, "flow_pkts_s": 95_000,
                           "fwd_pkts_s": 95_000, "bwd_pkts_s": 0})
        result = classify_flow_features.invoke({"flow_features_json": flow})
        assert "DDoS" in result or "HIGH VOLUME" in result or "flow_byts_s" in result

    def test_syn_flood_detected(self):
        flow = json.dumps({"syn_flag_cnt": 500, "ack_flag_cnt": 0, "tot_bwd_pkts": 0})
        result = classify_flow_features.invoke({"flow_features_json": flow})
        assert "SYN Flood" in result

    def test_port_scan_detected(self):
        flow = json.dumps({"pkt_len_mean": 40, "rst_flag_cnt": 15})
        result = classify_flow_features.invoke({"flow_features_json": flow})
        assert "Port Scan" in result

    def test_brute_force_ssh_detected(self):
        flow = json.dumps({"dst_port": 22, "flow_pkts_s": 50})
        result = classify_flow_features.invoke({"flow_features_json": flow})
        assert "Brute Force" in result or "SSH" in result

    def test_benign_no_anomaly(self):
        flow = json.dumps({
            "flow_byts_s": 12_000, "flow_pkts_s": 20,
            "syn_flag_cnt": 1, "ack_flag_cnt": 48,
            "rst_flag_cnt": 0, "urg_flag_cnt": 0,
            "pkt_len_mean": 604, "flow_iat_std": 30_000,
            "init_fwd_win_byts": 65535, "tot_bwd_pkts": 25,
        })
        result = classify_flow_features.invoke({"flow_features_json": flow})
        assert "No rule-based anomalies" in result

    def test_invalid_json_returns_error(self):
        result = classify_flow_features.invoke({"flow_features_json": "not-json"})
        assert "ERROR" in result


# ─── lookup_mitre ─────────────────────────────────────────────────────────────

class TestLookupMitre:

    def test_ddos(self):
        r = lookup_mitre.invoke({"attack_label": "DDoS"})
        assert "T1498" in r and "Impact" in r

    def test_portscan(self):
        r = lookup_mitre.invoke({"attack_label": "PortScan"})
        assert "T1046" in r and "Discovery" in r

    def test_ssh_patator(self):
        r = lookup_mitre.invoke({"attack_label": "SSH-Patator"})
        assert "T1110" in r and "Credential Access" in r

    def test_bot(self):
        r = lookup_mitre.invoke({"attack_label": "Bot"})
        assert "T1071" in r and "Command and Control" in r

    def test_benign(self):
        r = lookup_mitre.invoke({"attack_label": "BENIGN"})
        assert "BENIGN" in r or "benign" in r.lower()

    def test_unknown_label(self):
        r = lookup_mitre.invoke({"attack_label": "WeirdUnknownAttack"})
        assert "No exact MITRE match" in r


# ─── fetch_ip_history ─────────────────────────────────────────────────────────

class TestFetchIpHistory:

    def test_no_history(self):
        with patch("src.agents.tools.tools.get_history_for_ip",
                   return_value=[]):
            r = fetch_ip_history.invoke({"src_ip": "1.2.3.4"})
            assert "NO_HISTORY" in r or "No records" in r or "first-seen" in r.lower()

    def test_invalid_ip(self):
        r = fetch_ip_history.invoke({"src_ip": ""})
        assert "No valid source IP" in r

    def test_repetition_pattern(self):
        from unittest.mock import MagicMock
        ts = MagicMock(); ts.strftime = lambda fmt: "09:00:00"
        records = [
            {"timestamp": ts, "model_label": "DDoS", "model_confidence": 0.91,
             "is_attack": True, "attack_type": "DDoS", "confidence": 93},
            {"timestamp": ts, "model_label": "DDoS", "model_confidence": 0.88,
             "is_attack": True, "attack_type": "DDoS", "confidence": 90},
            {"timestamp": ts, "model_label": "DDoS", "model_confidence": 0.89,
             "is_attack": True, "attack_type": "DDoS", "confidence": 91},
        ]
        with patch("src.agents.tools.tools.get_history_for_ip",
                   return_value=records):
            r = fetch_ip_history.invoke({"src_ip": "45.33.32.156"})
            assert "REPETITION" in r

    def test_escalation_pattern(self):
        from unittest.mock import MagicMock
        ts = MagicMock(); ts.strftime = lambda fmt: "08:00:00"
        records = [
            {"timestamp": ts, "model_label": "PortScan",   "model_confidence": 0.97,
             "is_attack": True, "attack_type": "PortScan",   "confidence": 97},
            {"timestamp": ts, "model_label": "FTP-Patator","model_confidence": 0.89,
             "is_attack": True, "attack_type": "FTP-Patator","confidence": 91},
            {"timestamp": ts, "model_label": "SSH-Patator","model_confidence": 0.76,
             "is_attack": True, "attack_type": "SSH-Patator","confidence": 85},
        ]
        with patch("src.agents.tools.tools.get_history_for_ip",
                   return_value=records):
            r = fetch_ip_history.invoke({"src_ip": "203.0.113.77"})
            assert "ESCALATION" in r


# ─── _parse_result ────────────────────────────────────────────────────────────

class TestParseResult:
    flow = {"src_ip": "1.2.3.4", "dst_ip": "10.0.0.1", "protocol": "UDP"}

    def test_valid_attack_output(self):
        output = """
<classification>
{"is_attack": true, "attack_type": "DDoS", "confidence": 95,
 "severity": "CRITICAL", "history_signal": "CONFIRMS",
 "is_multi_stage": false, "mitre_technique_id": "T1498",
 "mitre_tactic": "Impact",
 "key_evidence": ["flow_byts_s=8500000"],
 "reasoning": "High volume UDP confirmed by 3 prior attacks."}
</classification>
"""
        r = _parse_result(output, self.flow, "DDoS", 0.91)
        assert r.is_attack is True
        assert r.attack_type == "DDoS"
        assert r.confidence == 95
        assert r.mitre_technique_id == "T1498"

    def test_valid_benign_output(self):
        output = """
<classification>
{"is_attack": false, "attack_type": "BENIGN", "confidence": 88,
 "severity": "INFO", "history_signal": "NEUTRAL",
 "is_multi_stage": false, "mitre_technique_id": "",
 "mitre_tactic": "", "key_evidence": [], "reasoning": "Normal HTTPS traffic."}
</classification>
"""
        r = _parse_result(output, self.flow, "BENIGN", 0.88)
        assert r.is_attack is False
        assert r.attack_type == "BENIGN"

    def test_unparseable_output_returns_safe_default(self):
        r = _parse_result("I cannot determine this.", self.flow, "DDoS", 0.5)
        assert r.is_attack is False
        assert r.attack_type == "PARSE_ERROR"
        assert "Manual review" in r.reasoning
