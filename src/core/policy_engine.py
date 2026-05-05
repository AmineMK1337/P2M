"""
src/core/policy_engine.py
─────────────────────────
Thread-safe loader for config/incident_policy.yaml.

Exposes the four RL-adaptive threshold values as plain attributes.
The RL optimizer writes new values to YAML and then calls reload();
the classification agent reads cached attributes — no YAML I/O on the hot path.

This file does NOT alter any classification logic.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Absolute path so the engine works regardless of cwd.
_DEFAULT_YAML = Path(__file__).resolve().parents[2] / "config" / "incident_policy.yaml"


class PolicyEngine:
    """
    Loads and caches decision thresholds from incident_policy.yaml.

    RL-adaptive attributes (written by RLPolicyOptimizer):
        model_trust_floor        — minimum model confidence to consider (default 0.50)
        model_high_confidence    — bypass SIEM above this threshold  (default 0.85)
        siem_corroboration_min   — minimum SIEM score to corroborate  (default 0.70)
        suspicious_escalate_count— SUSPICIOUS hits before escalation  (default 3)

    Read-only (not RL-adapted):
        siem_alert_count_min     — minimum raw SIEM alert count       (default 2)
        suspicious_recheck_minutes                                     (default 10)
    """

    # Hard-coded defaults — applied when YAML is missing or a key is absent.
    _DEFAULTS: dict[str, Any] = {
        "model_trust_floor": 0.50,
        "model_high_confidence": 0.85,
        "siem_corroboration_min": 0.70,
        "siem_alert_count_min": 2,
        "suspicious_escalate_count": 3,
        "suspicious_recheck_minutes": 10,
    }

    def __init__(self, yaml_path: str | Path = _DEFAULT_YAML) -> None:
        self._path = Path(yaml_path)
        self._lock = threading.RLock()

        # Public threshold attributes — initialised to defaults, then overwritten
        # by the first reload() call so the YAML is the authority from startup.
        self.model_trust_floor: float = self._DEFAULTS["model_trust_floor"]
        self.model_high_confidence: float = self._DEFAULTS["model_high_confidence"]
        self.siem_corroboration_min: float = self._DEFAULTS["siem_corroboration_min"]
        self.siem_alert_count_min: int = self._DEFAULTS["siem_alert_count_min"]
        self.suspicious_escalate_count: int = self._DEFAULTS["suspicious_escalate_count"]
        self.suspicious_recheck_minutes: int = self._DEFAULTS["suspicious_recheck_minutes"]

        self.reload()

    # ── Public API ────────────────────────────────────────────────────────────

    def reload(self) -> None:
        """
        Re-read YAML and update cached attributes.  Thread-safe.
        Called by RLPolicyOptimizer after each YAML write.
        """
        if not self._path.exists():
            logger.warning(
                "[PolicyEngine] %s not found — using hardcoded defaults", self._path
            )
            return

        try:
            raw = yaml.safe_load(self._path.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            logger.error("[PolicyEngine] Failed to read YAML: %s", exc)
            return

        dp = raw.get("decision_policy", {})
        ss = dp.get("suspicious_state", {})

        with self._lock:
            self.model_trust_floor = float(
                dp.get("model_trust_floor", self._DEFAULTS["model_trust_floor"])
            )
            self.model_high_confidence = float(
                dp.get("model_high_confidence", self._DEFAULTS["model_high_confidence"])
            )
            self.siem_corroboration_min = float(
                dp.get("siem_corroboration_min", self._DEFAULTS["siem_corroboration_min"])
            )
            self.siem_alert_count_min = int(
                dp.get("siem_alert_count_min", self._DEFAULTS["siem_alert_count_min"])
            )
            self.suspicious_escalate_count = int(
                ss.get("escalate_if_count", self._DEFAULTS["suspicious_escalate_count"])
            )
            self.suspicious_recheck_minutes = int(
                ss.get("recheck_after_minutes", self._DEFAULTS["suspicious_recheck_minutes"])
            )

        logger.debug(
            "[PolicyEngine] Reloaded — model_high_confidence=%.2f  "
            "model_trust_floor=%.2f  siem_corroboration_min=%.2f  "
            "suspicious_escalate_count=%d",
            self.model_high_confidence,
            self.model_trust_floor,
            self.siem_corroboration_min,
            self.suspicious_escalate_count,
        )

    def snapshot(self) -> dict[str, Any]:
        """Return a point-in-time copy of the adaptive thresholds."""
        with self._lock:
            return {
                "model_trust_floor": self.model_trust_floor,
                "model_high_confidence": self.model_high_confidence,
                "siem_corroboration_min": self.siem_corroboration_min,
                "siem_alert_count_min": self.siem_alert_count_min,
                "suspicious_escalate_count": self.suspicious_escalate_count,
                "suspicious_recheck_minutes": self.suspicious_recheck_minutes,
            }
