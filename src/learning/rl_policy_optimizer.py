"""
src/learning/rl_policy_optimizer.py
────────────────────────────────────
Background Q-learning optimizer that periodically adjusts the four
RL-adaptive thresholds in config/incident_policy.yaml.

It does NOT touch any classification logic.  It only:
  1. Fetches recent decision stats from Elasticsearch (or local fallback).
  2. Computes a compact state vector from operational metrics.
  3. Runs one Q-learning step to select an action.
  4. Applies the action by clamping and writing updated thresholds to YAML.
  5. Tells PolicyEngine to reload so the agent picks up the new values.

Actions
───────
  0  model_high_confidence  += 0.01
  1  model_high_confidence  -= 0.01
  2  model_trust_floor      += 0.01
  3  model_trust_floor      -= 0.01
  4  siem_corroboration_min += 0.01
  5  siem_corroboration_min -= 0.01
  6  suspicious_escalate_count += 1
  7  suspicious_escalate_count -= 1
  8  no change

Safe ranges (hard clamp, never violated)
─────────────────────────────────────────
  model_high_confidence    ∈ [0.75, 0.95]
  model_trust_floor        ∈ [0.35, 0.65]
  siem_corroboration_min   ∈ [0.55, 0.90]
  suspicious_escalate_count∈ [2, 6]
"""

from __future__ import annotations

import json
import logging
import os
import random
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

N_ACTIONS = 9

# Safe clamping bounds
_BOUNDS: dict[str, tuple] = {
    "model_high_confidence":    (0.75, 0.95),
    "model_trust_floor":        (0.35, 0.65),
    "siem_corroboration_min":   (0.55, 0.90),
    "suspicious_escalate_count": (2, 6),
}

# Q-learning hyper-parameters
_ALPHA = 0.10   # learning rate
_GAMMA = 0.90   # discount factor
_EPSILON = 0.10  # exploration rate

# Bins used to discretize each metric into 3 levels (0=low, 1=med, 2=high)
_BINS = {
    "suspicious_rate":      [0.10, 0.30],
    "fp_rate":              [0.10, 0.30],
    "fn_rate":              [0.10, 0.20],
    "avg_model_confidence": [0.60, 0.75],
    "avg_siem_confidence":  [0.40, 0.65],
}

_QTABLE_PATH = Path(__file__).resolve().parents[2] / "logs" / "rl_qtable.json"
_YAML_PATH   = Path(__file__).resolve().parents[2] / "config" / "incident_policy.yaml"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _bin(value: float, thresholds: list[float]) -> int:
    """Map a continuous value into a discrete bin index."""
    for i, t in enumerate(thresholds):
        if value < t:
            return i
    return len(thresholds)


def _clamp(value: float | int, lo: float | int, hi: float | int) -> float | int:
    return max(lo, min(hi, value))


def _load_qtable() -> dict[str, dict[int, float]]:
    if not _QTABLE_PATH.exists():
        return {}
    try:
        raw = json.loads(_QTABLE_PATH.read_text(encoding="utf-8"))
        return {k: {int(a): float(v) for a, v in actions.items()} for k, actions in raw.items()}
    except Exception as exc:
        logger.warning("[RL-OPTIMIZER] Could not load Q-table: %s", exc)
        return {}


def _save_qtable(table: dict[str, dict[int, float]]) -> None:
    _QTABLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        _QTABLE_PATH.write_text(
            json.dumps(table, indent=2), encoding="utf-8"
        )
    except Exception as exc:
        logger.warning("[RL-OPTIMIZER] Could not save Q-table: %s", exc)


# ── Optimizer ─────────────────────────────────────────────────────────────────

class RLPolicyOptimizer:
    """
    Q-learning optimizer for ANDS decision thresholds.

    Parameters
    ----------
    policy:
        The shared PolicyEngine instance.  The optimizer reads current
        threshold values from it and calls reload() after each YAML write.
    kibana:
        Optional KibanaAdapterBase instance for fetching ES decision stats.
        When None (or unavailable), the optimizer falls back to a local
        JSON decision log at logs/rl_decisions.jsonl.
    window_minutes:
        Look-back window used when querying Elasticsearch for recent stats.
    """

    def __init__(
        self,
        policy,                      # PolicyEngine — typed loosely to avoid circular import
        kibana=None,                 # KibanaAdapterBase or None
        window_minutes: int = 30,
    ) -> None:
        self._policy = policy
        self._kibana = kibana
        self._window_minutes = window_minutes
        self._lock = threading.Lock()

        self._qtable: dict[str, dict[int, float]] = _load_qtable()
        self._prev_state: Optional[str] = None
        self._prev_action: Optional[int] = None

    # ── Public entry point ────────────────────────────────────────────────────

    def run_cycle(self) -> None:
        """
        Execute one full RL cycle: fetch metrics → compute state → choose
        action → compute reward → update Q-table → write YAML → reload policy.
        """
        with self._lock:
            prev_thresholds = self._policy.snapshot()
            logger.info(
                "[RL-OPTIMIZER] Previous thresholds: model_high_confidence=%.3f  "
                "model_trust_floor=%.3f  siem_corroboration_min=%.3f  "
                "suspicious_escalate_count=%d",
                prev_thresholds["model_high_confidence"],
                prev_thresholds["model_trust_floor"],
                prev_thresholds["siem_corroboration_min"],
                prev_thresholds["suspicious_escalate_count"],
            )

            # 1. Fetch metrics
            metrics = self._fetch_metrics()
            logger.info(
                "[RL-OPTIMIZER] Current state metrics: fp_rate=%.3f  fn_rate=%.3f  "
                "suspicious_rate=%.3f  avg_model_conf=%.3f  avg_siem_conf=%.3f",
                metrics["fp_rate"],
                metrics["fn_rate"],
                metrics["suspicious_rate"],
                metrics["avg_model_confidence"],
                metrics["avg_siem_confidence"],
            )

            # 2. Build discrete state key
            state = self._state_key(metrics)

            # 3. Update Q-table for previous (state, action) pair using current reward
            if self._prev_state is not None and self._prev_action is not None:
                reward = self._compute_reward(metrics)
                logger.info("[RL-OPTIMIZER] Reward obtained: %.4f", reward)
                self._update_q(self._prev_state, self._prev_action, reward, state)

            # 4. Choose next action
            action = self._choose_action(state)
            action_name = self._action_name(action)
            logger.info("[RL-OPTIMIZER] Chosen action: %d — %s", action, action_name)

            # 5. Apply action → clamped thresholds
            new_thresholds = self._apply_action(dict(prev_thresholds), action)

            # 6. Write YAML and reload
            self._write_yaml(new_thresholds)
            self._policy.reload()
            logger.info("[RL-OPTIMIZER] Updated thresholds written to YAML.")

            # 7. Persist Q-table and update memory
            _save_qtable(self._qtable)
            self._prev_state = state
            self._prev_action = action

    # ── Metrics ───────────────────────────────────────────────────────────────

    def _fetch_metrics(self) -> dict[str, float]:
        """
        Fetch recent decision stats from Elasticsearch.
        Falls back gracefully when ES is unavailable.
        """
        defaults: dict[str, float] = {
            "fp_rate": 0.0,
            "fn_rate": 0.0,
            "suspicious_rate": 0.0,
            "avg_model_confidence": 0.80,
            "avg_siem_confidence": 0.50,
            "tp_count": 0.0,
            "fp_count": 0.0,
            "fn_count": 0.0,
            "wrong_mitigation": 0.0,
            "mitigation_success": 0.0,
            "analyst_override": 0.0,
        }

        if self._kibana is None or not self._kibana.is_available():
            return self._fetch_metrics_from_local_log(defaults)

        try:
            return self._fetch_metrics_from_es(defaults)
        except Exception as exc:
            logger.warning(
                "[RL-OPTIMIZER] ES metrics fetch failed (%s) — using local fallback", exc
            )
            return self._fetch_metrics_from_local_log(defaults)

    def _fetch_metrics_from_es(self, defaults: dict[str, float]) -> dict[str, float]:
        """Query ands-alerts and confirmed_attack_history for recent stats."""
        since = (datetime.now(timezone.utc) - timedelta(minutes=self._window_minutes)).isoformat()
        client = self._kibana._client  # type: ignore[attr-defined]
        result = dict(defaults)

        # ── Query ands-alerts ─────────────────────────────────────────────────
        alerts_query: dict[str, Any] = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": since}}},
            "aggs": {
                "total":      {"value_count": {"field": "is_attack"}},
                "attacks":    {"filter": {"term": {"is_attack": True}}},
                "suspicious": {"filter": {"term": {"suspicious": True}}},
                "avg_conf":   {"avg": {"field": "confidence"}},
            },
        }
        try:
            resp = client.search(index="ands-alerts", body=alerts_query)
            aggs = resp.get("aggregations", {})
            total = int(aggs.get("total", {}).get("value", 0))
            attacks = int(aggs.get("attacks", {}).get("doc_count", 0))
            suspicious = int(aggs.get("suspicious", {}).get("doc_count", 0))
            benign = max(0, total - attacks - suspicious)
            avg_conf = float(aggs.get("avg_conf", {}).get("value") or 0.80)

            result["suspicious_rate"] = suspicious / total if total > 0 else 0.0
            result["avg_model_confidence"] = avg_conf
            result["fn_count"] = float(suspicious)  # proxy: suspicious might be missed attacks
        except Exception as exc:
            logger.debug("[RL-OPTIMIZER] ands-alerts query failed: %s", exc)

        # ── Query confirmed_attack_history ────────────────────────────────────
        history_query: dict[str, Any] = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": since}}},
            "aggs": {
                "tp":   {"filter": {"term": {"decision_source": "verification_confirmed"}}},
                "fp":   {"filter": {"term": {"severity": "info"}}},
                "avg_model_conf": {"avg": {"field": "model_confidence"}},
                "avg_siem_conf":  {"avg": {"field": "siem_confidence"}},
            },
        }
        try:
            resp = client.search(index="confirmed_attack_history", body=history_query)
            aggs = resp.get("aggregations", {})
            tp = int(aggs.get("tp", {}).get("doc_count", 0))
            fp = int(aggs.get("fp", {}).get("doc_count", 0))
            avg_model = float(aggs.get("avg_model_conf", {}).get("value") or result["avg_model_confidence"])
            avg_siem  = float(aggs.get("avg_siem_conf",  {}).get("value") or defaults["avg_siem_confidence"])

            total_history = tp + fp + result["fn_count"]
            result["tp_count"] = float(tp)
            result["fp_count"] = float(fp)
            result["fp_rate"] = fp / total_history if total_history > 0 else 0.0
            result["fn_rate"] = result["fn_count"] / total_history if total_history > 0 else 0.0
            result["avg_model_confidence"] = avg_model
            result["avg_siem_confidence"] = avg_siem
            result["mitigation_success"] = float(tp)
        except Exception as exc:
            logger.debug("[RL-OPTIMIZER] confirmed_attack_history query failed: %s", exc)

        return result

    def _fetch_metrics_from_local_log(self, defaults: dict[str, float]) -> dict[str, float]:
        """
        Fallback: parse logs/rl_decisions.jsonl if it exists.
        Each line is a JSON dict with keys: is_attack, suspicious, confidence,
        decision_source, severity (written by an optional local logger).
        """
        log_path = Path(__file__).resolve().parents[2] / "logs" / "rl_decisions.jsonl"
        if not log_path.exists():
            logger.debug("[RL-OPTIMIZER] No local decision log found — returning defaults")
            return dict(defaults)

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=self._window_minutes)
        records: list[dict] = []
        try:
            for line in log_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                ts_str = obj.get("timestamp") or obj.get("@timestamp", "")
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if ts < cutoff:
                        continue
                except Exception:
                    pass
                records.append(obj)
        except Exception as exc:
            logger.warning("[RL-OPTIMIZER] Failed to read local decision log: %s", exc)
            return dict(defaults)

        if not records:
            return dict(defaults)

        total = len(records)
        attacks = sum(1 for r in records if r.get("is_attack"))
        suspicious = sum(1 for r in records if r.get("suspicious"))
        tp = sum(1 for r in records if r.get("decision_source") == "verification_confirmed")
        fp = sum(1 for r in records if r.get("severity") == "info" and r.get("is_attack"))
        confs = [float(r["confidence"]) for r in records if "confidence" in r]
        avg_conf = sum(confs) / len(confs) if confs else 0.80

        total_h = tp + fp + suspicious
        return {
            **defaults,
            "suspicious_rate": suspicious / total if total > 0 else 0.0,
            "fp_rate": fp / total_h if total_h > 0 else 0.0,
            "fn_rate": suspicious / total_h if total_h > 0 else 0.0,
            "avg_model_confidence": avg_conf,
            "tp_count": float(tp),
            "fp_count": float(fp),
            "fn_count": float(suspicious),
            "mitigation_success": float(tp),
        }

    # ── State ─────────────────────────────────────────────────────────────────

    def _state_key(self, metrics: dict[str, float]) -> str:
        """Discretize metrics into a compact tuple key for the Q-table."""
        bins = (
            _bin(metrics["suspicious_rate"],      _BINS["suspicious_rate"]),
            _bin(metrics["fp_rate"],              _BINS["fp_rate"]),
            _bin(metrics["fn_rate"],              _BINS["fn_rate"]),
            _bin(metrics["avg_model_confidence"], _BINS["avg_model_confidence"]),
            _bin(metrics["avg_siem_confidence"],  _BINS["avg_siem_confidence"]),
        )
        return str(bins)

    # ── Reward ────────────────────────────────────────────────────────────────

    def _compute_reward(self, metrics: dict[str, float]) -> float:
        """
        reward = 5·TP − 8·FP − 10·FN − 4·wrong_mitigation
                 + 3·mitigation_success − 2·analyst_override
        """
        return (
            5.0  * metrics["tp_count"]
            - 8.0  * metrics["fp_count"]
            - 10.0 * metrics["fn_count"]
            - 4.0  * metrics["wrong_mitigation"]
            + 3.0  * metrics["mitigation_success"]
            - 2.0  * metrics["analyst_override"]
        )

    # ── Q-learning ────────────────────────────────────────────────────────────

    def _q_values(self, state: str) -> dict[int, float]:
        return self._qtable.setdefault(state, {a: 0.0 for a in range(N_ACTIONS)})

    def _choose_action(self, state: str) -> int:
        if random.random() < _EPSILON:
            return random.randint(0, N_ACTIONS - 1)
        q = self._q_values(state)
        return max(q, key=q.get)  # type: ignore[arg-type]

    def _update_q(
        self,
        prev_state: str,
        prev_action: int,
        reward: float,
        next_state: str,
    ) -> None:
        q_prev = self._q_values(prev_state)
        q_next = self._q_values(next_state)
        best_next = max(q_next.values())
        old = q_prev[prev_action]
        q_prev[prev_action] = old + _ALPHA * (reward + _GAMMA * best_next - old)

    # ── Action application ────────────────────────────────────────────────────

    @staticmethod
    def _action_name(action: int) -> str:
        names = [
            "model_high_confidence += 0.01",
            "model_high_confidence -= 0.01",
            "model_trust_floor     += 0.01",
            "model_trust_floor     -= 0.01",
            "siem_corroboration_min += 0.01",
            "siem_corroboration_min -= 0.01",
            "suspicious_escalate_count += 1",
            "suspicious_escalate_count -= 1",
            "no change",
        ]
        return names[action] if action < len(names) else "unknown"

    @staticmethod
    def _apply_action(thresholds: dict[str, Any], action: int) -> dict[str, Any]:
        """
        Mutate thresholds according to the chosen action, then clamp all values.
        Returns the modified dict (thresholds is modified in-place and returned).
        """
        if action == 0:
            thresholds["model_high_confidence"] += 0.01
        elif action == 1:
            thresholds["model_high_confidence"] -= 0.01
        elif action == 2:
            thresholds["model_trust_floor"] += 0.01
        elif action == 3:
            thresholds["model_trust_floor"] -= 0.01
        elif action == 4:
            thresholds["siem_corroboration_min"] += 0.01
        elif action == 5:
            thresholds["siem_corroboration_min"] -= 0.01
        elif action == 6:
            thresholds["suspicious_escalate_count"] += 1
        elif action == 7:
            thresholds["suspicious_escalate_count"] -= 1
        # action == 8: no change

        # Hard clamp — NEVER violated
        lo, hi = _BOUNDS["model_high_confidence"]
        thresholds["model_high_confidence"] = round(
            float(_clamp(thresholds["model_high_confidence"], lo, hi)), 4
        )
        lo, hi = _BOUNDS["model_trust_floor"]
        thresholds["model_trust_floor"] = round(
            float(_clamp(thresholds["model_trust_floor"], lo, hi)), 4
        )
        lo, hi = _BOUNDS["siem_corroboration_min"]
        thresholds["siem_corroboration_min"] = round(
            float(_clamp(thresholds["siem_corroboration_min"], lo, hi)), 4
        )
        lo, hi = _BOUNDS["suspicious_escalate_count"]
        thresholds["suspicious_escalate_count"] = int(
            _clamp(int(thresholds["suspicious_escalate_count"]), lo, hi)
        )
        return thresholds

    # ── YAML write ────────────────────────────────────────────────────────────

    @staticmethod
    def _write_yaml(thresholds: dict[str, Any]) -> None:
        """
        Merge updated threshold values into the existing YAML and write it back.
        Uses a temp-file + os.replace for an atomic write.
        """
        if not _YAML_PATH.exists():
            logger.error("[RL-OPTIMIZER] YAML not found at %s — cannot write", _YAML_PATH)
            return

        try:
            raw = yaml.safe_load(_YAML_PATH.read_text(encoding="utf-8")) or {}
        except Exception as exc:
            logger.error("[RL-OPTIMIZER] Failed to read YAML before write: %s", exc)
            return

        # Patch only the four RL-adaptive keys — leave everything else untouched
        dp = raw.setdefault("decision_policy", {})
        dp["model_high_confidence"]  = thresholds["model_high_confidence"]
        dp["model_trust_floor"]      = thresholds["model_trust_floor"]
        dp["siem_corroboration_min"] = thresholds["siem_corroboration_min"]

        ss = dp.setdefault("suspicious_state", {})
        ss["escalate_if_count"] = thresholds["suspicious_escalate_count"]

        tmp = _YAML_PATH.with_suffix(".yaml.tmp")
        try:
            tmp.write_text(
                yaml.dump(raw, default_flow_style=False, sort_keys=False),
                encoding="utf-8",
            )
            os.replace(tmp, _YAML_PATH)
        except Exception as exc:
            logger.error("[RL-OPTIMIZER] Failed to write YAML: %s", exc)
            tmp.unlink(missing_ok=True)
