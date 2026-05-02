"""
Kibana / Elasticsearch history adapter for the classification agent.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
import importlib
import logging
import uuid

try:
    from src.shared.schemas import SIEMAlert
except ModuleNotFoundError:
    from shared.schemas import SIEMAlert

logger = logging.getLogger(__name__)

FLOWS_INDEX = "network_live_flows"
ATTACK_HISTORY_INDEX = "confirmed_attack_history"


@dataclass
class KibanaConfig:
    host: str = "http://localhost:9200"
    index: str = "ands-alerts"
    flows_index: str = FLOWS_INDEX
    attack_history_index: str = ATTACK_HISTORY_INDEX
    username: Optional[str] = None
    password: Optional[str] = None
    verify_certs: bool = False
    window_minutes: int = 10
    max_alerts: int = 50


class KibanaAdapterBase(ABC):
    @abstractmethod
    def get_alerts(self, src_ip: str, attack_type: str, window_minutes: int) -> list[SIEMAlert]:
        """Retrieve recent alerts matching src_ip and attack_type."""

    @abstractmethod
    def push_alert(self, result) -> bool:
        """Write a ClassificationResult to the alerts index."""

    @abstractmethod
    def push_flow(self, result) -> bool:
        """Write every flow row (attack or benign) to network_live_flows."""

    @abstractmethod
    def push_confirmed_attack(self, result) -> bool:
        """Write a confirmed attack event to confirmed_attack_history."""

    @abstractmethod
    def get_ip_history(self, ip: str) -> dict[str, Any]:
        """Return attack history summary for an IP from confirmed_attack_history."""

    @abstractmethod
    def get_same_attack_type_count(self, ip: str, attack_type: str, days: int = 30) -> int:
        """Count past attacks from ip that match attack_type."""

    @abstractmethod
    def count_recent_ip_attacks(self, ip: str, days: int = 7) -> int:
        """Count attacks from ip in the last `days` days."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True when adapter backend is reachable/ready."""

    def close(self) -> None:
        """Allow adapters with connections to release resources."""
        return

    def corroboration_score(self, alerts: list[SIEMAlert]) -> float:
        if not alerts:
            return 0.0

        now = datetime.now(timezone.utc)
        weighted_sum = 0.0
        weight_total = 0.0

        for alert in alerts:
            age_seconds = (now - alert.timestamp).total_seconds()
            weight = 2.0 if age_seconds < 120 else 1.0
            weighted_sum += float(alert.confidence) * weight
            weight_total += weight

        if weight_total == 0:
            return 0.0
        return min(weighted_sum / weight_total, 1.0)


class KibanaAdapter(KibanaAdapterBase):
    """Production adapter using elasticsearch-py."""

    def __init__(self, config: KibanaConfig):
        self.config = config
        self._client = None
        self._connect()

    def _connect(self):
        try:
            elasticsearch_module = importlib.import_module("elasticsearch")
            Elasticsearch = elasticsearch_module.Elasticsearch
            kwargs = {"verify_certs": self.config.verify_certs}
            if self.config.username and self.config.password:
                kwargs["basic_auth"] = (self.config.username, self.config.password)
            self._client = Elasticsearch(self.config.host, **kwargs)
            info = self._client.info()
            logger.info("[Kibana] Connected to Elasticsearch: %s", info["version"]["number"])
            self._ensure_index()
            self._ensure_flow_index()
            self._ensure_attack_history_index()
        except Exception as exc:
            logger.error("[Kibana] Connection failed: %s", exc)
            self._client = None

    def _ensure_index(self):
        if not self._client:
            return
        try:
            if self._client.indices.exists(index=self.config.index):
                return
            body = {
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "src_ip": {"type": "keyword"},
                        "attack_type": {"type": "keyword"},
                        "confidence": {"type": "float"},
                        "is_attack": {"type": "boolean"},
                        "decision_source": {"type": "keyword"},
                        "siem_alert_count": {"type": "integer"},
                    }
                }
            }
            self._client.indices.create(index=self.config.index, body=body)
            logger.info("[Kibana] Created index: %s", self.config.index)
        except Exception as exc:
            logger.error("[Kibana] Failed to ensure index '%s': %s", self.config.index, exc)

    def _ensure_flow_index(self):
        if not self._client:
            return
        try:
            if self._client.indices.exists(index=self.config.flows_index):
                return
            body = {
                "mappings": {
                    "properties": {
                        "@timestamp":           {"type": "date"},
                        "src_ip":               {"type": "keyword"},
                        "dst_ip":               {"type": "keyword"},
                        "src_port":             {"type": "integer"},
                        "dst_port":             {"type": "integer"},
                        "protocol":             {"type": "keyword"},
                        "packets":              {"type": "long"},
                        "bytes":                {"type": "long"},
                        "duration":             {"type": "float"},
                        "model_prediction":     {"type": "keyword"},
                        "predicted_attack_type":{"type": "keyword"},
                        "confidence":           {"type": "float"},
                        "is_attack":            {"type": "boolean"},
                        "decision_source":      {"type": "keyword"},
                        "siem_alert_count":     {"type": "integer"},
                        "severity":             {"type": "keyword"},
                        "source":               {"type": "keyword"},
                    }
                }
            }
            self._client.indices.create(index=self.config.flows_index, body=body)
            logger.info("[Kibana] Created index: %s", self.config.flows_index)
        except Exception as exc:
            logger.error("[Kibana] Failed to ensure index '%s': %s", self.config.flows_index, exc)

    def _ensure_attack_history_index(self):
        if not self._client:
            return
        try:
            if self._client.indices.exists(index=self.config.attack_history_index):
                return
            body = {
                "mappings": {
                    "properties": {
                        "@timestamp":       {"type": "date"},
                        "src_ip":           {"type": "keyword"},
                        "attack_type":      {"type": "keyword"},
                        "severity":         {"type": "keyword"},
                        "confidence":       {"type": "float"},
                        "model_confidence": {"type": "float"},
                        "siem_confidence":  {"type": "float"},
                        "decision_source":  {"type": "keyword"},
                        "incident_id":      {"type": "keyword"},
                    }
                }
            }
            self._client.indices.create(index=self.config.attack_history_index, body=body)
            logger.info("[Kibana] Created index: %s", self.config.attack_history_index)
        except Exception as exc:
            logger.error("[Kibana] Failed to ensure index '%s': %s", self.config.attack_history_index, exc)

    def get_alerts(self, src_ip: str, attack_type: str, window_minutes: int) -> list[SIEMAlert]:
        if not self._client:
            logger.warning("[Kibana] No client, returning empty alert list.")
            return []

        since = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        query = {
            "size": self.config.max_alerts,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"src_ip": src_ip}},
                        {"term": {"attack_type": attack_type}},
                        {"range": {"@timestamp": {"gte": since.isoformat()}}},
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
        }

        try:
            resp = self._client.search(index=self.config.index, body=query)
            alerts: list[SIEMAlert] = []
            for hit in resp.get("hits", {}).get("hits", []):
                src = hit.get("_source", {})
                ts = src.get("@timestamp")
                timestamp = datetime.now(timezone.utc)
                if ts:
                    try:
                        timestamp = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                    except ValueError:
                        pass

                alerts.append(
                    SIEMAlert(
                        src_ip=src.get("src_ip", src_ip),
                        attack_type=src.get("attack_type", attack_type),
                        confidence=float(src.get("confidence", 0.5)),
                        timestamp=timestamp,
                        raw=src,
                    )
                )

            logger.info("[Kibana] Found %s corroborating alerts for %s/%s", len(alerts), src_ip, attack_type)
            return alerts
        except Exception as exc:
            logger.error("[Kibana] Query failed: %s", exc)
            return []

    def push_alert(self, result) -> bool:
        if not self._client:
            return False
        try:
            doc = {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "src_ip": result.flow.src_ip or "unknown",
                "attack_type": result.attack_type,
                "confidence": float(result.confidence),
                "is_attack": bool(result.is_attack),
                "decision_source": result.decision_source,
                "siem_alert_count": int(result.siem_alert_count),
            }
            self._client.index(index=self.config.index, document=doc)
            return True
        except Exception as exc:
            logger.error("[Kibana] Push failed: %s", exc)
            return False

    def push_flow(self, result) -> bool:
        if not self._client:
            return False
        try:
            f = result.flow.features
            doc: dict[str, Any] = {
                "@timestamp":            datetime.now(timezone.utc).isoformat(),
                "src_ip":                result.flow.src_ip or "unknown",
                "dst_ip":                self._feat(f, ("Dst IP", " Dst IP", "dst_ip", "Destination IP")),
                "src_port":              self._feat_int(f, ("Src Port", " Src Port", "src_port", "Source Port")),
                "dst_port":              self._feat_int(f, ("Dst Port", " Dst Port", "dst_port", "Destination Port")),
                "protocol":              self._feat(f, ("Protocol",)),
                "packets":               self._feat_int(f, ("Tot Fwd Pkts", "Total Fwd Packets", "packets")),
                "bytes":                 self._feat_int(f, ("TotLen Fwd Pkts", "Total Length of Fwd Packets", "bytes")),
                "duration":              self._feat_float(f, ("Flow Duration", "duration")),
                "model_prediction":      "attack" if result.is_attack else "benign",
                "predicted_attack_type": result.attack_type if result.is_attack else "",
                "confidence":            float(result.confidence),
                "is_attack":             bool(result.is_attack),
                "decision_source":       result.decision_source,
                "siem_alert_count":      int(result.siem_alert_count),
                "severity":              result.severity,
                "source":                result.flow.source,
            }
            self._client.index(index=self.config.flows_index, document=doc)
            return True
        except Exception as exc:
            logger.error("[Kibana] push_flow failed: %s", exc)
            return False

    def push_confirmed_attack(self, result) -> bool:
        if not self._client:
            return False
        try:
            doc: dict[str, Any] = {
                "@timestamp":       datetime.now(timezone.utc).isoformat(),
                "src_ip":           result.flow.src_ip or "unknown",
                "attack_type":      result.attack_type,
                "severity":         result.severity,
                "confidence":       float(result.confidence),
                "model_confidence": float(result.model_confidence),
                "siem_confidence":  float(result.siem_confidence),
                "decision_source":  result.decision_source,
                "incident_id":      f"INC_{uuid.uuid4().hex[:8].upper()}",
            }
            self._client.index(index=self.config.attack_history_index, document=doc)
            return True
        except Exception as exc:
            logger.error("[Kibana] push_confirmed_attack failed: %s", exc)
            return False

    def get_ip_history(self, ip: str) -> dict[str, Any]:
        empty: dict[str, Any] = {
            "previous_attack_count": 0,
            "first_seen": None,
            "last_seen": None,
            "attack_types": [],
            "recent_attack_count": 0,
        }
        if not self._client:
            return empty
        try:
            query = {
                "size": 0,
                "query": {"term": {"src_ip": ip}},
                "aggs": {
                    "count":       {"value_count": {"field": "src_ip"}},
                    "first_seen":  {"min": {"field": "@timestamp"}},
                    "last_seen":   {"max": {"field": "@timestamp"}},
                    "attack_types":{"terms": {"field": "attack_type", "size": 20}},
                    "recent": {
                        "filter": {"range": {"@timestamp": {"gte": f"now-7d/d"}}},
                        "aggs": {"count": {"value_count": {"field": "src_ip"}}},
                    },
                },
            }
            resp = self._client.search(index=self.config.attack_history_index, body=query)
            aggs = resp.get("aggregations", {})
            return {
                "previous_attack_count": int(aggs.get("count", {}).get("value", 0)),
                "first_seen":            aggs.get("first_seen", {}).get("value_as_string"),
                "last_seen":             aggs.get("last_seen", {}).get("value_as_string"),
                "attack_types":          [b["key"] for b in aggs.get("attack_types", {}).get("buckets", [])],
                "recent_attack_count":   int(aggs.get("recent", {}).get("count", {}).get("value", 0)),
            }
        except Exception as exc:
            logger.error("[Kibana] get_ip_history failed for %s: %s", ip, exc)
            return empty

    def get_same_attack_type_count(self, ip: str, attack_type: str, days: int = 30) -> int:
        if not self._client:
            return 0
        try:
            query = {
                "size": 0,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"src_ip": ip}},
                            {"term": {"attack_type": attack_type}},
                            {"range": {"@timestamp": {"gte": f"now-{days}d/d"}}},
                        ]
                    }
                },
                "aggs": {"count": {"value_count": {"field": "src_ip"}}},
            }
            resp = self._client.search(index=self.config.attack_history_index, body=query)
            return int(resp.get("aggregations", {}).get("count", {}).get("value", 0))
        except Exception as exc:
            logger.error("[Kibana] get_same_attack_type_count failed for %s/%s: %s", ip, attack_type, exc)
            return 0

    def count_recent_ip_attacks(self, ip: str, days: int = 7) -> int:
        if not self._client:
            return 0
        try:
            query = {
                "size": 0,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"src_ip": ip}},
                            {"range": {"@timestamp": {"gte": f"now-{days}d/d"}}},
                        ]
                    }
                },
                "aggs": {"count": {"value_count": {"field": "src_ip"}}},
            }
            resp = self._client.search(index=self.config.attack_history_index, body=query)
            return int(resp.get("aggregations", {}).get("count", {}).get("value", 0))
        except Exception as exc:
            logger.error("[Kibana] count_recent_ip_attacks failed for %s: %s", ip, exc)
            return 0

    @staticmethod
    def _feat(features: dict, keys: tuple) -> Optional[str]:
        for k in keys:
            if k in features and features[k] is not None:
                return str(features[k])
        return None

    @staticmethod
    def _feat_int(features: dict, keys: tuple) -> Optional[int]:
        for k in keys:
            if k in features and features[k] is not None:
                try:
                    return int(float(features[k]))
                except (ValueError, TypeError):
                    pass
        return None

    @staticmethod
    def _feat_float(features: dict, keys: tuple) -> Optional[float]:
        for k in keys:
            if k in features and features[k] is not None:
                try:
                    return float(features[k])
                except (ValueError, TypeError):
                    pass
        return None

    def is_available(self) -> bool:
        return self._client is not None


class StubKibanaAdapter(KibanaAdapterBase):
    """Deterministic in-memory stub for development and tests."""

    def __init__(self, preset_alerts: Optional[list[SIEMAlert]] = None):
        self._alerts = preset_alerts or self._default_alerts()
        self._flows: list[dict[str, Any]] = []
        self._attack_history: list[dict[str, Any]] = []
        logger.info("[Kibana] Using StubKibanaAdapter.")

    @staticmethod
    def _default_alerts() -> list[SIEMAlert]:
        now = datetime.now(timezone.utc)
        return [
            SIEMAlert("192.168.1.10", "Intrusion", 0.91, now - timedelta(minutes=2)),
            SIEMAlert("192.168.1.10", "Intrusion", 0.87, now - timedelta(minutes=5)),
            SIEMAlert("10.0.0.55", "Intrusion", 0.82, now - timedelta(minutes=1)),
        ]

    def get_alerts(self, src_ip: str, attack_type: str, window_minutes: int) -> list[SIEMAlert]:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        matches = [
            a for a in self._alerts
            if a.src_ip == src_ip and a.attack_type == attack_type and a.timestamp >= cutoff
        ]
        logger.info("[Kibana:Stub] %s match(es) for %s/%s", len(matches), src_ip, attack_type)
        return matches

    def push_alert(self, result) -> bool:
        self._alerts.append(
            SIEMAlert(
                src_ip=result.flow.src_ip or "unknown",
                attack_type=result.attack_type,
                confidence=float(result.confidence),
                timestamp=datetime.now(timezone.utc),
            )
        )
        return True

    def push_flow(self, result) -> bool:
        self._flows.append({
            "@timestamp":            datetime.now(timezone.utc).isoformat(),
            "src_ip":                result.flow.src_ip or "unknown",
            "model_prediction":      "attack" if result.is_attack else "benign",
            "predicted_attack_type": result.attack_type if result.is_attack else "",
            "confidence":            float(result.confidence),
            "is_attack":             bool(result.is_attack),
        })
        return True

    def push_confirmed_attack(self, result) -> bool:
        self._attack_history.append({
            "@timestamp":   datetime.now(timezone.utc).isoformat(),
            "src_ip":       result.flow.src_ip or "unknown",
            "attack_type":  result.attack_type,
            "severity":     result.severity,
            "confidence":   float(result.confidence),
            "incident_id":  f"INC_{uuid.uuid4().hex[:8].upper()}",
        })
        return True

    def get_ip_history(self, ip: str) -> dict[str, Any]:
        records = [r for r in self._attack_history if r["src_ip"] == ip]
        if not records:
            return {"previous_attack_count": 0, "first_seen": None, "last_seen": None,
                    "attack_types": [], "recent_attack_count": 0}
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        types = list({r["attack_type"] for r in records})
        recent = sum(1 for r in records if r["@timestamp"] >= cutoff.isoformat())
        timestamps = sorted(r["@timestamp"] for r in records)
        return {
            "previous_attack_count": len(records),
            "first_seen":            timestamps[0],
            "last_seen":             timestamps[-1],
            "attack_types":          types,
            "recent_attack_count":   recent,
        }

    def get_same_attack_type_count(self, ip: str, attack_type: str, days: int = 30) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        return sum(
            1 for r in self._attack_history
            if r["src_ip"] == ip and r["attack_type"] == attack_type and r["@timestamp"] >= cutoff
        )

    def count_recent_ip_attacks(self, ip: str, days: int = 7) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        return sum(
            1 for r in self._attack_history
            if r["src_ip"] == ip and r["@timestamp"] >= cutoff
        )

    def is_available(self) -> bool:
        return True
