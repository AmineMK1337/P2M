"""
Kibana / Elasticsearch history adapter for the classification agent.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional
import importlib
import logging

try:
    from src.shared.schemas import SIEMAlert
except ModuleNotFoundError:
    from shared.schemas import SIEMAlert

logger = logging.getLogger(__name__)


@dataclass
class KibanaConfig:
    host: str = "http://localhost:9200"
    index: str = "ands-alerts"
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
        """Write a ClassificationResult to Kibana."""

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
        except Exception as exc:
            logger.error("[Kibana] Connection failed: %s", exc)
            self._client = None

    def _ensure_index(self):
        if not self._client:
            return

        try:
            exists = self._client.indices.exists(index=self.config.index)
            if exists:
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
                        {"term": {"src_ip.keyword": src_ip}},
                        {"term": {"attack_type.keyword": attack_type}},
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


class StubKibanaAdapter(KibanaAdapterBase):
    """Deterministic in-memory stub for development and tests."""

    def __init__(self, preset_alerts: Optional[list[SIEMAlert]] = None):
        self._alerts = preset_alerts or self._default_alerts()
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
            alert
            for alert in self._alerts
            if alert.src_ip == src_ip and alert.attack_type == attack_type and alert.timestamp >= cutoff
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
