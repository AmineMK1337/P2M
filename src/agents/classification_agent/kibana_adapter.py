"""
Kibana / Elasticsearch history adapter for the classification agent.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
import importlib
import json
import logging
import os
import re

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


@dataclass
class DatabaseSIEMConfig:
    """Configuration for SQL-backed SIEM history persistence."""

    url: str = "sqlite:///data/siem_history.db"
    table: str = "siem_alerts"
    max_alerts: int = 50


class KibanaAdapterBase(ABC):
    @abstractmethod
    def get_alerts(self, src_ip: str, attack_type: str, window_minutes: int) -> list[SIEMAlert]:
        """Retrieve recent alerts matching src_ip and attack_type."""

    @abstractmethod
    def push_alert(self, result) -> bool:
        """Write a ClassificationResult to Kibana."""

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


class DatabaseSIEMAdapter(KibanaAdapterBase):
    """Persistent SIEM history adapter supporting SQLite and PostgreSQL."""

    _VALID_TABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

    def __init__(self, config: DatabaseSIEMConfig):
        self.config = config
        self._table = self._validate_table_name(config.table)
        self._backend: str = ""
        self._sqlite_conn = None
        self._pg_module = None
        self._pg_dsn: Optional[str] = None
        self._connect()

    @classmethod
    def _validate_table_name(cls, table: str) -> str:
        cleaned = (table or "siem_alerts").strip()
        if not cls._VALID_TABLE_RE.match(cleaned):
            raise ValueError(
                f"Invalid table name '{table}'. Use letters, numbers, and underscores only."
            )
        return cleaned

    @staticmethod
    def _normalize_db_url(url: str) -> tuple[str, str]:
        raw = (url or "").strip()
        if not raw:
            return "sqlite", "data/siem_history.db"

        lower = raw.lower()
        if lower.startswith("sqlite:///"):
            return "sqlite", raw[len("sqlite:///") :]
        if lower.startswith("sqlite://"):
            return "sqlite", raw[len("sqlite://") :]

        if lower.startswith("postgres://"):
            return "postgresql", "postgresql://" + raw[len("postgres://") :]
        if lower.startswith("postgresql://"):
            return "postgresql", raw

        if "://" not in raw:
            return "sqlite", raw

        raise ValueError(
            "Unsupported SIEM DB URL. Use sqlite:///path/to.db or postgresql://user:pass@host:5432/db"
        )

    @staticmethod
    def _resolve_sqlite_path(path_value: str) -> str:
        candidate = (path_value or "").strip() or "data/siem_history.db"
        if candidate == ":memory:":
            return candidate

        # sqlite:///C:/... yields '/C:/...' on Windows; normalize to a drive path.
        if os.name == "nt" and len(candidate) >= 3 and candidate[0] == "/" and candidate[2] == ":":
            candidate = candidate[1:]

        resolved = os.path.abspath(os.path.expanduser(candidate))
        parent = os.path.dirname(resolved)
        if parent:
            os.makedirs(parent, exist_ok=True)
        return resolved

    def _connect(self) -> None:
        backend, location = self._normalize_db_url(self.config.url)
        self._backend = backend

        if backend == "sqlite":
            sqlite3 = importlib.import_module("sqlite3")
            sqlite_path = self._resolve_sqlite_path(location)
            self._sqlite_conn = sqlite3.connect(sqlite_path, check_same_thread=False)
            self._sqlite_conn.row_factory = sqlite3.Row
            self._ensure_sqlite_schema()
            logger.info("[SIEM:DB] Connected to SQLite at %s", sqlite_path)
            return

        if backend == "postgresql":
            self._pg_module = importlib.import_module("psycopg2")
            self._pg_dsn = location
            self._ensure_postgres_schema()
            logger.info("[SIEM:DB] Connected to PostgreSQL")
            return

        raise RuntimeError(f"Unsupported backend: {backend}")

    def _ensure_sqlite_schema(self) -> None:
        if not self._sqlite_conn:
            return

        self._sqlite_conn.executescript(
            f"""
            CREATE TABLE IF NOT EXISTS {self._table} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts_epoch REAL NOT NULL,
                ts_iso TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                is_attack INTEGER NOT NULL,
                decision_source TEXT,
                siem_alert_count INTEGER,
                raw_json TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_{self._table}_lookup
                ON {self._table}(src_ip, attack_type, ts_epoch DESC);

            CREATE INDEX IF NOT EXISTS idx_{self._table}_is_attack
                ON {self._table}(is_attack);
            """
        )
        self._sqlite_conn.commit()

    def _ensure_postgres_schema(self) -> None:
        if not self._pg_module or not self._pg_dsn:
            return

        with self._pg_module.connect(self._pg_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self._table} (
                        id SERIAL PRIMARY KEY,
                        ts_epoch DOUBLE PRECISION NOT NULL,
                        ts_iso TIMESTAMPTZ NOT NULL,
                        src_ip TEXT NOT NULL,
                        attack_type TEXT NOT NULL,
                        confidence DOUBLE PRECISION NOT NULL,
                        is_attack BOOLEAN NOT NULL,
                        decision_source TEXT,
                        siem_alert_count INTEGER,
                        raw_json JSONB
                    );
                    """
                )
                cur.execute(
                    f"""
                    CREATE INDEX IF NOT EXISTS idx_{self._table}_lookup
                    ON {self._table}(src_ip, attack_type, ts_epoch DESC);
                    """
                )
                cur.execute(
                    f"""
                    CREATE INDEX IF NOT EXISTS idx_{self._table}_is_attack
                    ON {self._table}(is_attack);
                    """
                )
            conn.commit()

    @staticmethod
    def _result_to_raw_doc(result: Any) -> dict[str, Any]:
        return {
            "src_ip": result.flow.src_ip or "unknown",
            "attack_type": result.attack_type,
            "confidence": float(result.confidence),
            "is_attack": bool(result.is_attack),
            "decision_source": getattr(result, "decision_source", "model"),
            "siem_alert_count": int(getattr(result, "siem_alert_count", 0)),
            "flow_source": getattr(result.flow, "source", "unknown"),
            "metadata": getattr(result, "metadata", {}),
            "reasoning": getattr(result, "reasoning", ""),
            "recommended_actions": getattr(result, "recommended_actions", []),
        }

    @staticmethod
    def _epoch_to_datetime(epoch: Any) -> datetime:
        try:
            return datetime.fromtimestamp(float(epoch), tz=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)

    def get_alerts(self, src_ip: str, attack_type: str, window_minutes: int) -> list[SIEMAlert]:
        cutoff_epoch = (datetime.now(timezone.utc) - timedelta(minutes=window_minutes)).timestamp()

        if self._backend == "sqlite":
            return self._get_alerts_sqlite(src_ip=src_ip, attack_type=attack_type, cutoff_epoch=cutoff_epoch)
        if self._backend == "postgresql":
            return self._get_alerts_postgres(src_ip=src_ip, attack_type=attack_type, cutoff_epoch=cutoff_epoch)

        return []

    def _get_alerts_sqlite(self, src_ip: str, attack_type: str, cutoff_epoch: float) -> list[SIEMAlert]:
        if not self._sqlite_conn:
            return []

        cur = self._sqlite_conn.execute(
            f"""
            SELECT src_ip, attack_type, confidence, ts_epoch, raw_json
            FROM {self._table}
            WHERE src_ip = ?
              AND attack_type = ?
              AND ts_epoch >= ?
              AND is_attack = 1
            ORDER BY ts_epoch DESC
            LIMIT ?
            """,
            (src_ip, attack_type, cutoff_epoch, int(self.config.max_alerts)),
        )
        rows = cur.fetchall()
        alerts: list[SIEMAlert] = []
        for row in rows:
            raw_payload = row[4]
            raw = {}
            if isinstance(raw_payload, str) and raw_payload:
                try:
                    raw = json.loads(raw_payload)
                except json.JSONDecodeError:
                    raw = {}

            alerts.append(
                SIEMAlert(
                    src_ip=str(row[0]),
                    attack_type=str(row[1]),
                    confidence=float(row[2]),
                    timestamp=self._epoch_to_datetime(row[3]),
                    raw=raw,
                )
            )
        return alerts

    def _get_alerts_postgres(self, src_ip: str, attack_type: str, cutoff_epoch: float) -> list[SIEMAlert]:
        if not self._pg_module or not self._pg_dsn:
            return []

        with self._pg_module.connect(self._pg_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT src_ip, attack_type, confidence, ts_epoch, raw_json
                    FROM {self._table}
                    WHERE src_ip = %s
                      AND attack_type = %s
                      AND ts_epoch >= %s
                      AND is_attack = TRUE
                    ORDER BY ts_epoch DESC
                    LIMIT %s
                    """,
                    (src_ip, attack_type, cutoff_epoch, int(self.config.max_alerts)),
                )
                rows = cur.fetchall()

        alerts: list[SIEMAlert] = []
        for row in rows:
            raw_payload = row[4]
            raw: dict[str, Any] = {}
            if isinstance(raw_payload, dict):
                raw = raw_payload
            elif isinstance(raw_payload, str) and raw_payload:
                try:
                    raw = json.loads(raw_payload)
                except json.JSONDecodeError:
                    raw = {}

            alerts.append(
                SIEMAlert(
                    src_ip=str(row[0]),
                    attack_type=str(row[1]),
                    confidence=float(row[2]),
                    timestamp=self._epoch_to_datetime(row[3]),
                    raw=raw,
                )
            )
        return alerts

    def push_alert(self, result) -> bool:
        now = datetime.now(timezone.utc)
        ts_epoch = now.timestamp()
        raw_doc = self._result_to_raw_doc(result)

        try:
            if self._backend == "sqlite" and self._sqlite_conn:
                self._sqlite_conn.execute(
                    f"""
                    INSERT INTO {self._table} (
                        ts_epoch, ts_iso, src_ip, attack_type,
                        confidence, is_attack, decision_source,
                        siem_alert_count, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ts_epoch,
                        now.isoformat(),
                        result.flow.src_ip or "unknown",
                        result.attack_type,
                        float(result.confidence),
                        1 if bool(result.is_attack) else 0,
                        getattr(result, "decision_source", "model"),
                        int(getattr(result, "siem_alert_count", 0)),
                        json.dumps(raw_doc),
                    ),
                )
                self._sqlite_conn.commit()
                return True

            if self._backend == "postgresql" and self._pg_module and self._pg_dsn:
                with self._pg_module.connect(self._pg_dsn) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            f"""
                            INSERT INTO {self._table} (
                                ts_epoch, ts_iso, src_ip, attack_type,
                                confidence, is_attack, decision_source,
                                siem_alert_count, raw_json
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                            """,
                            (
                                ts_epoch,
                                now,
                                result.flow.src_ip or "unknown",
                                result.attack_type,
                                float(result.confidence),
                                bool(result.is_attack),
                                getattr(result, "decision_source", "model"),
                                int(getattr(result, "siem_alert_count", 0)),
                                json.dumps(raw_doc),
                            ),
                        )
                    conn.commit()
                return True
        except Exception as exc:
            logger.error("[SIEM:DB] Push failed: %s", exc)
            return False

        return False

    def close(self) -> None:
        if self._sqlite_conn:
            self._sqlite_conn.close()
            self._sqlite_conn = None


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


def create_siem_adapter(
    backend: str = "auto",
    *,
    kibana_config: Optional[KibanaConfig] = None,
    database_config: Optional[DatabaseSIEMConfig] = None,
    preset_stub_alerts: Optional[list[SIEMAlert]] = None,
) -> KibanaAdapterBase:
    """Build an adapter from the selected backend with safe fallback to stub."""

    selected = (backend or "auto").strip().lower()
    db_cfg = database_config or DatabaseSIEMConfig()

    if selected == "auto":
        if kibana_config and kibana_config.host:
            selected = "elasticsearch"
        elif db_cfg.url:
            selected = "database"
        else:
            selected = "stub"

    if selected in {"elasticsearch", "kibana"}:
        if not kibana_config or not kibana_config.host:
            logger.warning("[SIEM] Elasticsearch selected without host; falling back to stub.")
            return StubKibanaAdapter(preset_alerts=preset_stub_alerts)

        adapter = KibanaAdapter(kibana_config)
        if adapter._client is None:  # noqa: SLF001 - checked for graceful fallback
            logger.warning("[SIEM] Elasticsearch unavailable; falling back to stub.")
            return StubKibanaAdapter(preset_alerts=preset_stub_alerts)
        return adapter

    if selected in {"database", "db", "sqlite", "postgresql", "postgres"}:
        db_url = db_cfg.url

        if selected == "sqlite" and (not db_url or db_url.lower().startswith(("postgres://", "postgresql://"))):
            db_url = "sqlite:///data/siem_history.db"

        if selected in {"postgres", "postgresql"} and db_url.lower().startswith("sqlite"):
            logger.warning("[SIEM] PostgreSQL backend requested but SQLite URL provided; using SQLite URL as-is.")

        try:
            return DatabaseSIEMAdapter(
                DatabaseSIEMConfig(
                    url=db_url,
                    table=db_cfg.table,
                    max_alerts=db_cfg.max_alerts,
                )
            )
        except Exception as exc:
            logger.error("[SIEM] Database adapter failed (%s); falling back to stub.", exc)
            return StubKibanaAdapter(preset_alerts=preset_stub_alerts)

    if selected == "stub":
        return StubKibanaAdapter(preset_alerts=preset_stub_alerts)

    raise ValueError(f"Unknown SIEM backend '{backend}'.")
