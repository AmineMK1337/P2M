"""
src/db/history_store.py
───────────────────────
PostgreSQL persistence layer for the Intrusion Classification Agent.

Stores every classification result so future calls to fetch_ip_history
can detect repetition, escalation, and contradiction patterns.
"""

import os
import json
from datetime import datetime, timedelta
from typing import Optional

import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

# ─── Schema ───────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS classification_history (
    id                  SERIAL PRIMARY KEY,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Network identifiers
    src_ip              TEXT,
    dst_ip              TEXT,
    src_port            INTEGER,
    dst_port            INTEGER,
    protocol            TEXT,

    -- Model input (Signal 1)
    model_label         TEXT NOT NULL,
    model_confidence    FLOAT NOT NULL,

    -- Agent output (Signal 2)
    is_attack           BOOLEAN,
    attack_type         TEXT,
    confidence          INTEGER,
    severity            TEXT,
    history_signal      TEXT,
    is_multi_stage      BOOLEAN DEFAULT FALSE,
    mitre_technique_id  TEXT,
    mitre_tactic        TEXT,
    key_evidence        JSONB,
    reasoning           TEXT,

    -- Full flow stored for audit / downstream use
    flow_features       JSONB
);

CREATE INDEX IF NOT EXISTS idx_ch_src_ip    ON classification_history(src_ip);
CREATE INDEX IF NOT EXISTS idx_ch_timestamp ON classification_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_ch_is_attack ON classification_history(is_attack);
"""


def _conn():
    return psycopg2.connect(DATABASE_URL)


def init_db():
    """Create tables if they don't exist. Call once at startup."""
    with _conn() as conn:
        with conn.cursor() as cur:
            cur.execute(_SCHEMA)
        conn.commit()


# ─── Read ─────────────────────────────────────────────────────────────────────

def get_history_for_ip(
    src_ip: str,
    hours: int = 24,
    limit: int = 20,
) -> list[dict]:
    """Return recent classification records for a given source IP."""
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    with _conn() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT
                    timestamp, src_ip, dst_ip, protocol,
                    model_label, model_confidence,
                    is_attack, attack_type, confidence,
                    severity, history_signal, mitre_tactic
                FROM classification_history
                WHERE src_ip = %s AND timestamp >= %s
                ORDER BY timestamp DESC
                LIMIT %s
            """, (src_ip, cutoff, limit))
            return [dict(r) for r in cur.fetchall()]


# ─── Write ────────────────────────────────────────────────────────────────────

def store_classification(
    flow: dict,
    model_label: str,
    model_confidence: float,
    result,          # ClassificationResult — typed loosely to avoid circular import
) -> Optional[int]:
    """Persist a classification result. Returns the new row ID."""
    if not DATABASE_URL:
        return None  # DB not configured — skip silently

    try:
        with _conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO classification_history (
                        src_ip, dst_ip, src_port, dst_port, protocol,
                        model_label, model_confidence,
                        is_attack, attack_type, confidence, severity,
                        history_signal, is_multi_stage,
                        mitre_technique_id, mitre_tactic,
                        key_evidence, reasoning, flow_features
                    ) VALUES (
                        %(src_ip)s, %(dst_ip)s, %(src_port)s, %(dst_port)s, %(protocol)s,
                        %(model_label)s, %(model_confidence)s,
                        %(is_attack)s, %(attack_type)s, %(confidence)s, %(severity)s,
                        %(history_signal)s, %(is_multi_stage)s,
                        %(mitre_technique_id)s, %(mitre_tactic)s,
                        %(key_evidence)s, %(reasoning)s, %(flow_features)s
                    ) RETURNING id
                """, {
                    "src_ip":             flow.get("src_ip"),
                    "dst_ip":             flow.get("dst_ip"),
                    "src_port":           flow.get("src_port"),
                    "dst_port":           flow.get("dst_port"),
                    "protocol":           flow.get("protocol"),
                    "model_label":        model_label,
                    "model_confidence":   model_confidence,
                    "is_attack":          result.is_attack,
                    "attack_type":        result.attack_type,
                    "confidence":         result.confidence,
                    "severity":           result.severity,
                    "history_signal":     result.history_signal,
                    "is_multi_stage":     result.is_multi_stage,
                    "mitre_technique_id": result.mitre_technique_id,
                    "mitre_tactic":       result.mitre_tactic,
                    "key_evidence":       json.dumps(result.key_evidence),
                    "reasoning":          result.reasoning,
                    "flow_features":      json.dumps(flow),
                })
                row_id = cur.fetchone()[0]
            conn.commit()
        return row_id
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"DB store failed: {e}")
        return None
