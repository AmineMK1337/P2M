"""Persistence tests for SIEM adapters."""

from types import SimpleNamespace

import pytest

from src.agents.classification_agent.kibana_adapter import (
    DatabaseSIEMAdapter,
    DatabaseSIEMConfig,
    create_siem_adapter,
)
from src.shared.schemas import FlowRecord


def _fake_result(
    src_ip: str = "1.2.3.4",
    attack_type: str = "DDoS",
    confidence: float = 0.91,
):
    flow = FlowRecord(features={"Src IP": src_ip}, source="test")
    return SimpleNamespace(
        flow=flow,
        attack_type=attack_type,
        confidence=confidence,
        is_attack=True,
        decision_source="model",
        siem_alert_count=0,
        metadata={},
        reasoning="test",
        recommended_actions=["block_immediately"],
    )


def test_database_siem_adapter_sqlite_persists_across_instances(tmp_path):
    db_path = tmp_path / "siem_history.db"
    config = DatabaseSIEMConfig(
        url=f"sqlite:///{db_path}",
        table="siem_alerts",
        max_alerts=10,
    )

    writer = DatabaseSIEMAdapter(config)
    assert writer.push_alert(_fake_result()) is True
    writer.close()

    reader = DatabaseSIEMAdapter(config)
    alerts = reader.get_alerts(src_ip="1.2.3.4", attack_type="DDoS", window_minutes=60)
    reader.close()

    assert len(alerts) == 1
    assert alerts[0].src_ip == "1.2.3.4"
    assert alerts[0].attack_type == "DDoS"
    assert alerts[0].confidence == pytest.approx(0.91)


def test_create_siem_adapter_auto_uses_database_when_configured(tmp_path):
    db_path = tmp_path / "auto_siem.db"

    adapter = create_siem_adapter(
        backend="auto",
        database_config=DatabaseSIEMConfig(
            url=f"sqlite:///{db_path}",
            table="siem_alerts",
            max_alerts=5,
        ),
        preset_stub_alerts=[],
    )

    try:
        assert isinstance(adapter, DatabaseSIEMAdapter)
    finally:
        adapter.close()
