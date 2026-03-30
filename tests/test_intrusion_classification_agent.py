"""Tests for the current ANDS classification agent implementation."""

from pathlib import Path

import pytest

import src.agents.classification_agent.agent as classification_module
from src.agents.classification_agent.agent import (
    DetectionClassificationAgent,
    FlowInputConfig,
    FusionEngine,
    get_flow_stream,
)
from src.agents.classification_agent.kibana_adapter import StubKibanaAdapter
from src.shared.schemas import FlowRecord


class _FakeModel:
    """Simple deterministic model stub for agent unit tests."""

    def __init__(self, _model_path: str, threshold_override=None):
        self.threshold = 0.42 if threshold_override is None else float(threshold_override)

    def predict(self, flow: FlowRecord):
        if str(flow.src_ip) == "10.10.10.10":
            return "Intrusion", 0.93, 0.99
        return "BENIGN", 0.88, 0.11


def test_get_flow_stream_csv_mode_reads_rows(tmp_path):
    csv_file = tmp_path / "flows.csv"
    csv_file.write_text("Src IP,Flow Duration\n1.2.3.4,123\n5.6.7.8,456\n", encoding="utf-8")

    config = FlowInputConfig(mode="csv", csv_path=str(csv_file))
    flows = list(get_flow_stream(config))

    assert len(flows) == 2
    assert flows[0].src_ip == "1.2.3.4"
    assert flows[1].src_ip == "5.6.7.8"
    assert flows[0].source == "csv"


def test_get_flow_stream_invalid_mode_raises():
    with pytest.raises(ValueError, match="mode must be one of"):
        list(get_flow_stream(FlowInputConfig(mode="invalid")))


def test_fusion_engine_prefers_model_without_siem_signal():
    fused, source = FusionEngine().fuse(model_confidence=0.77, siem_confidence=0.0, siem_alert_count=0)
    assert fused == 0.77
    assert source == "model"


def test_fusion_engine_prefers_siem_when_stronger():
    fused, source = FusionEngine().fuse(model_confidence=0.70, siem_confidence=0.92, siem_alert_count=2)
    assert fused == 0.92
    assert source == "siem"


def test_process_flow_attack_pushes_to_kibana_and_triggers_callback(monkeypatch):
    monkeypatch.setattr(classification_module, "PCAIntrusionModel", _FakeModel)

    kibana = StubKibanaAdapter(preset_alerts=[])
    callback_hits = []

    agent = DetectionClassificationAgent(
        model_path="unused-for-test.joblib",
        kibana=kibana,
        on_attack=lambda result: callback_hits.append(result.src_ip),
    )
    initial_alerts = len(kibana._alerts)

    flow = FlowRecord(features={"Src IP": "10.10.10.10", "Flow Duration": 1000}, source="test")
    result = agent.process_flow(flow)

    assert result.is_attack is True
    assert result.attack_type == "Intrusion"
    assert result.decision_source == "model"
    assert result.metadata["model_threshold"] == 0.42
    assert callback_hits == ["10.10.10.10"]
    assert len(kibana._alerts) == initial_alerts + 1


def test_process_flow_benign_skips_kibana_by_default(monkeypatch):
    monkeypatch.setattr(classification_module, "PCAIntrusionModel", _FakeModel)

    kibana = StubKibanaAdapter(preset_alerts=[])
    agent = DetectionClassificationAgent(model_path="unused-for-test.joblib", kibana=kibana)
    initial_alerts = len(kibana._alerts)

    flow = FlowRecord(features={"Src IP": "192.168.0.2", "Flow Duration": 10}, source="test")
    result = agent.process_flow(flow)

    assert result.is_attack is False
    assert result.attack_type == "BENIGN"
    assert len(kibana._alerts) == initial_alerts


def test_process_flow_benign_can_be_pushed_when_enabled(monkeypatch):
    monkeypatch.setattr(classification_module, "PCAIntrusionModel", _FakeModel)

    kibana = StubKibanaAdapter(preset_alerts=[])
    agent = DetectionClassificationAgent(
        model_path="unused-for-test.joblib",
        kibana=kibana,
        push_benign_to_kibana=True,
    )
    initial_alerts = len(kibana._alerts)

    flow = FlowRecord(features={"Src IP": "192.168.0.2", "Flow Duration": 10}, source="test")
    result = agent.process_flow(flow)

    assert result.is_attack is False
    assert len(kibana._alerts) == initial_alerts + 1


def test_run_processes_all_flows(monkeypatch, tmp_path):
    monkeypatch.setattr(classification_module, "PCAIntrusionModel", _FakeModel)

    csv_file = tmp_path / "batch.csv"
    csv_file.write_text("Src IP,Flow Duration\n10.10.10.10,500\n192.168.1.2,20\n", encoding="utf-8")

    agent = DetectionClassificationAgent(
        model_path="unused-for-test.joblib",
        kibana=StubKibanaAdapter(preset_alerts=[]),
    )

    results = agent.run(FlowInputConfig(mode="csv", csv_path=str(Path(csv_file))))

    assert len(results) == 2
    assert sum(1 for r in results if r.is_attack) == 1
