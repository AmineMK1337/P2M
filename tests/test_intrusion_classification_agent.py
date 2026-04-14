"""Tests for the current ANDS classification agent implementation."""

from pathlib import Path
import json

import numpy as np
import pytest

import src.agents.classification_agent.agent as classification_module
from src.agents.classification_agent.agent import (
    DetectionClassificationAgent,
    FlowInputConfig,
    FusionEngine,
    get_flow_stream,
)
from src.agents.classification_agent.kibana_adapter import StubKibanaAdapter
from src.shared.schemas import ClassificationResult, FlowRecord


class _IdentityScaler:
    def transform(self, x):
        return np.asarray(x, dtype=float)


class _ProjectionPCA:
    def transform(self, x):
        return np.asarray(x, dtype=float)

    def inverse_transform(self, x):
        # Force non-zero reconstruction error so test samples are attacks.
        return np.zeros_like(np.asarray(x, dtype=float))


class _AttackTypeModel:
    feature_names_in_ = np.array(["Flow Duration"], dtype=object)

    def predict(self, _x):
        return np.array(["DDoS"], dtype=object)


class _FakeModel:
    """Simple deterministic model stub for agent unit tests."""

    def __init__(self, _model_path: str, threshold_override=None):
        self.threshold = 0.42 if threshold_override is None else float(threshold_override)

    def predict(self, flow: FlowRecord):
        if str(flow.src_ip) == "10.10.10.10":
            return "Intrusion", 0.93, 0.99
        return "BENIGN", 0.88, 0.11


def test_get_flow_stream_csv_mode_reads_rows(tmp_path):
    csv_file = tmp_path / "test.csv"
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


def test_pca_intrusion_model_returns_specific_attack_type_from_bundle_model(monkeypatch):
    bundle = {
        "scaler": _IdentityScaler(),
        "pca": _ProjectionPCA(),
        "threshold": 0.5,
        "feature_columns": ["Flow Duration"],
        "attack_type_model": _AttackTypeModel(),
    }
    monkeypatch.setattr(classification_module.joblib, "load", lambda _path: bundle)

    model = classification_module.PCAIntrusionModel("unused.joblib")
    attack_type, confidence, score = model.predict(
        FlowRecord(features={"Flow Duration": 2.0}, source="test")
    )

    assert attack_type == "DDoS"
    assert score > model.threshold
    assert 0.5 <= confidence <= 1.0


def test_pca_intrusion_model_falls_back_to_flow_label_for_attack_type(monkeypatch):
    bundle = {
        "scaler": _IdentityScaler(),
        "pca": _ProjectionPCA(),
        "threshold": 0.5,
        "feature_columns": ["Flow Duration"],
    }
    monkeypatch.setattr(classification_module.joblib, "load", lambda _path: bundle)

    model = classification_module.PCAIntrusionModel("unused.joblib")
    attack_type, _, _ = model.predict(
        FlowRecord(features={"Flow Duration": 2.0, "Label": "PortScan"}, source="test")
    )

    assert attack_type == "PortScan"


def test_pca_intrusion_model_uses_attack_type_centroids(monkeypatch):
    bundle = {
        "scaler": _IdentityScaler(),
        "pca": _ProjectionPCA(),
        "threshold": 0.5,
        "feature_columns": ["Flow Duration"],
        "attack_type_centroids": {
            "DDoS": [10.0],
            "PortScan": [2.0],
        },
    }
    monkeypatch.setattr(classification_module.joblib, "load", lambda _path: bundle)

    model = classification_module.PCAIntrusionModel("unused.joblib")
    attack_type, _, _ = model.predict(
        FlowRecord(features={"Flow Duration": 2.0}, source="test")
    )

    assert attack_type == "PortScan"

def test_pca_intrusion_model_loads_centroids_from_sidecar(monkeypatch, tmp_path):
    model_path = tmp_path / "pca_intrusion_detector.joblib"
    model_path.write_bytes(b"stub")

    sidecar_path = model_path.with_suffix(".attack_type_centroids.json")
    sidecar_payload = {
        "attack_type_centroids": {
            "DDoS": [10.0],
            "PortScan": [2.0],
        },
        "attack_classes": ["DDoS", "PortScan"],
    }
    sidecar_path.write_text(json.dumps(sidecar_payload), encoding="utf-8")

    bundle = {
        "scaler": _IdentityScaler(),
        "pca": _ProjectionPCA(),
        "threshold": 0.5,
        "feature_columns": ["Flow Duration"],
    }
    monkeypatch.setattr(classification_module.joblib, "load", lambda _path: bundle)

    model = classification_module.PCAIntrusionModel(str(model_path))
    attack_type, _, _ = model.predict(
        FlowRecord(features={"Flow Duration": 2.0}, source="test")
    )

    assert attack_type == "PortScan"


def test_print_summary_includes_attack_type_ip_associations(capsys):
    results = [
        ClassificationResult(
            flow=FlowRecord(features={"Src IP": "10.0.0.1"}, source="test"),
            is_attack=True,
            attack_type="DDoS",
            confidence=0.99,
            model_confidence=0.99,
            siem_confidence=0.0,
            siem_alert_count=0,
            decision_source="model",
        ),
        ClassificationResult(
            flow=FlowRecord(features={"Src IP": "10.0.0.2"}, source="test"),
            is_attack=True,
            attack_type="PortScan",
            confidence=0.91,
            model_confidence=0.91,
            siem_confidence=0.0,
            siem_alert_count=0,
            decision_source="model",
        ),
        ClassificationResult(
            flow=FlowRecord(features={"Src IP": "192.168.1.5"}, source="test"),
            is_attack=False,
            attack_type="BENIGN",
            confidence=0.85,
            model_confidence=0.85,
            siem_confidence=0.0,
            siem_alert_count=0,
            decision_source="model",
        ),
    ]

    DetectionClassificationAgent._print_summary(results)
    out = capsys.readouterr().out

    assert "Attack Type -> Source IP(s)" in out
    assert "DDoS" in out and "10.0.0.1" in out
    assert "PortScan" in out and "10.0.0.2" in out
