"""
Unified Classification Agent for ANDS.
Combines flow ingestion (former agent1) and fused decision logic.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Optional
import logging

import joblib
import numpy as np
import pandas as pd

try:
    from src.agents.classification_agent.kibana_adapter import KibanaAdapterBase
    from src.shared.schemas import ClassificationResult, FlowRecord
except ModuleNotFoundError:
    from agents.classification_agent.kibana_adapter import KibanaAdapterBase
    from shared.schemas import ClassificationResult, FlowRecord

logger = logging.getLogger(__name__)


@dataclass
class FlowInputConfig:
    mode: str = "csv"
    csv_path: str = "data/flows.csv"
    watch_dir: str = "data/cicflowmeter_out"


def _iter_csv(path: Path, source: str) -> Iterator[FlowRecord]:
    if not path.exists():
        raise FileNotFoundError(f"Flow input file not found: {path}")

    # Some captures are exported as Excel files but keep a .csv extension.
    # XLSX files are ZIP containers and start with the PK signature.
    with path.open("rb") as fh:
        signature = fh.read(4)

    if signature == b"PK\x03\x04":
        df = pd.read_excel(path)
        logger.warning("[ClassificationAgent] Input file is XLSX content with .csv name, loaded as Excel: %s", path)
    else:
        last_error: Optional[Exception] = None
        for encoding in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
            try:
                df = pd.read_csv(path, encoding=encoding)
                if encoding != "utf-8":
                    logger.warning("[ClassificationAgent] Loaded CSV with fallback encoding '%s': %s", encoding, path)
                break
            except UnicodeDecodeError as exc:
                last_error = exc
            except pd.errors.ParserError:
                # Fall back to delimiter auto-detection for irregular CSV exports.
                try:
                    df = pd.read_csv(path, encoding=encoding, sep=None, engine="python")
                    logger.warning("[ClassificationAgent] Loaded CSV with auto-detected delimiter and encoding '%s': %s", encoding, path)
                    break
                except Exception as exc:
                    last_error = exc
        else:
            raise ValueError(
                "Could not parse input file as CSV. "
                f"Tried encodings utf-8, utf-8-sig, cp1252, latin-1 and delimiter auto-detection: {path}. "
                f"Last error: {last_error}"
            )

    for _, row in df.iterrows():
        yield FlowRecord(features=row.to_dict(), source=source, raw_row=row)


def get_flow_stream(config: FlowInputConfig) -> Iterator[FlowRecord]:
    mode = (config.mode or "csv").lower().strip()

    if mode == "csv":
        yield from _iter_csv(Path(config.csv_path), source="csv")
        return

    if mode == "cicflowmeter":
        watch = Path(config.watch_dir)
        if not watch.exists():
            raise FileNotFoundError(f"Watch directory not found: {watch}")

        for csv_file in sorted(watch.glob("*.csv")):
            yield from _iter_csv(csv_file, source="cicflowmeter")
        return

    raise ValueError("mode must be one of: csv, cicflowmeter")


class PCAIntrusionModel:
    """
    Wrapper around deployments/models/pca_intrusion_detector.joblib.

    The bundle is expected to contain scaler, pca, threshold and optional feature_columns.
    It is an anomaly detector where:
    - 1 means benign
    - -1 means intrusion
    """

    def __init__(self, model_path: str, threshold_override: Optional[float] = None):
        self.model_path = Path(model_path)
        logger.info("[ClassificationAgent] Loading PCA bundle from %s", self.model_path)
        bundle = joblib.load(self.model_path)

        required = ("scaler", "pca", "threshold")
        missing = [k for k in required if k not in bundle]
        if missing:
            raise ValueError(f"Invalid model bundle, missing keys: {missing}")

        self.scaler = bundle["scaler"]
        self.pca = bundle["pca"]
        bundle_threshold = float(bundle["threshold"])
        self.threshold = float(threshold_override) if threshold_override is not None else bundle_threshold
        if threshold_override is not None:
            logger.warning(
                "[ClassificationAgent] Overriding model threshold from %.6f to %.6f",
                bundle_threshold,
                self.threshold,
            )
        self.feature_columns = bundle.get("feature_columns")

    @staticmethod
    def _anomaly_scores(original: np.ndarray, reconstructed: np.ndarray) -> np.ndarray:
        return np.sum((original - reconstructed) ** 2, axis=1)

    def _prepare(self, flow: FlowRecord) -> pd.DataFrame:
        df = flow.to_dataframe()

        if self.feature_columns:
            for col in self.feature_columns:
                if col not in df.columns:
                    df[col] = 0
            df = df[self.feature_columns]

        df = df.apply(pd.to_numeric, errors="coerce").fillna(0)
        return df

    def predict(self, flow: FlowRecord) -> tuple[str, float, float]:
        """
        Returns (attack_type, model_confidence, score).
        attack_type is BENIGN or Intrusion.
        """
        X_df = self._prepare(flow)
        x_scaled = self.scaler.transform(X_df)
        x_pca = self.pca.transform(x_scaled)
        x_reconstructed = self.pca.inverse_transform(x_pca)
        score = float(self._anomaly_scores(x_scaled, x_reconstructed)[0])

        is_benign = score < self.threshold
        attack_type = "BENIGN" if is_benign else "Intrusion"

        eps = 1e-9
        if is_benign:
            benign_ratio = max(0.0, min(1.0, 1.0 - (score / (self.threshold + eps))))
            confidence = 0.5 + 0.5 * benign_ratio
        else:
            attack_ratio = max(0.0, min(1.0, (score - self.threshold) / (self.threshold + eps)))
            confidence = 0.5 + 0.5 * attack_ratio

        return attack_type, float(confidence), score


class FusionEngine:
    def fuse(self, model_confidence: float, siem_confidence: float, siem_alert_count: int) -> tuple[float, str]:
        if siem_alert_count == 0 or siem_confidence == 0.0:
            return model_confidence, "model"

        if model_confidence >= siem_confidence:
            return model_confidence, "model+siem"
        return siem_confidence, "siem"


class ReasoningEngine:
    """Generates human-readable reasoning for classification decisions."""

    @staticmethod
    def generate_reasoning(
        is_attack: bool,
        attack_type: str,
        confidence: float,
        model_confidence: float,
        siem_confidence: float,
        siem_alert_count: int,
        anomaly_score: float,
        threshold: float,
        decision_source: str,
    ) -> tuple[str, dict[str, Any]]:
        """
        Generates a reasoning explanation and detailed breakdown.
        Returns (reasoning_text, reasoning_details_dict).
        """
        details: dict[str, Any] = {
            "decision": "attack" if is_attack else "benign",
            "confidence_score": round(confidence, 3),
            "decision_source": decision_source,
        }

        if is_attack:
            if decision_source == "model":
                reasoning = (
                    f"Classified as {attack_type} (confidence: {confidence:.1%}) based on PCA anomaly detection. "
                    f"Anomaly score {anomaly_score:.4f} exceeds threshold {threshold:.4f} by "
                    f"{((anomaly_score - threshold) / threshold * 100):.1f}%, indicating behavioral deviation from normal traffic."
                )
                details["anomaly_breakdown"] = {
                    "score": round(anomaly_score, 4),
                    "threshold": round(threshold, 4),
                    "deviation_percent": round(((anomaly_score - threshold) / threshold * 100), 1),
                }
            elif decision_source == "model+siem":
                reasoning = (
                    f"Classified as {attack_type} (confidence: {confidence:.1%}). "
                    f"Model signals attack with {model_confidence:.1%} confidence (anomaly score: {anomaly_score:.4f}). "
                    f"SIEM corroborates with {siem_alert_count} recent alert(s) matching this attack type and source ({siem_confidence:.1%} confidence)."
                )
                details["model_signal"] = round(model_confidence, 3)
                details["siem_signal"] = {
                    "confidence": round(siem_confidence, 3),
                    "recent_alerts": siem_alert_count,
                }
            else:  # "siem"
                reasoning = (
                    f"Re-classified as {attack_type} based on SIEM historical context ({siem_confidence:.1%} confidence, {siem_alert_count} recent alerts). "
                    f"Model had lower confidence, but SIEM history shows this source repeatedly flagged for same attack type."
                )
                details["siem_override"] = {
                    "confidence": round(siem_confidence, 3),
                    "alert_count": siem_alert_count,
                }
        else:
            reasoning = (
                f"Classified as {attack_type} (confidence: {confidence:.1%}). "
                f"Anomaly score {anomaly_score:.4f} is within normal range (threshold: {threshold:.4f}). "
                f"Traffic patterns are consistent with benign network activity."
            )
            details["anomaly_breakdown"] = {
                "score": round(anomaly_score, 4),
                "threshold": round(threshold, 4),
                "margin_to_threshold": round((threshold - anomaly_score), 4),
            }

        return reasoning, details

    @staticmethod
    def recommend_actions(is_attack: bool, attack_type: str, confidence: float) -> list[str]:
        """
        Suggests mitigation actions based on classification result.
        """
        actions: list[str] = []

        if not is_attack:
            return ["monitor_only"]

        # High confidence attacks — take immediate action
        if confidence >= 0.75:
            actions.append("block_immediately")
            actions.append("log_for_investigation")
        elif confidence >= 0.6:
            actions.append("rate_limit")
            actions.append("log_for_investigation")
        else:
            actions.append("monitor_closely")
            actions.append("log_for_investigation")

        # Attack-specific recommendations
        attack_lower = (attack_type or "").lower().strip()
        if "ddos" in attack_lower or "syn" in attack_lower:
            actions.append("enable_syn_flood_protection")
            actions.append("increase_connection_limits")
        elif "portscan" in attack_lower or "port scan" in attack_lower:
            actions.append("block_scanner")
            actions.append("enable_port_scanning_alerts")
        elif "bruteforce" in attack_lower or "brute force" in attack_lower:
            actions.append("enforce_rate_limiting_on_auth")
            actions.append("enable_account_lockout")
        elif "web attack" in attack_lower:
            actions.append("enable_waf")
            actions.append("sanitize_inputs")
        elif "botnet" in attack_lower:
            actions.append("block_permanently")
            actions.append("threat_intelligence_update")
        elif "infiltration" in attack_lower:
            actions.append("isolate_host")
            actions.append("enable_full_packet_capture")

        return actions


class DetectionClassificationAgent:
    """Unified classification agent that ingests flows and performs fused decisions."""

    def __init__(
        self,
        model_path: str,
        kibana: KibanaAdapterBase,
        on_attack: Optional[Callable[[ClassificationResult], None]] = None,
        threshold: float = 0.5,
        kibana_window_minutes: int = 10,
        model_threshold_override: Optional[float] = None,
        push_benign_to_kibana: bool = False,
    ):
        self.model = PCAIntrusionModel(model_path, threshold_override=model_threshold_override)
        self.kibana = kibana
        self.fusion = FusionEngine()
        self.reasoning = ReasoningEngine()
        self.on_attack = on_attack
        self.threshold = float(threshold)
        self.kibana_window_minutes = int(kibana_window_minutes)
        self.push_benign_to_kibana = push_benign_to_kibana

    def process_flow(self, flow: FlowRecord) -> ClassificationResult:
        attack_type, model_conf, anomaly_score = self.model.predict(flow)
        model_flags_attack = attack_type != "BENIGN"

        # Keep final verdict identical to model output (BENIGN vs Intrusion).
        siem_conf = 0.0
        siem_count = 0
        fused_conf = model_conf
        decision_source = "model"
        is_attack = model_flags_attack

        # Generate reasoning
        reasoning_text, reasoning_details = self.reasoning.generate_reasoning(
            is_attack=is_attack,
            attack_type=attack_type if is_attack else "BENIGN",
            confidence=fused_conf,
            model_confidence=model_conf,
            siem_confidence=siem_conf,
            siem_alert_count=siem_count,
            anomaly_score=anomaly_score,
            threshold=self.model.threshold,
            decision_source=decision_source,
        )

        # Generate recommended actions
        recommended_actions = self.reasoning.recommend_actions(
            is_attack=is_attack,
            attack_type=attack_type if is_attack else "BENIGN",
            confidence=fused_conf,
        )

        result = ClassificationResult(
            flow=flow,
            is_attack=is_attack,
            attack_type=attack_type if is_attack else "BENIGN",
            confidence=fused_conf,
            model_confidence=model_conf,
            siem_confidence=siem_conf,
            siem_alert_count=siem_count,
            decision_source=decision_source,
            reasoning=reasoning_text,
            recommended_actions=recommended_actions,
            reasoning_details=reasoning_details,
            metadata={
                "threshold": self.threshold,
                "model_threshold": self.model.threshold,
                "anomaly_score": anomaly_score,
            },
        )

        self._log(result)
        if result.is_attack or self.push_benign_to_kibana:
            self.kibana.push_alert(result)

        if result.is_attack and self.on_attack:
            self.on_attack(result)

        return result

    def run(self, input_config: FlowInputConfig) -> list[ClassificationResult]:
        logger.info("[ClassificationAgent] Starting in '%s' mode", input_config.mode)
        results: list[ClassificationResult] = []
        for flow in get_flow_stream(input_config):
            results.append(self.process_flow(flow))
        self._print_summary(results)
        return results

    def _log(self, result: ClassificationResult):
        if result.is_attack:
            logger.warning(
                "[ClassificationAgent] ATTACK type=%s fused=%.3f model=%.3f siem=%.3f alerts=%s source=%s ip=%s\n"
                "  Reasoning: %s\n"
                "  Recommended Actions: %s",
                result.attack_type,
                result.confidence,
                result.model_confidence,
                result.siem_confidence,
                result.siem_alert_count,
                result.decision_source,
                result.flow.src_ip,
                result.reasoning,
                ", ".join(result.recommended_actions),
            )
        else:
            logger.info(
                "[ClassificationAgent] BENIGN conf=%.3f ip=%s\n  Reasoning: %s",
                result.confidence,
                result.flow.src_ip,
                result.reasoning,
            )

    @staticmethod
    def _print_summary(results: list[ClassificationResult]):
        attacks = [r for r in results if r.is_attack]
        print("\n" + "=" * 55)
        print("  Classification Agent - Summary")
        print("=" * 55)
        print(f"  Total flows   : {len(results)}")
        print(f"  Attacks       : {len(attacks)}")
        print(f"  Benign        : {len(results) - len(attacks)}")
        print("=" * 55 + "\n")
