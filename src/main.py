"""
ANDS - Unified Classification Agent entrypoint.

Examples:
  python -m src.main --mode csv --csv data/flows.csv
  python -m src.main --mode cicflowmeter --watch data/cicflowmeter_out
"""

import argparse
import logging
import os
from pathlib import Path

try:
	from src.agents.classification_agent.agent import FlowInputConfig, DetectionClassificationAgent
	from src.agents.classification_agent.kibana_adapter import (
		KibanaAdapter,
		KibanaConfig,
	)
	from src.agents.mitigation_agent.agent import MitigationAgent
except ModuleNotFoundError:
	from agents.classification_agent.agent import FlowInputConfig, DetectionClassificationAgent
	from agents.classification_agent.kibana_adapter import (
		KibanaAdapter,
		KibanaConfig,
	)
	from agents.mitigation_agent.agent import MitigationAgent


logging.basicConfig(
	level=logging.INFO,
	format="%(asctime)s [%(levelname)s] %(message)s",
	datefmt="%H:%M:%S",
)


def _default_model_path() -> str:
	return str(Path(__file__).resolve().parents[1] / "deployments" / "models" / "pca_intrusion_detector.joblib")


def _env_bool(name: str, default: bool = False) -> bool:
	value = os.getenv(name)
	if value is None:
		return default
	return value.strip().lower() in {"1", "true", "yes", "on"}


# Dummy forward removed since we use MitigationAgent explicitly

def parse_args():
	parser = argparse.ArgumentParser(description="ANDS Classification Agent")
	parser.add_argument("--mode", choices=["csv", "cicflowmeter"], default="csv")
	parser.add_argument("--csv", default="data/flows.csv")
	parser.add_argument("--watch", default="data/cicflowmeter_out")
	parser.add_argument("--model", default=_default_model_path())
	parser.add_argument("--model-threshold", type=float, default=None, help="Override PCA anomaly threshold from model bundle")
	parser.add_argument("--threshold", type=float, default=0.5)
	parser.add_argument("--kibana-host", default=os.getenv("KIBANA_HOST", "http://localhost:9200"), help="Elasticsearch host for SIEM corroboration")
	parser.add_argument("--kibana-index", default=os.getenv("KIBANA_INDEX", "ands-alerts"), help="Elasticsearch index name")
	parser.add_argument("--kibana-user", default=os.getenv("KIBANA_USER"))
	parser.add_argument("--kibana-pass", default=os.getenv("KIBANA_PASS"))
	parser.add_argument(
		"--kibana-verify-certs",
		action="store_true",
		default=_env_bool("KIBANA_VERIFY_CERTS", False),
		help="Enable TLS certificate verification",
	)
	parser.add_argument("--siem-max-alerts", type=int, default=int(os.getenv("SIEM_MAX_ALERTS", "50")))
	parser.add_argument("--kibana-save-all", action="store_true", default=_env_bool("KIBANA_SAVE_ALL", False), help="Save both benign and attack flows to SIEM storage (default saves attacks only)")
	parser.add_argument("--window", type=int, default=int(os.getenv("SIEM_WINDOW_MINUTES", "10")), help="SIEM look-back window (minutes)")
	parser.add_argument("--use-siem-history", dest="use_siem_history", action="store_true", default=_env_bool("USE_SIEM_HISTORY", True), help="Enable SIEM historical corroboration for fusion")
	parser.add_argument("--disable-siem-history", dest="use_siem_history", action="store_false", help="Disable SIEM historical corroboration")
	return parser.parse_args()


def _build_kibana_or_raise(args):
	host = (args.kibana_host or "").strip()
	if not host:
		raise RuntimeError("KIBANA_HOST is required for SIEM history fusion.")

	adapter = KibanaAdapter(
		KibanaConfig(
			host=host,
			index=args.kibana_index,
			username=args.kibana_user,
			password=args.kibana_pass,
			verify_certs=args.kibana_verify_certs,
			max_alerts=args.siem_max_alerts,
		)
	)
	if not adapter.is_available():
		raise RuntimeError(
			f"Could not connect to Elasticsearch at {host}. "
			"Start Elasticsearch/Kibana or update KIBANA_HOST credentials."
		)
	return adapter


def main():
	args = parse_args()
	kibana = _build_kibana_or_raise(args)
	print(f"[main] SIEM backend: {kibana.__class__.__name__}")

	input_config = FlowInputConfig(
		mode=args.mode,
		csv_path=args.csv,
		watch_dir=args.watch,
	)

	mitigation_agent = MitigationAgent()

	agent = DetectionClassificationAgent(
		model_path=args.model,
		kibana=kibana,
		on_attack=mitigation_agent.mitigate,
		threshold=args.threshold,
		kibana_window_minutes=args.window,
		model_threshold_override=args.model_threshold,
		push_benign_to_kibana=args.kibana_save_all,
		use_siem_history=bool(args.use_siem_history),
	)

	agent.run(input_config)


if __name__ == "__main__":
	main()
