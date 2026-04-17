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
		DatabaseSIEMConfig,
		KibanaConfig,
		StubKibanaAdapter,
		create_siem_adapter,
	)
	from src.agents.mitigation_agent.agent import MitigationAgent
	from src.shared.schemas import ClassificationResult
except ModuleNotFoundError:
	from agents.classification_agent.agent import FlowInputConfig, DetectionClassificationAgent
	from agents.classification_agent.kibana_adapter import (
		DatabaseSIEMConfig,
		KibanaConfig,
		StubKibanaAdapter,
		create_siem_adapter,
	)
	from agents.mitigation_agent.agent import MitigationAgent
	from shared.schemas import ClassificationResult


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
	parser.add_argument(
		"--siem-backend",
		choices=["auto", "elasticsearch", "kibana", "database", "db", "sqlite", "postgres", "postgresql", "stub"],
		default=os.getenv("SIEM_BACKEND", "elasticsearch"),
		help="SIEM backend selection. Default is elasticsearch; set to auto for dynamic selection.",
	)
	parser.add_argument("--kibana-host", default=os.getenv("KIBANA_HOST"), help="Elasticsearch host (used when backend is elasticsearch)")
	parser.add_argument("--kibana-index", default=os.getenv("KIBANA_INDEX", "ands-alerts"), help="Elasticsearch index name")
	parser.add_argument("--kibana-user", default=os.getenv("KIBANA_USER"))
	parser.add_argument("--kibana-pass", default=os.getenv("KIBANA_PASS"))
	parser.add_argument(
		"--kibana-verify-certs",
		action="store_true",
		default=_env_bool("KIBANA_VERIFY_CERTS", False),
		help="Enable TLS certificate verification",
	)
	parser.add_argument(
		"--siem-db-url",
		default=os.getenv("SIEM_DB_URL") or os.getenv("DATABASE_URL"),
		help="SQL SIEM database URL. Examples: sqlite:///data/siem_history.db, postgresql://user:pass@host/db",
	)
	parser.add_argument(
		"--siem-sqlite-path",
		default=os.getenv("SIEM_SQLITE_PATH", "data/siem_history.db"),
		help="Fallback SQLite DB path when no SQL URL is provided.",
	)
	parser.add_argument("--siem-db-table", default=os.getenv("SIEM_DB_TABLE", "siem_alerts"))
	parser.add_argument("--siem-max-alerts", type=int, default=int(os.getenv("SIEM_MAX_ALERTS", "50")))
	parser.add_argument("--kibana-save-all", action="store_true", default=_env_bool("KIBANA_SAVE_ALL", False), help="Save both benign and attack flows to SIEM storage (default saves attacks only)")
	parser.add_argument("--window", type=int, default=int(os.getenv("SIEM_WINDOW_MINUTES", "10")), help="SIEM look-back window (minutes)")
	parser.add_argument("--use-siem-history", dest="use_siem_history", action="store_true", default=_env_bool("USE_SIEM_HISTORY", True), help="Enable SIEM historical corroboration for fusion")
	parser.add_argument("--disable-siem-history", dest="use_siem_history", action="store_false", help="Disable SIEM historical corroboration")
	return parser.parse_args()


def main():
	args = parse_args()

	kibana_config = None
	if args.kibana_host:
		kibana_config = KibanaConfig(
			host=args.kibana_host,
			index=args.kibana_index,
			username=args.kibana_user,
			password=args.kibana_pass,
			verify_certs=args.kibana_verify_certs,
			max_alerts=args.siem_max_alerts,
		)

	db_url = args.siem_db_url
	if not db_url and args.siem_backend in {"auto", "database", "db", "sqlite"}:
		db_url = f"sqlite:///{args.siem_sqlite_path}"

	database_config = DatabaseSIEMConfig(
		url=db_url or f"sqlite:///{args.siem_sqlite_path}",
		table=args.siem_db_table,
		max_alerts=args.siem_max_alerts,
	)

	kibana = create_siem_adapter(
		backend=args.siem_backend,
		kibana_config=kibana_config,
		database_config=database_config,
	)

	if isinstance(kibana, StubKibanaAdapter):
		print("[main] SIEM backend resolved to StubKibanaAdapter (in-memory only).")
	else:
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
