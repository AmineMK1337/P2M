"""
ANDS - Unified Classification Agent entrypoint.

Examples:
  python -m src.main --mode csv --csv data/flows.csv
  python -m src.main --mode cicflowmeter --watch data/cicflowmeter_out
"""

import argparse
import logging
from pathlib import Path

try:
	from src.agents.classification_agent.agent import FlowInputConfig, DetectionClassificationAgent
	from src.agents.classification_agent.kibana_adapter import KibanaAdapter, KibanaConfig, StubKibanaAdapter
	from src.shared.schemas import ClassificationResult
except ModuleNotFoundError:
	from agents.classification_agent.agent import FlowInputConfig, DetectionClassificationAgent
	from agents.classification_agent.kibana_adapter import KibanaAdapter, KibanaConfig, StubKibanaAdapter
	from shared.schemas import ClassificationResult


logging.basicConfig(
	level=logging.INFO,
	format="%(asctime)s [%(levelname)s] %(message)s",
	datefmt="%H:%M:%S",
)


def _default_model_path() -> str:
	return str(Path(__file__).resolve().parents[1] / "deployments" / "models" / "pca_intrusion_detector.joblib")


def forward_to_agent3(result: ClassificationResult):
	"""Bridge callback for confirmed attacks."""
	print(
		"[Bridge -> Agent3] "
		f"type={result.attack_type} | conf={result.confidence:.3f} | "
		f"ip={result.flow.src_ip} | source={result.decision_source}"
	)


def parse_args():
	parser = argparse.ArgumentParser(description="ANDS Classification Agent")
	parser.add_argument("--mode", choices=["csv", "cicflowmeter"], default="csv")
	parser.add_argument("--csv", default="data/flows.csv")
	parser.add_argument("--watch", default="data/cicflowmeter_out")
	parser.add_argument("--model", default=_default_model_path())
	parser.add_argument("--threshold", type=float, default=0.5)
	parser.add_argument("--kibana-host", default=None, help="Elasticsearch host (omit to use stub)")
	parser.add_argument("--kibana-index", default="ands-alerts", help="Elasticsearch index name")
	parser.add_argument("--kibana-user", default=None)
	parser.add_argument("--kibana-pass", default=None)
	parser.add_argument("--window", type=int, default=10, help="SIEM look-back window (minutes)")
	return parser.parse_args()


def main():
	args = parse_args()

	if args.kibana_host:
		kibana = KibanaAdapter(
			KibanaConfig(
				host=args.kibana_host,
				index=args.kibana_index,
				username=args.kibana_user,
				password=args.kibana_pass,
			)
		)
	else:
		print("[main] No --kibana-host provided, using StubKibanaAdapter.")
		kibana = StubKibanaAdapter()

	input_config = FlowInputConfig(
		mode=args.mode,
		csv_path=args.csv,
		watch_dir=args.watch,
	)

	agent = DetectionClassificationAgent(
		model_path=args.model,
		kibana=kibana,
		on_attack=forward_to_agent3,
		threshold=args.threshold,
		kibana_window_minutes=args.window,
	)

	agent.run(input_config)


if __name__ == "__main__":
	main()
