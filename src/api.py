import asyncio
import logging
import os
import time
from typing import Dict, Any, List

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

try:
    from src.agents.classification_agent.agent import FlowInputConfig, DetectionClassificationAgent, get_flow_stream
    from src.agents.classification_agent.kibana_adapter import (
        KibanaAdapter,
        KibanaConfig,
    )
    from src.agents.mitigation_agent.agent import MitigationAgent
    from src.shared.schemas import ClassificationResult
except ModuleNotFoundError:
    from agents.classification_agent.agent import FlowInputConfig, DetectionClassificationAgent, get_flow_stream
    from agents.classification_agent.kibana_adapter import (
        KibanaAdapter,
        KibanaConfig,
    )
    from agents.mitigation_agent.agent import MitigationAgent
    from shared.schemas import ClassificationResult

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("api_server")

app = FastAPI(title="ANDS Classification API")

# Setup CORS for local frontend dev
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global State Container
global_state: Dict[str, Any] = {
    "traffic": {"pps": 0, "connections": [], "history": []},
    "capture": {"pcaps": 0, "status": "running", "source": "csv"},
    "features": {"flows": 0, "items": []},
    "detection": {
        "prediction": "normal",
        "confidence": 0.5,
        "attack_type": "BENIGN",
        "reasoning": "Waiting for traffic..."
    },
    "decision": {"action": "allow", "source": "policy", "confidence": 0.5},
    "defense": {"blocked_ips": [], "total": 0, "last_blocked_ip": None},
    "mitigation": {
        "status": "pending",
        "actions_taken": [],
        "mitigated": False
    },
    "logs": ["[API] System booted. Initializing Classification Agent..."]
}

flow_count = 0
blocked_ips = set()


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _build_siem_adapter():
    if not _env_bool("USE_SIEM_HISTORY", default=True):
        logger.info("[API] USE_SIEM_HISTORY is False. Skipping Elasticsearch connection.")
        return None

    kibana_host = (os.getenv("KIBANA_HOST") or "http://localhost:9200").strip()
    if not kibana_host:
        raise RuntimeError("KIBANA_HOST is required for SIEM history fusion.")

    adapter = KibanaAdapter(
        KibanaConfig(
            host=kibana_host,
            index=os.getenv("KIBANA_INDEX", "ands-alerts"),
            username=os.getenv("KIBANA_USER") or None,
            password=os.getenv("KIBANA_PASS") or None,
            verify_certs=_env_bool("KIBANA_VERIFY_CERTS", False),
            max_alerts=int(os.getenv("SIEM_MAX_ALERTS", "50")),
        )
    )
    if not adapter.is_available():
        raise RuntimeError(
            f"Could not connect to Elasticsearch at {kibana_host}. "
            "Start Elasticsearch/Kibana or update KIBANA_HOST credentials."
        )
    logger.info("[API] SIEM adapter initialized: %s", adapter.__class__.__name__)
    return adapter

def update_global_state(result: ClassificationResult):
    global flow_count, blocked_ips, global_state
    
    flow_count += 1
    
    src_ip = result.flow.src_ip or "unknown"
    if result.is_attack:
        blocked_ips.add(src_ip)
    
    # Keep last N logs
    log_msg = (f"[Model] {result.attack_type} detected. IP: {src_ip} "
               f"(conf: {result.confidence:.2%})")
    global_state["logs"].append(log_msg)
    if len(global_state["logs"]) > 20:
        global_state["logs"].pop(0)

    # Format features safely
    feature_items = []
    # Pick a few key features to display to avoid blowing up the payload
    for k, v in list(result.flow.features.items())[:8]:
        feature_items.append({"key": str(k), "label": str(k), "value": str(v)})

    global_state["traffic"]["pps"] = 100 + (flow_count % 50)  # Simulated
    global_state["traffic"]["connections"] = [
        {"src": src_ip, "proto": "TCP"}
    ]
    
    global_state["features"]["flows"] = flow_count
    global_state["features"]["items"] = feature_items
    
    global_state["detection"] = {
        "prediction": "attack" if result.is_attack else "normal",
        "confidence": result.confidence,
        "model_confidence": result.model_confidence,
        "siem_confidence": result.siem_confidence,
        "attack_type": result.attack_type,
        "reasoning": result.reasoning
    }
    
    global_state["decision"] = {
        "action": "block" if result.is_attack else "allow",
        "source": result.decision_source,
        "confidence": result.confidence
    }
    
    # We maintain order to match what frontend expects
    blocked_list = list(blocked_ips)
    global_state["defense"] = {
        "blocked_ips": blocked_list,
        "total": len(blocked_ips),
        "last_blocked_ip": blocked_list[-1] if blocked_list else "none"
    }

    # Add detailed mitigation data for the dashboard
    global_state["mitigation"] = {
        "status": result.mitigation_status,
        "actions_taken": result.mitigation_actions,
        "mitigated": result.mitigated
    }

async def agent_loop(kibana):
    """
    Background worker that indefinitely streams data into the ClassificationAgent.
    This replaces the previous 'main.py' CLI loop when running via the API.
    """
    logger.info("Initializing background agent loop...")
    
    mitigation_agent = MitigationAgent()

    use_siem_history = _env_bool("USE_SIEM_HISTORY", default=True)
    siem_window = int(os.getenv("SIEM_WINDOW_MINUTES", "10"))
    save_benign = _env_bool("KIBANA_SAVE_ALL", True)

    global_state["logs"].append(
        f"[API] SIEM backend active: {kibana.__class__.__name__} (history_fusion={'on' if use_siem_history else 'off'})"
    )
    
    agent = DetectionClassificationAgent(
        model_path="deployments/models/pca_intrusion_detector.joblib",
        kibana=kibana,
        on_attack=mitigation_agent.mitigate,
        threshold=0.5,
        push_benign_to_kibana=save_benign,
        kibana_window_minutes=siem_window,
        use_siem_history=use_siem_history,
    )
    
    # 1. Determine the active capture mode
    target_csv = "data/flows.csv"
    watch_dir = os.environ.get("FLOW_WATCH_DIR", "data/flows_csv")
    
    is_live = False
    if os.path.exists(watch_dir):
        logger.info(f"Live watch directory detected at {watch_dir}. API set to live pipeline mode.")
        input_config = FlowInputConfig(mode="cicflowmeter", watch_dir=watch_dir)
        is_live = True
        global_state["capture"] = {"status": "running", "source": "cicflowmeter"}
    else:
        if not os.path.exists(target_csv):
            target_csv = "data/test/test.csv"
        logger.info(f"Live processing directory off. Fallback to API CSV mock stream: {target_csv}")
        input_config = FlowInputConfig(mode="csv", csv_path=target_csv)
        global_state["capture"] = {"status": "mock", "source": "csv"}
        
    global_state["capture"]["status"] = "running"
        
    while True:
        try:
            if not is_live:
                logger.info(f"Beginning to stream flows from {target_csv}...")
                
            for flow in get_flow_stream(input_config):
                # Classify
                result = agent.process_flow(flow)
                
                # Update Dashboard State
                update_global_state(result)
                
                # Sleep between individual CSV flows to simulate realtime
                if not is_live:
                    await asyncio.sleep(1.0)
            
            if is_live:
                # The directory exhausted. Sleep briefly before polling for the next 5-sec PCAP cutoff.
                await asyncio.sleep(1.5)
            else:
                logger.info("Flow stream exhausted. Restarting loop in 5 seconds to simulate continued monitoring.")
                await asyncio.sleep(5)
            
        except FileNotFoundError as e:
            logger.error(f"Waiting for capture directory: {e}")
            await asyncio.sleep(3)
        except Exception as e:
            logger.error(f"Exception in agent loop: {e}")
            await asyncio.sleep(5)

@app.on_event("startup")
async def startup_event():
    kibana = _build_siem_adapter()
    asyncio.create_task(agent_loop(kibana))

@app.get("/api/system_state")
async def get_system_state():
    return global_state

@app.get("/api/logs")
async def get_logs():
    return "\n".join(global_state["logs"])
