import asyncio
import logging
import time
from typing import Dict, Any, List

from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware

try:
    from src.agents.classification_agent.agent import FlowInputConfig, DetectionClassificationAgent, get_flow_stream
    from src.agents.classification_agent.kibana_adapter import StubKibanaAdapter
    from src.shared.schemas import ClassificationResult
except ModuleNotFoundError:
    from agents.classification_agent.agent import FlowInputConfig, DetectionClassificationAgent, get_flow_stream
    from agents.classification_agent.kibana_adapter import StubKibanaAdapter
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
    "logs": ["[API] System booted. Initializing Classification Agent..."]
}

flow_count = 0
blocked_ips = set()

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

async def agent_loop():
    logger.info("Starting background agent loop...")
    
    # Initialise as we did in main.py
    import src.main as main_script
    model_path = main_script._default_model_path()
    
    kibana = StubKibanaAdapter()
    
    agent = DetectionClassificationAgent(
        model_path=model_path,
        kibana=kibana,
        threshold=0.5,
        kibana_window_minutes=10,
        push_benign_to_kibana=False,
    )
    
    # We check if data/flows.csv exists, fallback if not
    import os
    target_csv = "data/flows.csv"
    if not os.path.exists(target_csv):
        target_csv = "data/test/test.csv"
        
    input_config = FlowInputConfig(
        mode="csv",
        csv_path=target_csv
    )
    
    while True:
        try:
            logger.info(f"Beginning to stream flows from {target_csv}...")
            for flow in get_flow_stream(input_config):
                result = agent.process_flow(flow)
                update_global_state(result)
                
                # Simulate realistic incoming stream delays (1.0s per flow)
                await asyncio.sleep(1.0)
            
            logger.info("Flow stream exhausted. Restarting loop in 5 seconds to simulate continued monitoring.")
            await asyncio.sleep(5)
            
        except Exception as e:
            logger.error(f"Error in agent_loop: {e}")
            await asyncio.sleep(5)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(agent_loop())

@app.get("/api/system_state")
async def get_system_state():
    return global_state

@app.get("/api/logs")
async def get_logs():
    return "\n".join(global_state["logs"])
