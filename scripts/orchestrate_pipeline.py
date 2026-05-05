#!/usr/bin/env python3
"""
ANDS Pipeline Orchestrator - Main execution loop

Coordinates sequential execution of:
1. Packet capture (tcpdump)
2. Flow extraction (CICFlowMeter)
3. ML inference
4. Detection & mitigation agents
"""

import sys
import os
import time
import subprocess
import logging
from pathlib import Path
from datetime import datetime
import signal

# Setup paths
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

# ============================================================================
# CONFIGURATION
# ============================================================================

INTERFACE = "enp0s8"           # Attacker -> Victim interface
CAPTURE_DURATION = 5           # Seconds per cycle
CYCLE_INTERVAL = 5             # Seconds between cycles

# Fixed paths
INPUT_FILE = Path("/data/test1/simulated_attack.pcap")
OUTPUT_PREFIX = Path("/data/test1/output")
ALERTS_LOG = Path("/logs/alerts.log")

# Working directories
PCAP_DIR = Path("/data/test1")
CSV_DIR = Path("/data/test1")
LOG_DIR = Path("/logs")

# Model
MODEL_PATH = REPO_ROOT / "deployments" / "models" / "pca_intrusion_detector.joblib"
DETECTION_THRESHOLD = 0.5

# ============================================================================
# LOGGING
# ============================================================================

def setup_logging():
    """Configure logging to console and file"""
    log_format = '%(asctime)s [%(levelname)-8s] %(name)-15s %(message)s'
    log_file = LOG_DIR / "orchestrator.log"
    
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger("ORCHESTRATOR")

logger = None

# ============================================================================
# STAGE 1: PACKET CAPTURE
# ============================================================================

def capture_traffic(cycle_num):
    """Capture 5 seconds of traffic using tcpdump"""
    
    logger.info(f"[CAPTURE] Cycle {cycle_num}: Starting {CAPTURE_DURATION}s capture on {INTERFACE}...")
    
    temp_pcap = PCAP_DIR / f"temp_{cycle_num}.pcap"
    
    try:
        # Run tcpdump with timeout
        cmd = [
            "sudo", "tcpdump",
            "-i", INTERFACE,
            "-w", str(temp_pcap),
            "-G", str(CAPTURE_DURATION),
            "-W", "1"
        ]
        
        result = subprocess.run(cmd, capture_output=True, timeout=CAPTURE_DURATION + 2)
        
        if temp_pcap.exists() and temp_pcap.stat().st_size > 0:
            # Atomic move to standard input file
            temp_pcap.replace(INPUT_FILE)
            logger.info(f"[CAPTURE] ✓ Captured {INPUT_FILE.stat().st_size} bytes to {INPUT_FILE}")
            return True
        else:
            logger.warning(f"[CAPTURE] ⚠ Capture produced empty file")
            temp_pcap.unlink(missing_ok=True)
            return False
            
    except subprocess.TimeoutExpired:
        logger.error(f"[CAPTURE] ✗ Timeout after {CAPTURE_DURATION + 2}s")
        temp_pcap.unlink(missing_ok=True)
        return False
    except Exception as e:
        logger.error(f"[CAPTURE] ✗ Error: {e}")
        temp_pcap.unlink(missing_ok=True)
        return False

# ============================================================================
# STAGE 2: CICFLOWMETER FEATURE EXTRACTION
# ============================================================================

def extract_features(cycle_num):
    """Process PCAP through CICFlowMeter to extract flow features"""
    
    if not INPUT_FILE.exists():
        logger.error(f"[CICFLOWMETER] ✗ Input PCAP not found: {INPUT_FILE}")
        return None
    
    timestamp = int(time.time() * 1000)  # Millisecond precision
    output_csv = Path(f"{OUTPUT_PREFIX}_{timestamp}.csv")
    
    logger.info(f"[CICFLOWMETER] Cycle {cycle_num}: Processing {INPUT_FILE}")
    
    try:
        # Run CICFlowMeter sniffer as module
        cmd = [
            "python3", "-m", "cicflowmeter.sniffer",
            str(INPUT_FILE),
            str(output_csv)
        ]
        
        result = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            timeout=30,
            text=True
        )
        
        if output_csv.exists() and output_csv.stat().st_size > 0:
            flow_count = len(output_csv.read_text().strip().split('\n')) - 1
            logger.info(f"[CICFLOWMETER] ✓ Extracted {flow_count} flows to {output_csv.name}")
            
            # Store path for next stage
            (PCAP_DIR / ".last_csv").write_text(str(output_csv))
            return output_csv
        else:
            logger.warning(f"[CICFLOWMETER] ⚠ No flows extracted")
            output_csv.unlink(missing_ok=True)
            return None
            
    except subprocess.TimeoutExpired:
        logger.error(f"[CICFLOWMETER] ✗ Timeout after 30s")
        output_csv.unlink(missing_ok=True)
        return None
    except Exception as e:
        logger.error(f"[CICFLOWMETER] ✗ Error: {e}")
        output_csv.unlink(missing_ok=True)
        return None

# ============================================================================
# STAGE 3: ML INFERENCE
# ============================================================================

def run_inference(cycle_num, csv_file):
    """Run batch ML inference on extracted features"""
    
    if not csv_file or not csv_file.exists():
        logger.warning(f"[ML_INFERENCE] Cycle {cycle_num}: No CSV input")
        return False
    
    logger.info(f"[ML_INFERENCE] Cycle {cycle_num}: Running batch inference...")
    
    try:
        import pandas as pd
        import joblib
        import numpy as np
        
        # Load model bundle
        bundle = joblib.load(str(MODEL_PATH))
        scaler = bundle['scaler']
        pca = bundle['pca']
        model_threshold = bundle.get('threshold', DETECTION_THRESHOLD)
        feature_columns = list(bundle.get('feature_columns', []))
        
        # Load CSV
        df = pd.read_csv(str(csv_file))
        
        if df.empty:
            logger.warning(f"[ML_INFERENCE] ⚠ No flows in CSV")
            return True
        
        # Align features
        missing = [c for c in feature_columns if c not in df.columns]
        if missing:
            logger.error(f"[ML_INFERENCE] ✗ Missing features: {missing}")
            return False
        
        # Extract and normalize features
        X = df[feature_columns].fillna(0).values.astype(np.float32)
        
        # Transform through PCA
        X_scaled = scaler.transform(X)
        X_pca = pca.transform(X_scaled)
        X_reconstructed = pca.inverse_transform(X_pca)
        
        # Calculate anomaly scores
        scores = np.sum((X_scaled - X_reconstructed) ** 2, axis=1)
        predictions = np.array([1 if s < model_threshold else -1 for s in scores])
        
        # Log results
        attacks = np.sum(predictions == -1)
        if attacks > 0:
            logger.info(f"[ML_INFERENCE] ✓ {attacks} ATTACKS detected out of {len(predictions)} flows")
        else:
            logger.info(f"[ML_INFERENCE] ✓ All {len(predictions)} flows benign")
        
        # Save inference results
        df['prediction'] = predictions
        df['anomaly_score'] = scores
        df['is_attack'] = (predictions == -1)
        results_file = csv_file.with_stem(csv_file.stem + "_results")
        df.to_csv(results_file, index=False)
        logger.info(f"[ML_INFERENCE] ✓ Results saved: {results_file.name}")
        
        return True
        
    except ImportError as e:
        logger.error(f"[ML_INFERENCE] ✗ Missing dependency: {e}")
        return False
    except Exception as e:
        logger.error(f"[ML_INFERENCE] ✗ Error: {e}")
        return False

# ============================================================================
# STAGE 4: DETECTION & MITIGATION AGENTS
# ============================================================================

def run_detection_agent(cycle_num, csv_file):
    """Run classification agent and trigger mitigations"""
    
    if not csv_file or not csv_file.exists():
        logger.warning(f"[AGENT] Cycle {cycle_num}: No input available")
        return True
    
    logger.info(f"[AGENT] Cycle {cycle_num}: Running classification agent...")
    
    try:
        # Import agents (with fallback for missing SIEM)
        from src.agents.classification_agent.agent import (
            FlowInputConfig,
            DetectionClassificationAgent
        )
        from src.agents.mitigation_agent.agent import MitigationAgent
        
        config = FlowInputConfig(mode='csv', csv_path=str(csv_file))
        
        # Initialize agents
        mitigation_agent = MitigationAgent()
        agent = DetectionClassificationAgent(
            config=config,
            model_path=str(MODEL_PATH),
            siem_adapter=None,  # SIEM optional for pipeline
            on_attack=mitigation_agent.mitigate  # Pass mitigation callback
        )
        
        # Process flows and collect results
        detection_count = 0
        mitigation_count = 0
        
        for result in agent.infer():
            if result.is_attack:
                detection_count += 1
                logger.info(
                    f"[ALERT] Attack detected: {result.attack_type} "
                    f"from {result.source_ip} (conf={result.confidence:.2f})"
                )
                mitigation_count += 1
        
        if detection_count > 0:
            logger.info(f"[AGENT] ✓ {detection_count} detections, {mitigation_count} mitigations triggered")
        
        return True
        
    except Exception as e:
        logger.warning(f"[AGENT] ⚠ Agent execution failed: {e}")
        # Non-fatal: pipeline continues
        return True

# ============================================================================
# MAIN ORCHESTRATION LOOP
# ============================================================================

def setup_environment():
    """Initialize directories and validate configuration"""
    
    logger.info("Setting up environment...")
    
    # Create directories
    for d in [PCAP_DIR, CSV_DIR, LOG_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    
    # Verify interface
    try:
        result = subprocess.run(
            ["ip", "link", "show", INTERFACE],
            capture_output=True,
            timeout=5
        )
        if result.returncode != 0:
            logger.error(f"✗ Interface {INTERFACE} not found")
            return False
    except Exception as e:
        logger.error(f"✗ Cannot verify interface: {e}")
        return False
    
    # Verify model
    if not MODEL_PATH.exists():
        logger.error(f"✗ Model not found: {MODEL_PATH}")
        return False
    
    logger.info("✓ Environment ready")
    return True

def main():
    """Main orchestration loop"""
    
    global logger
    logger = setup_logging()
    
    # Validate environment
    if not setup_environment():
        logger.critical("Setup failed")
        sys.exit(1)
    
    logger.info("")
    logger.info("╔════════════════════════════════════════════════════════════════╗")
    logger.info("║          ANDS PIPELINE ORCHESTRATOR - STARTING                ║")
    logger.info("╚════════════════════════════════════════════════════════════════╝")
    logger.info("")
    logger.info("Configuration:")
    logger.info(f"  Interface:  {INTERFACE}")
    logger.info(f"  Cycle:      {CAPTURE_DURATION}s capture + processing")
    logger.info(f"  Interval:   {CYCLE_INTERVAL}s")
    logger.info(f"  PCAP dir:   {PCAP_DIR}")
    logger.info(f"  Model:      {MODEL_PATH.name}")
    logger.info("")
    
    cycle = 0
    
    def signal_handler(sig, frame):
        logger.info("Received interrupt signal, shutting down...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Infinite loop
    try:
        while True:
            cycle += 1
            cycle_start = time.time()
            
            logger.info("")
            logger.info("="*70)
            logger.info(f"CYCLE {cycle} [{datetime.now().strftime('%H:%M:%S')}]")
            logger.info("="*70)
            
            # Execute pipeline stages sequentially
            success = True
            csv_file = None
            
            # Stage 1: Capture
            if not capture_traffic(cycle):
                success = False
            else:
                # Stage 2: Extract features
                csv_file = extract_features(cycle)
                if csv_file:
                    # Stage 3: ML inference
                    if not run_inference(cycle, csv_file):
                        success = False
                    else:
                        # Stage 4: Detection & mitigation
                        run_detection_agent(cycle, csv_file)
                else:
                    success = False
            
            # Calculate remaining sleep time
            elapsed = time.time() - cycle_start
            remaining = CYCLE_INTERVAL - elapsed
            
            if remaining > 0:
                logger.info(f"[PIPELINE] Cycle complete. Sleeping {remaining:.1f}s until next cycle...")
                time.sleep(remaining)
            else:
                logger.warning(f"[PIPELINE] ⚠ Cycle took {elapsed:.1f}s (exceeded {CYCLE_INTERVAL}s limit)")
    
    except KeyboardInterrupt:
        logger.info("Pipeline interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Unhandled error: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
