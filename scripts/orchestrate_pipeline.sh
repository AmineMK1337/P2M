#!/bin/bash
# ANDS Pipeline Orchestrator - Bash Wrapper
# 
# Launches the Python orchestration engine that runs the complete
# micro-batching pipeline: capture -> extract -> infer -> mitigate
#
# Usage:
#   bash scripts/orchestrate_pipeline.sh
#   OR (as background daemon)
#   bash scripts/orchestrate_pipeline.sh &
#   disown

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is required but not installed"
    exit 1
fi

echo "[+] Starting ANDS Pipeline Orchestrator..."
echo "[+] Repository root: $REPO_ROOT"

# Export environment for subprocess
export PYTHONUNBUFFERED=1
export PYTHONPATH="$REPO_ROOT:$PYTHONPATH"

# Run the Python orchestrator
exec python3 "$REPO_ROOT/scripts/orchestrate_pipeline.py" "$@"

