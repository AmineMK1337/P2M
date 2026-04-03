#!/bin/bash

# Move to repo root (CRITICAL)
cd "$(dirname "$0")/.."

echo "====================================="
echo "   AND SYSTEM STARTING..."
echo "====================================="

# Create dirs
mkdir -p ~/ands/pcaps
mkdir -p ~/ands/flows_csv
mkdir -p ~/ands/logs

# Kill old processes (avoid duplicates)
echo "[+] Cleaning old processes..."
pkill -f tcpdump
pkill -f pcap_loop.sh
pkill -f "python -m src.main"

sleep 2

# Start packet capture
echo "[+] Starting packet capture..."
sudo tcpdump -i eth1 -w ~/ands/pcaps/capture_%s.pcap -G 3 -W 100 > ~/ands/logs/tcpdump.log 2>&1 &

sleep 2

# Start PCAP processing
echo "[+] Starting PCAP processing..."
bash scripts/pcap_loop.sh > ~/ands/logs/pcap_loop.log 2>&1 &

sleep 2

# Start ML engine
echo "[+] Starting ML detection..."
python -m src.main --mode cicflowmeter --watch ~/ands/flows_csv > ~/ands/logs/ml.log 2>&1 &

sleep 2

echo "[+] SYSTEM RUNNING"
echo "Logs:"
echo "  - tcpdump:   ~/ands/logs/tcpdump.log"
echo "  - pcap loop: ~/ands/logs/pcap_loop.log"
echo "  - ML:        ~/ands/logs/ml.log"

echo "====================================="