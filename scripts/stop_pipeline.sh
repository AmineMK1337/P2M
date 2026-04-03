#!/bin/bash

echo "[+] Stopping system..."

pkill -f tcpdump
pkill -f pcap_loop.sh
pkill -f "python -m src.main"

echo "[+] Stopped."