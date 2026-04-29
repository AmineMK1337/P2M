# ANDS Deployment Guide: Gateway VM

This guide explains how to run the **ANDS (Autonomous Network Defense System)** on your Linux Gateway VM for real-time traffic capture, detection, and automated mitigation.

## 1. Prerequisites

Ensure the following are installed and configured on your VM:

*   **Linux OS** (Ubuntu/Debian recommended).
*   **Python 3.8+** and a virtual environment (`python -m venv .venv`).
*   **tcpdump**: For packet capture.
*   **iptables**: For firewall-based mitigation.
*   **Sudo Privileges**: The user running the script must have `sudo` access.
    *   *Tip:* For seamless background operation, configure passwordless sudo for `iptables` and `ip` commands.
*   **Dependencies**: Install via `pip install -r requirements.txt`.

## 2. Configuration

Ensure your `.env` file is configured at the repo root. Key variables:
*   `KIBANA_HOST`: URL of your Elasticsearch/Kibana instance for SIEM fusion.
*   `USE_SIEM_HISTORY`: Set to `True` to enable corroboration.

## 3. Running the Live Pipeline

The entire system (Capture -> Flow Extraction -> Classification -> Mitigation) is orchestrated by a single script.

### Start the Pipeline
Run the following from the root of the repository:
```bash
bash scripts/run_pipeline.sh
```

### What this script does:
1.  **Creates Directories**: Initializes `data/test1`, `data/flows_csv`, and `logs`.
2.  **Packet Capture**: Starts `tcpdump` on `eth1` (adjust the interface in the script if needed), rolling every 5 seconds.
3.  **Flow Extraction**: Starts `scripts/pcap_loop.sh` which watches `data/test1` and converts PCAPs to CSV using the internal `cicflowmeter`.
4.  **Backend API**: Starts the FastAPI server (`src.api`) on port `8000`, which processes the CSVs and triggers the **Mitigation Agent**.

## 4. Mitigation Agent Behavior

The Mitigation Agent is designed to block malicious IPs using `iptables`.

*   **Interactive Mode**: If you run the backend manually in a terminal, the agent will **ask for your confirmation** `[y/N]` before applying any firewall rule.
*   **Background Mode**: When running via `run_pipeline.sh` (which redirects output to logs), the agent detects the non-interactive environment and **automatically applies the mitigation** to ensure the gateway remains protected.
*   **Privileges**: All firewall actions are automatically prefixed with `sudo`.

## 5. Monitoring & Logs

You can monitor the system performance via the logs:
*   `tail -f logs/ml.log`: Watch classification decisions and mitigation actions.
*   `tail -f logs/pcap_loop.log`: Monitor PCAP to CSV conversion.
*   `tail -f logs/tcpdump.log`: Monitor raw packet capture status.

## 6. Accessing the Dashboard

Once the pipeline is running, you can access the dashboard by navigating to the VM's IP address on port `8000` in your web browser:
`http://<VM_IP>:8000/api/system_state`
