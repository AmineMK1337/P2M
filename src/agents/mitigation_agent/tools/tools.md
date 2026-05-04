# Mitigation Agent Tools — Role Summary

This document outlines the role and behavior of each tool available to the **MitigationAgent**. All tools are designed to automatically mitigate detected cyberattacks on the Ubuntu victim machine. Each tool is idempotent, cross-platform, and requires user approval before execution (unless `AUTO_MITIGATE=true`).

---

## Tool Overview

| Tool | Purpose | OS Support | Severity |
|------|---------|-----------|----------|
| `block_ip` | Block all inbound traffic from an IP | Linux (iptables), Windows (netsh) | High |
| `rate_limit_ip` | Rate-limit connection attempts from an IP | Linux (hashlimit), Windows (fallback to block) | Medium |
| `null_route_ip` | Blackhole all traffic from an IP via kernel route | Linux (ip route), Windows (fallback to block) | High |
| `throttle_connections` | Throttle new TCP connections per minute from an IP | Linux (recent module), Windows (fallback to block) | Medium |
| `quarantine_host` | Move a host to a restricted VLAN segment | SDN/Switch API | Medium |
| `isolate_host` | Fully isolate a host (block inbound + outbound) | Linux (iptables), Windows (netsh) | Critical |
| `alert_soc` | Send a structured alert to the SOC/Wazuh | Webhook/API | Low |

---

## Detailed Tool Descriptions

### 1. **block_ip** (High Severity)

**Purpose:** Block all inbound traffic from a specified IP address using the OS firewall.

**Parameters:**
- `ip_address` (str, required): The IP to block
- `duration_minutes` (int, default=60): How long to keep the block active

**Implementation:**
- **Linux:** Inserts an iptables rule: `sudo iptables -I INPUT -s {ip} -j DROP`
- **Windows:** Adds a Windows Firewall rule via netsh with rule name `ANDS_Block_{ip}`
- **Idempotency:** Tracks blocked IPs in `_blocked_ips` set; skips if already blocked in current session

**Use Cases:**
- Stopping DDoS attacks
- Blocking port scans
- Preventing brute force attacks after rate limit exceeded

**Approval:** Requires user confirmation (via `_confirm_action`) unless `AUTO_MITIGATE=true`

---

### 2. **rate_limit_ip** (Medium Severity)

**Purpose:** Limit the number of inbound connections per second from an IP address, allowing some traffic but preventing floods.

**Parameters:**
- `ip_address` (str, required): The IP to rate-limit
- `max_connections_per_second` (int, default=10): Connection limit threshold

**Implementation:**
- **Linux:** Uses iptables with hashlimit module: `iptables ... -m hashlimit --hashlimit-above {rate}/sec -j DROP`
- **Windows:** Falls back to full `block_ip` (native rate limiting not supported)
- **Behavior:** Drops packets exceeding the threshold

**Use Cases:**
- Mitigating volumetric DDoS attacks while preserving legitimate traffic
- Allowing some communication while preventing resource exhaustion
- Softer response than full block; allows investigation

**Approval:** Requires user confirmation

---

### 3. **null_route_ip** (High Severity)

**Purpose:** Black-hole all traffic from an IP address using a kernel-level null route, preventing the victim from even responding.

**Parameters:**
- `ip_address` (str, required): The IP to null-route

**Implementation:**
- **Linux:** Adds a null route: `sudo ip route add blackhole {ip}/32`
- **Windows:** Falls back to `block_ip` (null routes not natively supported)
- **Behavior:** All packets matching the route are silently dropped at the kernel level

**Use Cases:**
- Stopping advanced attacks that exploit responses
- More efficient than iptables for high-volume attacks
- Preventing reconnaissance when attacker learns the victim's responses

**Approval:** Requires user confirmation

---

### 4. **throttle_connections** (Medium Severity)

**Purpose:** Limit the rate of **new** TCP connection attempts (SYN packets) from an IP, slowing down brute force and scanning attacks.

**Parameters:**
- `ip_address` (str, required): The IP to throttle
- `max_new_per_minute` (int, default=5): Maximum new connections per minute

**Implementation:**
- **Linux:** Uses iptables with the `recent` module:
  1. First rule: Marks SYN packets from the IP
  2. Second rule: Drops SYN packets if `--hitcount` (new connections) exceeded in 60 seconds
- **Windows:** Falls back to full `block_ip`
- **Stateful:** Tracks connection attempts over a rolling 60-second window

**Use Cases:**
- Mitigating brute force attacks (e.g., SSH, RDP, HTTP login)
- Slowing down port scans
- Allowing legitimate traffic while blocking scanners

**Approval:** Requires user confirmation

---

### 5. **quarantine_host** (Medium Severity)

**Purpose:** Move a compromised internal host to a restricted VLAN segment, isolating it from the main network without losing observability.

**Parameters:**
- `ip_address` (str, required): The IP of the host to quarantine

**Implementation:**
- Currently a **stub/placeholder** — logs the action and records it in the audit trail
- **Future:** Will require an SDN controller (e.g., OpenDaylight) or managed switch API (e.g., Cisco DNAC)
- **Behavior:** Marks the host for quarantine but does not yet execute the actual VLAN move

**Use Cases:**
- Isolating compromised internal machines without killing the connection
- Maintaining forensic evidence by keeping the machine online for inspection
- Preventing lateral movement while preserving network visibility

**Approval:** Auto-approved (stub only); will require approval once API integrated

---

### 6. **isolate_host** (Critical Severity)

**Purpose:** Fully isolate a host by blocking **both inbound AND outbound** traffic, preventing any network communication.

**Parameters:**
- `ip_address` (str, required): The IP of the host to isolate

**Implementation:**
- **Linux:** Inserts two iptables rules:
  1. `sudo iptables -I INPUT -s {ip} -j DROP` (block inbound)
  2. `sudo iptables -I OUTPUT -d {ip} -j DROP` (block outbound)
- **Windows:** Adds two netsh firewall rules:
  1. Inbound rule: `ANDS_Isolate_In_{ip}`
  2. Outbound rule: `ANDS_Isolate_Out_{ip}`
- **Behavior:** Kills all connectivity for the host

**Use Cases:**
- Emergency containment of a severely compromised machine
- Stopping data exfiltration attempts
- Preventing a host from attacking other targets
- Last resort when other mitigations insufficient

**Approval:** Requires user confirmation (critical operation)

---

### 7. **alert_soc** (Low Severity)

**Purpose:** Send a structured alert to the Security Operations Center (SOC) or SIEM system (e.g., Wazuh) for auditing and human review.

**Parameters:**
- `message` (str, required): The alert message
- `severity` (str, default="medium"): Alert severity level — one of `low`, `medium`, `high`, `critical`

**Implementation:**
- Currently a **stub** — logs the alert and records it in `_action_log`
- **Future:** Will POST to a Wazuh webhook or custom SOC API:
  ```python
  requests.post(
      WAZUH_WEBHOOK_URL,
      json={"severity": severity, "message": message},
      timeout=5,
  )
  ```
- **Usage:** Always called as the final step to create an audit trail

**Use Cases:**
- Creating forensic evidence of all mitigation actions
- Notifying human analysts of automated responses
- Feeding data back into SIEM for correlation and reporting
- Ensuring accountability and compliance

**Approval:** Auto-approved (informational only)

---

## Execution Flow

The typical mitigation flow follows this pattern:

```
ClassificationResult (attack detected)
         ↓
[MitigationAgent receives result]
         ↓
[SELECT TOOL based on attack type]
    ├─ DDoS         → block_ip or rate_limit_ip or null_route_ip
    ├─ Brute Force  → throttle_connections or block_ip
    ├─ Port Scan    → throttle_connections or null_route_ip
    ├─ Infiltration → isolate_host
    └─ Other        → block_ip (default)
         ↓
[Tool executed with user approval]
         ↓
[Action recorded in _action_log]
         ↓
[alert_soc called with summary]
         ↓
[Agent reports final action taken]
```

---

## Idempotency & State

- **`block_ip` idempotency:** Uses `_blocked_ips` set to track blocked IPs within the session. Skips re-blocking.
- **Session audit log:** `_action_log` list tracks every tool invocation with timestamp, status, and details for post-incident analysis.
- **User approval:** `_confirm_action` enforces approval unless `AUTO_MITIGATE=true` environment variable is set.

---

## OS Platform Mapping

| Tool | Linux | Windows | Fallback |
|------|-------|---------|----------|
| block_ip | ✅ iptables | ✅ netsh | N/A |
| rate_limit_ip | ✅ hashlimit | ❌ → block_ip | Full block |
| null_route_ip | ✅ ip route | ❌ → block_ip | Full block |
| throttle_connections | ✅ recent module | ❌ → block_ip | Full block |
| quarantine_host | 🔄 Stub | 🔄 Stub | Stub |
| isolate_host | ✅ iptables (2 rules) | ✅ netsh (2 rules) | N/A |
| alert_soc | 🔄 Stub → Webhook | 🔄 Stub → Webhook | Stub |

**Legend:** ✅ Full support | ❌ Not supported | 🔄 Stub (future API integration)

---

## Environment Variables

- **`AUTO_MITIGATE`**: Set to `"true"`, `"1"`, or `"yes"` to auto-approve all actions without prompting. Useful for automated pipelines.
- Default (not set): User is prompted for approval on each tool invocation.

---

## Future Enhancements

1. **quarantine_host API integration** — Connect to SDN controller or switch management API
2. **alert_soc webhook** — Integrate with Wazuh or custom SIEM
3. **Custom duration tracking** — Implement expiration of temporary blocks
4. **Rollback capability** — Allow undoing recent mitigations
5. **Attack-specific tool selection** — Hardcode tool choice per attack type rather than leaving to agent
