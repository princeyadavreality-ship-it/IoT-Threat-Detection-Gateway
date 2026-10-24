# IoT Threat Detection & Hardening Gateway

A modular, software-simulated network security gateway that monitors IoT device traffic, detects cyber threats using rule-based heuristics (inspired by Suricata/Snort), and automatically enforces network isolation via `iptables` rules.

---

## 📁 Project Architecture & File Breakdown

The codebase is strictly modularized to decouple packet ingestion from detection and response. This allows swapping the simulated traffic generator with live network capture (e.g. `pyshark` / `scapy`) without modifying detection or firewall response logic.

| File | Component | Responsibility |
| :--- | :--- | :--- |
| `traffic_simulator.py` | **Traffic Simulator** | Models 5 IoT devices (Camera, Door Lock, Temp Sensor, Power Plug, Thermostat) emitting benign HTTP/MQTT/HTTPS packets. Injects realistic network attacks. |
| `usb_monitor.py` | **Endpoint USB Agent** | Simulates host telemetry agent (e.g. `MANAGER-LAPTOP`) monitoring USB insertions and DLP copy operations. Bridges air-gapped file theft events to gateway. |
| `detection_engine.py` | **Detection Engine** | Stateful, sliding-window rule engine inspecting packet headers and behavioral metrics: Port Scans, Brute Force, C2 Beaconing (low jitter variance), Volume Floods, and USB Exfiltration. |
| `response_engine.py` | **Response Engine** | Decides `ISOLATE` vs `MONITOR`, maintains an active blocklist, synthesizes exact `iptables`, Windows `netsh`, and Windows Registry `USBSTOR` lockdown commands with dry-run safety. |
| `dashboard.py` | **Live Web Dashboard** | Modern FastAPI web application rendering live device telemetry, alerts table, firewall ledger, and interactive attack injection buttons. |
| `main.py` | **Unified Runner** | CLI entry point supporting both automated end-to-end simulation demonstration and web server startup. |
| `requirements.txt` | **Dependencies** | Minimal dependencies (`fastapi`, `uvicorn`, `pydantic`). |

---

## 🚀 Setup & Run Instructions on Windows

### Step 1: Verify Python Installation
Open **Command Prompt (`cmd.exe`)** or **PowerShell** and verify Python 3.9+ is installed:
```bash
python --version
```
*(If not installed, download from [python.org](https://www.python.org/downloads/) and ensure you check **"Add Python to PATH"** during installation).*

### Step 2: Navigate to the Project Directory
```bash
cd iot_gateway
```

### Step 3: Create and Activate a Virtual Environment
```bash
# In Command Prompt or PowerShell:
python -m venv venv

# Activate in Command Prompt:
venv\Scripts\activate.bat

# OR activate in PowerShell:
.\venv\Scripts\Activate.ps1
```

### Step 4: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 5: Run the System

#### Option A: Run Terminal CLI Simulation (Recommended First)
Runs an automated end-to-end test verifying normal baseline traffic, then sequentially injecting and detecting all 4 attacks with full console logs:
```bash
python main.py
```

#### Option B: Launch Live Web Dashboard
```bash
python main.py --web
```
or directly via uvicorn:
```bash
uvicorn dashboard:app --reload --host 127.0.0.1 --port 8000
```
Then open your browser at:
👉 **[http://localhost:8000](http://localhost:8000)**

---

## 🎯 Simulated Attack Vectors & Detection Logic

### 1. Port Scan Reconnaissance
- **Attack Behavior**: An external scanner rapidly probes 15+ different ports (e.g., 21, 22, 80, 554, 8080) on a target IoT device within a 10-second window.
- **Detection Algorithm**: Tracks unique destination ports per `(source_ip, target_ip)` pair in a sliding 10-second time window. Triggers when `unique_ports >= 15`.
- **Response**: Categorized as `HIGH` severity. Target attacker IP is isolated via `iptables -A FORWARD -s <ip> -j DROP`.

### 2. Credential Brute-Force Login
- **Attack Behavior**: Repeated failed authentication handshakes (SSH, Telnet, or Web admin panel) against an IoT device (e.g. Smart Door Lock on port 22).
- **Detection Algorithm**: Tracks failed authentication events (`auth_success == False`) grouped by `(source_ip, target_ip, target_port)`. Triggers when failures `>= 5` within a 10-second window.
- **Response**: Categorized as `HIGH` severity. Attacker IP is quarantined immediately.

### 3. Command & Control (C2) Beaconing
- **Attack Behavior**: A compromised internal IoT device (e.g. Smart Plug) calls home to an external malicious server at fixed, machine-like intervals.
- **Detection Algorithm**: Analyzes inter-packet arrival deltas ($\Delta t$). Calculates the sample mean and standard deviation (jitter). If the standard deviation $\sigma < 0.25\text{s}$ across 5+ consecutive connections, it flags machine-generated beaconing.
- **Response**: Categorized as `HIGH` severity. The **compromised internal IoT device IP** is isolated to prevent data exfiltration or lateral spread.

### 4. Volume Flood (DDoS / Exfiltration)
- **Attack Behavior**: A sudden burst of high-bandwidth traffic exceeding the expected baseline for an IoT sensor or camera.
- **Detection Algorithm**: Aggregates byte volume in a 3-second sliding window. Triggers when transmitted bytes $\ge 25,000\text{ bytes}$ (or configurable bandwidth ceiling). Note: Protocol filtering strictly checks network transports (`TCP`, `UDP`) to prevent cross-contamination with endpoint USB writes.
- **Response**: Categorized as `HIGH` severity. Drops traffic stream immediately.

### 5. Air-Gapped USB Data Exfiltration (Endpoint DLP)
- **The Security Gap Addressed**: Traditional network gateways only inspect packets traversing network interfaces (routers/switches). When a rogue insider or employee inserts a USB thumb drive and copies confidential database backups or encryption keys directly from disk, **that data never touches the network wire**. Network-only firewalls have a 100% blind spot for physical USB theft.
- **The Solution**: An endpoint-aware telemetry agent (`usb_monitor.py` running on `MANAGER-LAPTOP` / `192.168.1.15`) streams local peripheral events (insertion, drive letters, bytes written, files accessed) into the gateway's detection pipeline.
- **Detection Algorithm**: Aggregates USB mass storage write bytes within a 30-second sliding window. Triggers when cumulative write volume $\ge 50\text{ MB}$ or unauthorized flash drive attached.
- **Response**: Network `iptables` cannot stop physical USB transfers. Therefore, the Response Engine synthesizes OS-level endpoint device lockdown commands:
  - **Windows Registry Command**: `reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v Start /t REG_DWORD /d 4 /f` (instantly disables the Windows USB Mass Storage driver).
  - **Linux / Raspberry Pi Kernel Command**: `modprobe -r usb_storage && echo 'blacklist usb-storage' >> /etc/modprobe.d/blacklist.conf` (unloads and blacklists kernel USB storage module).
  - **Restoration / Unblock**: Setting `Start=3` or removing the modprobe blacklist restores normal authorized access.

---

## 🔒 Safety Mode & Real Hardware (Raspberry Pi) Deployment

### Safety Flag
In `response_engine.py`, `safety_mode` defaults to `True`.
- **`safety_mode = True`**: Synthesizes and logs the exact `iptables` and Windows `netsh` firewall commands without executing them on your operating system.
- **`safety_mode = False`**: Calls `subprocess.run()` to enforce the firewall rule on the host OS.

### Migrating to a Raspberry Pi with Live Packet Capture (`pyshark`)
To connect this gateway to a real network interface (e.g., `eth0` or `wlan0` bridging IoT devices):

1. **Install TShark & PyShark on the Raspberry Pi**:
   ```bash
   sudo apt-get update
   sudo apt-get install -y tshark
   pip install pyshark
   ```

2. **Replace `TrafficSimulator.generate_normal_packet()` with PyShark Live Capture**:
   In a new script `live_capture.py`:
   ```python
   import pyshark
   from detection_engine import DetectionEngine
   from response_engine import ResponseEngine
   from traffic_simulator import Packet

   engine = DetectionEngine()
   responder = ResponseEngine(safety_mode=False)  # Enforce real iptables!

   # Sniff on your Raspberry Pi gateway network interface
   capture = pyshark.LiveCapture(interface='eth0')
   for raw_pkt in capture.sniff_continuously():
       try:
           # Map live packet to our unified Packet structure
           pkt = Packet(
               timestamp=float(raw_pkt.sniff_timestamp),
               src_ip=raw_pkt.ip.src,
               dst_ip=raw_pkt.ip.dst,
               src_port=int(raw_pkt[raw_pkt.transport_layer].srcport),
               dst_port=int(raw_pkt[raw_pkt.transport_layer].dstport),
               protocol=raw_pkt.transport_layer,
               length=int(raw_pkt.length),
               flags=str(getattr(raw_pkt.tcp, 'flags', '')) if hasattr(raw_pkt, 'tcp') else '',
               auth_success=None
           )
           # Pass directly to the same Detection Engine
           alerts = engine.analyze_packets([pkt])
           for alert in alerts:
               responder.process_alert(alert)
       except AttributeError:
           continue
   ```
Because the `DetectionEngine` and `ResponseEngine` only depend on generic `Packet` dataclasses, zero changes are required in your detection or response logic!
