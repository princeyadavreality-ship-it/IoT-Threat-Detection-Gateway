# 🛡️ IoT Threat Detection & Hardening Gateway

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![React](https://img.shields.io/badge/React-19.0-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-6.2-646CFF?logo=vite&logoColor=white)](https://vitejs.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-4.1-38B2AC?logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)

> **Production-grade, real-time cyber defense gateway and SOC dashboard engineered for Internet of Things (IoT) fleets.**  
> Detects anomalous behavior, MITRE ATT&CK vectors, brute-force intrusions, and C2 beacons using stateful heuristics, then automatically enforces quarantine policies via host firewalls (`iptables` / `nftables`).

---

## 📑 Table of Contents

- [Overview & Architecture](#-overview--architecture)
- [Key Features](#-key-features)
- [System Architecture Flow](#-system-architecture-flow)
- [Threat Detection Heuristics](#-threat-detection-heuristics)
- [Repository Structure](#-repository-structure)
- [Quickstart: React SOC Dashboard (Frontend)](#-quickstart-react-soc-dashboard-frontend)
- [Quickstart: Python Gateway Engine (Backend)](#-quickstart-python-gateway-engine-backend)
- [Hardware Deployment: Raspberry Pi (Live Capture)](#-hardware-deployment-raspberry-pi-live-capture)
- [MITRE ATT&CK Matrix Alignment](#-mitre-attck-matrix-alignment)
- [Contributing & License](#-contributing--license)

---

## 🌐 Overview & Architecture

Consumer and industrial IoT devices (smart cameras, door locks, environmental sensors, medical telemetry nodes) frequently lack host-based intrusion prevention agents and remain vulnerable to unauthenticated reconnaissance, credential guessing, and botnet recruitment.

The **IoT Threat Detection Gateway** bridges this gap by acting as an inline or tap security broker. It features a dual-component architecture:

1. **Enterprise React 19 SOC Dashboard**: High-fidelity operational console featuring real-time packet stream inspection, radar subnet topologies, Mean Time Between Incidents (MTBI) trend analysis, audio voice dispatch, forensic hex packet inspection, and RFC-4180 CSV incident exports.
2. **Python IoT Gateway Engine (`/iot_gateway`)**: Decoupled, stateful heuristic detection and automated firewall response engine that models IoT fleet behavior and can be bound directly to physical Linux network interfaces (`pyshark`/`tshark`) or run in software simulation.

---

## ⚡ Key Features

- 🛰️ **Subnet Device Radar & Topology**: Interactive radar sweeping subnet endpoints with real-time status (Healthy, Attacked, Quarantined, Offline) and port/protocol metadata.
- 🎯 **Multi-Vector Attack Simulation**: Inject realistic cyber attacks with one click:
  - **Port Scan Reconnaissance** (rapid multi-port discovery)
  - **Credential Brute-Force** (repeated authentication failures on port 22/80)
  - **C2 Command & Control Beaconing** (low-jitter periodic egress callbacks)
  - **Volume Flood / DDoS** (high-bandwidth packet saturation)
- 🔍 **Deep Forensics & Raw Hex Inspector**: Click any incident in the ledger to open a slide-out forensic drawer with L3/L4 packet header dissection, 16-byte hexadecimal memory dump, ASCII decode, and MITRE ATT&CK mapping.
- 📈 **Mean Time Between Incidents (MTBI) Analytics**: Quantifies security posture trajectory over time with mean delta tracking, stability ratings, and heuristic evaluation windows.
- 🛡️ **Automated Quarantine & Firewall Enforcement**: Instantly isolates hostile actors or infected internal nodes via dynamically generated Linux `iptables` / Windows `netsh` firewall rules, backed by a dry-run `safety_mode`.
- 🎙️ **Voice Dispatch System**: Hands-free synthetic audio warnings for high-severity threats using the browser Web Speech API.
- 📊 **Audit-Ready Reporting**: Instant one-click CSV export with RFC-4180 compliance, sanitizing commas and quotes for external SIEM integration.
- 🌓 **Enterprise Dual-Theme Engine**: Built with centralized CSS design tokens for Dark and Light operational SOC environments.

---

## 🏗️ System Architecture Flow

```text
       ┌───────────────────────────────────────────────────────────┐
       │                 IoT Device Fleet (Subnet)                 │
       │  [Smart Camera]  [Door Lock]  [Temp Sensor]  [Smart Plug] │
       └─────────────────────────────┬─────────────────────────────┘
                                     │ (Network Traffic: MQTT, HTTP, RTSP)
                                     ▼
                      ┌─────────────────────────────┐
                      │    Ingress Packet Stream    │
                      │ (Live Capture or Simulator) │
                      └──────────────┬──────────────┘
                                     │
                                     ▼
        ┌──────────────────────────────────────────────────────────┐
        │                 Stateful Detection Engine                │
        │                                                          │
        │  • Port Scan Tracker (Unique Ports in 10s Window)        │
        │  • Auth Failure Counter (Grouped by Source & Target)     │
        │  • C2 Beaconing Heuristic (Inter-Arrival Variance σ)     │
        │  • Volume Flood Aggregator (Bytes / 3s Sliding Window)   │
        └────────────────────────────┬─────────────────────────────┘
                                     │
                         Threat Alert Detected?
                                     │
                    ┌────────────────┴────────────────┐
                    │ YES                             │ NO
                    ▼                                 ▼
    ┌───────────────────────────────┐     ┌────────────────────────┐
    │    Automated Response Engine  │     │ Telemetry Buffer Only  │
    │                               │     └────────────────────────┘
    │ • Evaluate Quarantine Policy  │
    │ • Synthesize iptables Rules   │
    │ • Add Hostile IP to Blocklist │
    └───────────────┬───────────────┘
                    │
                    ▼
    ┌──────────────────────────────────────────────────────────────┐
    │                 Interactive SOC Operations Center            │
    │                                                              │
    │  [Live Threat Feed] [Hex Packet Inspector] [MTBI Trend Chart]│
    │  [Severity Filters] [Voice Audio Dispatch] [CSV SIEM Export] │
    └──────────────────────────────────────────────────────────────┘
```

---

## 🔬 Threat Detection Heuristics

| Threat Vector | Detection Rule & Algorithm | Threshold Default | Response Action |
| :--- | :--- | :--- | :--- |
| **Port Scan** | Measures cardinality of unique destination ports per `(src_ip, dst_ip)` in a 10s sliding window. | $\ge 15$ unique ports | `ISOLATE` attacker IP via `iptables -I FORWARD -s <ip> -j DROP` |
| **Brute Force** | Aggregates authentication rejection events (`auth_success == False`) grouped by `(src_ip, dst_ip, port)`. | $\ge 5$ failures in 10s | `ISOLATE` attacker IP |
| **C2 Beaconing** | Calculates standard deviation $\sigma$ of packet inter-arrival deltas $\Delta t$:<br>$\sigma = \sqrt{\frac{1}{N}\sum_{i=1}^N (\Delta t_i - \mu)^2}$ | $\sigma < 0.25\text{s}$ across $\ge 5$ connections | `ISOLATE` internal compromised device IP to prevent lateral movement |
| **Volume Flood** | Aggregates cumulative byte throughput per device in a sliding 3s window. | $\ge 25,000\text{ bytes}$ in 3s | `ISOLATE` egress stream |

---

## 📁 Repository Structure

```text
├── .github/
│   ├── workflows/
│   │   └── ci.yml                 # Automated CI test and build workflow
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md          # Standardized GitHub bug report template
│   │   └── feature_request.md     # Feature request template
│   └── PULL_REQUEST_TEMPLATE.md   # Pull request review checklist
├── iot_gateway/                   # Standalone Python Gateway Engine
│   ├── detection_engine.py        # Stateful sliding-window IDS detection heuristics
│   ├── response_engine.py         # Automated firewall enforcement & quarantine ledger
│   ├── traffic_simulator.py       # Realistic IoT device traffic & attack injector
│   ├── dashboard.py               # Lightweight FastAPI web dashboard & REST API
│   ├── main.py                    # Unified CLI runner & automated simulation script
│   ├── requirements.txt           # Python backend dependencies
│   └── README.md                  # Python gateway dedicated manual
├── public/                        # Static web assets & icons
├── src/                           # React 19 Frontend SOC Application
│   ├── components/
│   │   ├── AlertDetailDrawer.tsx  # Slide-out forensic packet inspector & hex dump
│   │   ├── AlertsDataTable.tsx    # Incident ledger with severity filters & CSV export
│   │   ├── MTBITrendAnalysis.tsx  # Mean Time Between Incidents trend analytics
│   │   ├── NetworkRadar.tsx       # Canvas-based real-time radar subnet scanner
│   │   ├── ObservabilityChart.tsx # Recharts 60-minute traffic & threat line chart
│   │   ├── VoiceAlertHUD.tsx      # Web Speech API synthesized audio dispatcher
│   │   ├── StatCardsRow.tsx       # Key SOC operational metric cards
│   │   └── ...                    # Additional modular SOC panels
│   ├── data/
│   │   └── mockData.ts            # Default device inventories & detection thresholds
│   ├── types.ts                   # Global TypeScript type definitions
│   ├── index.css                  # Theme tokens & Tailwind CSS root imports
│   ├── main.tsx                   # React application entry point
│   └── App.tsx                    # Main state orchestrator & view controller
├── .env.example                   # Environment configuration blueprint
├── .gitignore                     # Git ignore patterns for Node, Python, and OS files
├── CONTRIBUTING.md                # Contribution guidelines and code standards
├── LICENSE                        # MIT Open Source License
├── package.json                   # Node.js project manifest & scripts
├── SECURITY.md                    # Security policy & responsible vulnerability reporting
├── tsconfig.json                  # TypeScript compiler configuration
└── vite.config.ts                 # Vite build & bundler configuration
```

---

## 💻 Quickstart: React SOC Dashboard (Frontend)

### Prerequisites
- **Node.js**: v18.0.0 or higher (v20+ recommended)
- **npm** or **bun** / **yarn**

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/iot-threat-detection-gateway.git
cd iot-threat-detection-gateway
```

### 2. Install dependencies
```bash
npm install
```

### 3. Start the development server
```bash
npm run dev
```

Visit **`http://localhost:3000`** in your browser to interact with the full SOC dashboard.

### 4. Build for production
```bash
npm run build
```
Compiled static assets will be output to the `dist/` directory.

---

## 🐍 Quickstart: Python Gateway Engine (Backend)

The Python gateway runs independently and can be deployed on a gateway router, server, or virtual machine.

### Prerequisites
- **Python 3.9+**
- `pip` and `virtualenv`

### 1. Navigate to the Python gateway folder
```bash
cd iot_gateway
```

### 2. Create and activate a virtual environment
```bash
# macOS/Linux:
python3 -m venv venv
source venv/bin/activate

# Windows:
python -m venv venv
.\venv\Scripts\activate
```

### 3. Install requirements
```bash
pip install -r requirements.txt
```

### 4. Run the end-to-end automated test
Runs a complete simulation proving baseline telemetry, followed by sequentially injecting and detecting all 4 attacks with full console logs:
```bash
python main.py
```

### 5. (Optional) Run the FastAPI Web Dashboard
```bash
python main.py --web
```
Or directly with Uvicorn:
```bash
uvicorn dashboard:app --reload --host 0.0.0.0 --port 8000
```
Open **`http://localhost:8000`** to access the lightweight Python web dashboard.

---

## 🍓 Hardware Deployment: Raspberry Pi (Live Capture)

To use this software as a physical IoT security appliance between your home/office router and IoT devices:

1. **Hardware Requirements**:
   - Raspberry Pi 4 Model B or Raspberry Pi 5 (running Raspberry Pi OS 64-bit).
   - Dual Network Interfaces (e.g., built-in Ethernet `eth0` + USB Gigabit Ethernet adapter `eth1`, configured as a bridge or routing gateway).

2. **Install Network Capture Prerequisites**:
   ```bash
   sudo apt-get update
   sudo apt-get install -y tshark iptables tcpdump
   pip install pyshark
   ```

3. **Deploy Live Packet Sniffing**:
   Create a small ingress daemon `live_capture.py` inside `iot_gateway/`:
   ```python
   import pyshark
   from detection_engine import DetectionEngine
   from response_engine import ResponseEngine
   from traffic_simulator import Packet

   engine = DetectionEngine()
   responder = ResponseEngine(safety_mode=False)  # Enforce real iptables rules!

   capture = pyshark.LiveCapture(interface='eth0')
   print("[*] Gateway actively monitoring eth0 interface...")

   for raw_pkt in capture.sniff_continuously():
       try:
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
           alerts = engine.analyze_packets([pkt])
           for alert in alerts:
               responder.process_alert(alert)
       except (AttributeError, KeyError):
           continue
   ```

Because `DetectionEngine` and `ResponseEngine` only consume normalized `Packet` dataclasses, the exact same detection algorithms and response logic run seamlessly on live physical hardware!

---

## 🎯 MITRE ATT&CK Matrix Alignment

| Technique ID | Technique Name | Tactic | Simulated Attack Scenario |
| :--- | :--- | :--- | :--- |
| **[T1046](https://attack.mitre.org/techniques/T1046/)** | Network Service Discovery | Discovery | External scanner mapping open RTSP/HTTP ports across IoT devices |
| **[T1110.001](https://attack.mitre.org/techniques/T1110/001/)** | Password Guessing | Credential Access | Rapid dictionary authentication attempts against Smart Door Lock SSH |
| **[T1071.001](https://attack.mitre.org/techniques/T1071/001/)** | Web Protocols (C2) | Command & Control | Smart Plug firmware compromised with machine-interval callbacks |
| **[T1498.001](https://attack.mitre.org/techniques/T1498/001/)** | Direct Network Flood | Impact | Volumetric packet burst overwhelming local network bandwidth |

---

## 🤝 Contributing & License

Contributions, feature suggestions, and bug reports are welcome! Please review [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) before submitting pull requests.

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for details.
