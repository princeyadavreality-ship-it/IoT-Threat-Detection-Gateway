"""
Web Dashboard for IoT Threat Detection & Hardening Gateway
==========================================================
Built with FastAPI to display live IoT device inventory, security alerts,
response actions, and interactive attack injection controls.

Run on Windows/Linux:
    uvicorn dashboard:app --reload --host 0.0.0.0 --port 8000
Or simply:
    python main.py
"""

import time
import os
import json
from typing import Dict, List, Optional
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

try:
    from traffic_simulator import TrafficSimulator, DEFAULT_DEVICES
    from detection_engine import DetectionEngine, Alert
    from response_engine import ResponseEngine, ResponseAction
except ImportError:
    from .traffic_simulator import TrafficSimulator, DEFAULT_DEVICES
    from .detection_engine import DetectionEngine, Alert
    from .response_engine import ResponseEngine, ResponseAction

# Initialize Shared Gateway Services
simulator = TrafficSimulator()
detection_engine = DetectionEngine()
response_engine = ResponseEngine(safety_mode=True)

app = FastAPI(
    title="IoT Threat Detection & Hardening Gateway",
    description="Network security gateway monitoring IoT device traffic and isolating compromised nodes",
    version="1.0.0"
)

# Seed with some initial benign traffic
for _ in range(12):
    simulator.generate_normal_packet()


class AttackRequest(BaseModel):
    attack_type: str  # 'port_scan', 'brute_force', 'c2_beaconing', 'volume_flood'
    target_ip: Optional[str] = None


class UnblockRequest(BaseModel):
    ip: str


class SafetyToggleRequest(BaseModel):
    safety_mode: bool


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """
    Serves a modern, responsive HTML dashboard for the IoT gateway.
    Self-contained with responsive styling, status badges, and live API hooks.
    """
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IoT Threat Detection & Hardening Gateway</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0b0f19;
            --surface: #131b2e;
            --surface-border: #1e293b;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
            --accent: #3b82f6;
            --danger: #ef4444;
            --danger-bg: rgba(239, 68, 68, 0.12);
            --warning: #f59e0b;
            --warning-bg: rgba(245, 158, 11, 0.12);
            --success: #10b981;
            --success-bg: rgba(16, 185, 129, 0.12);
            --font-main: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            --font-mono: 'JetBrains Mono', monospace;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            background-color: var(--bg);
            color: var(--text-main);
            font-family: var(--font-main);
            padding: 24px;
            line-height: 1.5;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--surface-border);
            flex-wrap: wrap;
            gap: 16px;
        }
        .title-group h1 { font-size: 22px; font-weight: 700; color: #fff; }
        .title-group p { font-size: 13px; color: var(--text-muted); }
        .btn-bar { display: flex; gap: 10px; align-items: center; }
        .btn {
            background: var(--surface);
            color: #fff;
            border: 1px solid var(--surface-border);
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .btn:hover { border-color: var(--accent); }
        .btn-primary { background: var(--accent); border-color: var(--accent); }
        .btn-primary:hover { opacity: 0.9; }
        .btn-danger { background: var(--danger); border-color: var(--danger); }
        
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }
        .card {
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 12px;
            padding: 18px;
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 14px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--surface-border);
        }
        .card-title { font-size: 15px; font-weight: 600; color: #fff; }
        
        /* Tables */
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { text-align: left; padding: 10px 12px; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--surface-border); }
        td { padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.04); vertical-align: top; }
        .mono { font-family: var(--font-mono); font-size: 12px; }
        
        /* Badges */
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }
        .badge-high { background: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger); }
        .badge-med { background: var(--warning-bg); color: var(--warning); border: 1px solid var(--warning); }
        .badge-low { background: var(--success-bg); color: var(--success); border: 1px solid var(--success); }
        .badge-isolated { background: var(--danger-bg); color: var(--danger); border: 1px solid var(--danger); font-weight: 700; }
        .badge-online { background: var(--success-bg); color: var(--success); border: 1px solid var(--success); }
        
        .code-box {
            background: #060911;
            padding: 8px 12px;
            border-radius: 6px;
            font-family: var(--font-mono);
            font-size: 11px;
            color: #38bdf8;
            word-break: break-all;
        }
        
        .inject-bar {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 10px;
        }
        .inject-btn {
            background: #1e293b;
            color: #f8fafc;
            border: 1px solid #334155;
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
        }
        .inject-btn:hover { background: #334155; border-color: var(--accent); }
    </style>
</head>
<body>

    <div class="header">
        <div class="title-group">
            <h1>🛡️ IoT Threat Detection & Hardening Gateway</h1>
            <p>Monitors 5 IoT devices, analyzes network flows, and generates automated iptables isolation rules.</p>
        </div>
        <div class="btn-bar">
            <button class="btn btn-primary" onclick="runScan()">🔍 Run Scan Now</button>
            <button class="btn" onclick="toggleSafety()" id="safetyBtn">🔒 Safety Flag: ON (Simulated)</button>
            <button class="btn" onclick="fetchData()">🔄 Refresh</button>
        </div>
    </div>

    <!-- Attack Injector Sandbox -->
    <div class="card" style="margin-bottom: 24px;">
        <div class="card-header">
            <span class="card-title">⚡ Attack Simulator (Inject Real Test Patterns)</span>
            <span style="font-size: 12px; color: var(--text-muted)">Injects realistic attack streams into the detection engine</span>
        </div>
        <div class="inject-bar">
            <button class="inject-btn" onclick="injectAttack('port_scan')">🎯 Inject 1: Port Scan (18 Ports Rapid Sweep)</button>
            <button class="inject-btn" onclick="injectAttack('brute_force')">🔑 Inject 2: Brute-Force Login (8 Failed Auths)</button>
            <button class="inject-btn" onclick="injectAttack('c2_beaconing')">📡 Inject 3: C2 Beaconing (Fixed-interval Low Jitter)</button>
            <button class="inject-btn" onclick="injectAttack('volume_flood')">🌊 Inject 4: Volume Flood (DDoS/Exfil Burst)</button>
        </div>
    </div>

    <div class="grid">
        <!-- 1. Monitored Devices -->
        <div class="card" style="grid-column: 1 / -1;">
            <div class="card-header">
                <span class="card-title">📡 Monitored IoT Subnet (192.168.1.10 - 14)</span>
                <span id="deviceCount" style="font-size: 12px; color: var(--text-muted)">5 Devices Active</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Device Name</th>
                        <th>IP Address</th>
                        <th>MAC Address</th>
                        <th>Type</th>
                        <th>Normal Ports/Protocols</th>
                        <th>Gateway Status</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody id="deviceTableBody">
                    <!-- Populated dynamically -->
                </tbody>
            </table>
        </div>

        <!-- 2. Security Alerts -->
        <div class="card" style="grid-column: span 2;">
            <div class="card-header">
                <span class="card-title">🚨 Detected Threat Alerts</span>
                <span id="alertCount" style="font-size: 12px; color: var(--danger)">0 Active Alerts</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Alert ID</th>
                        <th>Category</th>
                        <th>Severity</th>
                        <th>Source IP</th>
                        <th>Target IP</th>
                        <th>Forensic Detail</th>
                    </tr>
                </thead>
                <tbody id="alertsTableBody">
                    <!-- Populated dynamically -->
                </tbody>
            </table>
        </div>

        <!-- 3. Automated Hardening Actions -->
        <div class="card">
            <div class="card-header">
                <span class="card-title">🛡️ Response & Firewall Ledger</span>
                <span id="quarantineCount" style="font-size: 12px; color: var(--warning)">0 Quarantined</span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Target IP</th>
                        <th>Action</th>
                        <th>Generated iptables Command</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="responseTableBody">
                    <!-- Populated dynamically -->
                </tbody>
            </table>
        </div>
    </div>

    <script>
        async function fetchData() {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();
                renderUI(data);
            } catch (err) {
                console.error("Failed to load status", err);
            }
        }

        function renderUI(data) {
            // Render Devices
            const devTbody = document.getElementById('deviceTableBody');
            devTbody.innerHTML = '';
            for (const [ip, dev] of Object.entries(data.devices)) {
                const isBlocked = data.blocklist.includes(ip);
                const statusBadge = isBlocked 
                    ? '<span class="badge badge-isolated">QUARANTINED / ISOLATED</span>'
                    : '<span class="badge badge-online">ONLINE / MONITORED</span>';
                
                const actionBtn = isBlocked
                    ? `<button class="btn btn-primary" style="padding:4px 10px; font-size:11px" onclick="unblockIp('${ip}')">Lift Quarantine</button>`
                    : `<span style="color:var(--text-muted); font-size:11px">Protected</span>`;

                devTbody.innerHTML += `
                    <tr>
                        <td><strong>${dev.name}</strong></td>
                        <td class="mono">${dev.ip}</td>
                        <td class="mono" style="color:var(--text-muted)">${dev.mac}</td>
                        <td>${dev.device_type}</td>
                        <td class="mono">${dev.normal_protocols.join(', ')} (${dev.normal_ports.join(', ')})</td>
                        <td>${statusBadge}</td>
                        <td>${actionBtn}</td>
                    </tr>
                `;
            }

            // Render Alerts
            const alertTbody = document.getElementById('alertsTableBody');
            alertTbody.innerHTML = '';
            document.getElementById('alertCount').innerText = `${data.alerts.length} Total Alerts`;

            if (data.alerts.length === 0) {
                alertTbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-muted); padding:20px;">No security alerts detected. Subnet traffic is normal.</td></tr>`;
            } else {
                data.alerts.slice().reverse().forEach(alt => {
                    const badgeClass = alt.severity === 'HIGH' ? 'badge-high' : alt.severity === 'MEDIUM' ? 'badge-med' : 'badge-low';
                    alertTbody.innerHTML += `
                        <tr>
                            <td class="mono"><strong>${alt.alert_id}</strong></td>
                            <td><span class="badge ${badgeClass}">${alt.category}</span></td>
                            <td><strong style="color:${alt.severity === 'HIGH' ? 'var(--danger)' : 'var(--warning)'}">${alt.severity}</strong></td>
                            <td class="mono">${alt.source_ip}</td>
                            <td class="mono">${alt.target_ip}</td>
                            <td>${alt.detail}</td>
                        </tr>
                    `;
                });
            }

            // Render Response Ledger
            const respTbody = document.getElementById('responseTableBody');
            respTbody.innerHTML = '';
            document.getElementById('quarantineCount').innerText = `${data.blocklist.length} Quarantined`;

            if (data.response_actions.length === 0) {
                respTbody.innerHTML = `<tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:20px;">No quarantine actions executed yet.</td></tr>`;
            } else {
                data.response_actions.slice().reverse().forEach(act => {
                    respTbody.innerHTML += `
                        <tr>
                            <td class="mono"><strong>${act.target_ip}</strong></td>
                            <td><span class="badge ${act.action === 'ISOLATE' ? 'badge-isolated' : 'badge-low'}">${act.action}</span></td>
                            <td><div class="code-box">${act.iptables_command}</div></td>
                            <td><span style="font-size:11px; font-weight:600; color:${act.status === 'ACTIVE_BLOCK' ? 'var(--danger)' : 'var(--text-muted)'}">${act.status}</span></td>
                        </tr>
                    `;
                });
            }

            // Update safety button
            const safetyBtn = document.getElementById('safetyBtn');
            safetyBtn.innerText = data.safety_mode 
                ? '🔒 Safety Flag: ON (Simulated)' 
                : '⚠️ Safety Flag: OFF (Real OS Commands)';
            safetyBtn.style.borderColor = data.safety_mode ? 'var(--surface-border)' : 'var(--danger)';
        }

        async function runScan() {
            await fetch('/api/scan', { method: 'POST' });
            fetchData();
        }

        async function injectAttack(type) {
            await fetch('/api/inject', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ attack_type: type })
            });
            // Automatically analyze right after injection
            await fetch('/api/scan', { method: 'POST' });
            fetchData();
        }

        async function unblockIp(ip) {
            await fetch('/api/unblock', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip: ip })
            });
            fetchData();
        }

        async function toggleSafety() {
            const current = document.getElementById('safetyBtn').innerText.includes('ON');
            await fetch('/api/toggle_safety', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ safety_mode: !current })
            });
            fetchData();
        }

        // Initial fetch and 4s auto-refresh
        fetchData();
        setInterval(fetchData, 4000);
    </script>
</body>
</html>
    """
    return HTMLResponse(content=html_content)


@app.get("/api/status")
async def get_status():
    """
    Returns JSON state of devices, alerts, response history, and active blocklist.
    """
    return {
        "devices": {ip: dev.to_dict() if hasattr(dev, 'to_dict') else dev.__dict__ for ip, dev in simulator.devices.items()},
        "alerts": [alt.to_dict() for alt in detection_engine.alerts],
        "response_actions": [act.to_dict() for act in response_engine.action_history],
        "blocklist": list(response_engine.blocklist),
        "safety_mode": response_engine.safety_mode,
        "packet_count": len(simulator.packet_buffer)
    }


@app.post("/api/scan")
async def run_scan():
    """
    Runs detection engine over currently buffered packets,
    dispatches new alerts to the response engine, and updates firewall rules.
    """
    # Analyze recent packets
    recent_packets = simulator.packet_buffer[-150:] if simulator.packet_buffer else []
    new_alerts = detection_engine.analyze_packets(recent_packets)

    new_actions = []
    for alert in new_alerts:
        action = response_engine.process_alert(alert)
        new_actions.append(action.to_dict())

    return {
        "status": "success",
        "new_alerts_detected": len(new_alerts),
        "new_actions_taken": len(new_actions)
    }


@app.post("/api/inject")
async def inject_attack_endpoint(req: AttackRequest):
    """
    Injects one of the 4 realistic attack patterns into the traffic simulator stream.
    """
    attack_type = req.attack_type.lower()
    injected_count = 0

    if attack_type == "port_scan":
        target = req.target_ip or "192.168.1.10"  # Target the camera
        pkts = simulator.inject_port_scan(target_ip=target, num_ports=18)
        injected_count = len(pkts)
    elif attack_type == "brute_force":
        target = req.target_ip or "192.168.1.11"  # Target the smart lock
        pkts = simulator.inject_brute_force(target_ip=target, attempts=8)
        injected_count = len(pkts)
    elif attack_type == "c2_beaconing":
        compromised = req.target_ip or "192.168.1.13"  # Compromised power plug
        pkts = simulator.inject_c2_beaconing(compromised_ip=compromised, count=8)
        injected_count = len(pkts)
    elif attack_type == "volume_flood":
        target = req.target_ip or "192.168.1.10"  # Flood the camera
        pkts = simulator.inject_volume_flood(target_ip=target, packet_count=35)
        injected_count = len(pkts)
    else:
        return JSONResponse({"status": "error", "message": f"Unknown attack type {attack_type}"}, status_code=400)

    return {
        "status": "success",
        "attack_type": attack_type,
        "packets_injected": injected_count
    }


@app.post("/api/unblock")
async def unblock_endpoint(req: UnblockRequest):
    """
    Lifts quarantine for an IP address.
    """
    success = response_engine.unblock_ip(req.ip)
    return {"status": "success" if success else "not_found", "unblocked_ip": req.ip}


@app.post("/api/toggle_safety")
async def toggle_safety_endpoint(req: SafetyToggleRequest):
    """
    Toggles dry-run safety mode.
    """
    response_engine.set_safety_mode(req.safety_mode)
    return {"status": "success", "safety_mode": response_engine.safety_mode}
