import { IoTDevice, DetectionThresholds, ThreatAlert, AdaptiveBaselineConfig, SuppressedFalsePositive } from '../types';

export const GATEWAY_IP = '192.168.1.1';
export const EXTERNAL_ATTACKER_IP = '198.51.100.42';
export const C2_SERVER_IP = '203.0.113.88';

export const getInitialAlerts = (): ThreatAlert[] => {
  const now = Date.now();
  return [
    {
      id: 'ALT-0001',
      timestamp: now - 42 * 60 * 1000,
      category: 'PORT_SCAN',
      severity: 'HIGH',
      sourceIp: '198.51.100.42',
      targetIp: '192.168.1.10',
      detail: 'Rapid TCP port sweep: 18 ports probed within 1.2s reconnaissance burst.',
      evidence: { uniquePortsCount: 18, windowSec: 10.0, samplePorts: [21, 22, 23, 80, 443, 8080] },
      status: 'RESOLVED',
    },
    {
      id: 'ALT-0002',
      timestamp: now - 24 * 60 * 1000,
      category: 'BRUTE_FORCE',
      severity: 'HIGH',
      sourceIp: '198.51.100.42',
      targetIp: '192.168.1.11',
      detail: 'Credential brute-force login attack on Smart Lock management port 22.',
      evidence: { failedAttempts: 8, targetPort: 22, windowSec: 10.0 },
      status: 'RESOLVED',
    },
    {
      id: 'ALT-0003',
      timestamp: now - 12 * 60 * 1000,
      category: 'C2_BEACONING',
      severity: 'HIGH',
      sourceIp: '192.168.1.12',
      targetIp: '203.0.113.88',
      detail: 'Periodic low-jitter outbound command & control beacon pulses detected.',
      evidence: { packetCount: 6, intervalAvgSec: 1.05, jitterSec: 0.04 },
      status: 'ACTIVE',
    },
  ];
};

export const INITIAL_DEVICES: IoTDevice[] = [
  {
    id: 'cam-01',
    name: 'Smart Security Camera',
    ip: '192.168.1.10',
    mac: 'AA:BB:CC:10:20:30',
    deviceType: 'Security Camera',
    normalDestinations: ['52.14.99.102'],
    normalPorts: [443, 554],
    normalProtocols: ['HTTPS', 'TCP'],
    status: 'ONLINE',
    packetsSent: 142,
    packetsReceived: 98,
    bytesTotal: 184500,
    lastSeen: Date.now(),
  },
  {
    id: 'lock-01',
    name: 'Smart Door Lock',
    ip: '192.168.1.11',
    mac: 'AA:BB:CC:11:22:33',
    deviceType: 'Access Control',
    normalDestinations: ['34.210.45.88'],
    normalPorts: [8883],
    normalProtocols: ['MQTT', 'TCP'],
    status: 'ONLINE',
    packetsSent: 84,
    packetsReceived: 76,
    bytesTotal: 12400,
    lastSeen: Date.now(),
  },
  {
    id: 'sensor-01',
    name: 'Temp/Humidity Sensor',
    ip: '192.168.1.12',
    mac: 'AA:BB:CC:12:24:36',
    deviceType: 'Environment Sensor',
    normalDestinations: ['104.26.10.4'],
    normalPorts: [1883],
    normalProtocols: ['MQTT'],
    status: 'ONLINE',
    packetsSent: 65,
    packetsReceived: 32,
    bytesTotal: 8300,
    lastSeen: Date.now(),
  },
  {
    id: 'plug-01',
    name: 'Smart Power Plug',
    ip: '192.168.1.13',
    mac: 'AA:BB:CC:13:26:39',
    deviceType: 'Power Controller',
    normalDestinations: ['172.67.180.12'],
    normalPorts: [80, 443],
    normalProtocols: ['HTTP', 'TCP'],
    status: 'ONLINE',
    packetsSent: 92,
    packetsReceived: 88,
    bytesTotal: 19800,
    lastSeen: Date.now(),
  },
  {
    id: 'thermo-01',
    name: 'Smart Thermostat Hub',
    ip: '192.168.1.14',
    mac: 'AA:BB:CC:14:28:42',
    deviceType: 'Climate Control',
    normalDestinations: ['18.232.11.90'],
    normalPorts: [443],
    normalProtocols: ['HTTPS', 'TCP'],
    status: 'ONLINE',
    packetsSent: 110,
    packetsReceived: 104,
    bytesTotal: 34100,
    lastSeen: Date.now(),
  },
  {
    id: 'manager-01',
    name: 'Manager Workstation (DLP Agent)',
    ip: '192.168.1.15',
    mac: '00:1E:67:AA:23:49',
    deviceType: 'Workstation / Endpoint',
    normalDestinations: ['192.168.1.1', '52.14.99.102'],
    normalPorts: [443, 445],
    normalProtocols: ['HTTPS', 'TCP', 'USB'],
    status: 'ONLINE',
    packetsSent: 154,
    packetsReceived: 142,
    bytesTotal: 452000,
    lastSeen: Date.now(),
  },
];

export const DEFAULT_THRESHOLDS: DetectionThresholds = {
  portScanUniquePorts: 15,
  portScanWindowSec: 10.0,
  bruteForceFailures: 5,
  bruteForceWindowSec: 10.0,
  beaconingMinPackets: 5,
  beaconingMaxJitterSec: 0.25,
  beaconingWindowSec: 30.0,
  volumeFloodBytes: 25000,
  volumeFloodWindowSec: 3.0,
  usbExfiltrationBytes: 50 * 1024 * 1024,
  usbExfiltrationWindowSec: 30.0,
};

export const DEFAULT_ADAPTIVE_CONFIG: AdaptiveBaselineConfig = {
  enabled: true,
  maintenanceStartHour: 2,  // 02:00
  maintenanceEndHour: 5,    // 05:00
  maintenanceFactor: 2.2,   // 2.2x tolerance during maintenance
  offpeakFactor: 1.3,       // 1.3x tolerance off-peak
  mode: 'MANUAL_SIMULATED', // Set to simulated by default so user can directly play with scrubber!
  simulatedHour: 3.25,      // 03:15 AM — inside maintenance window by default
  autoSuppressMaintenanceSpikes: true,
};

export const INITIAL_SUPPRESSED_EVENTS: SuppressedFalsePositive[] = [
  {
    id: 'SUP-0001',
    timestamp: Date.now() - 36 * 60 * 1000,
    category: 'VOLUME_FLOOD',
    sourceIp: '52.14.99.102',
    targetIp: '192.168.1.10',
    rawMetric: 37500,
    metricUnit: 'Bytes',
    staticThreshold: 25000,
    adaptiveThreshold: 55000,
    regime: 'MAINTENANCE_WINDOW',
    multiplier: 2.2,
    reason: 'Scheduled OTA firmware update binary stream tolerated under Adaptive Baseline during MAINTENANCE_WINDOW. Dynamic threshold expanded to 55,000 B to prevent false isolation.',
    preventedAction: 'iptables -A FORWARD -s 52.14.99.102 -j DROP',
  },
  {
    id: 'SUP-0002',
    timestamp: Date.now() - 28 * 60 * 1000,
    category: 'PORT_SCAN',
    sourceIp: '192.168.1.1',
    targetIp: '192.168.1.10',
    rawMetric: 17,
    metricUnit: 'Unique Ports',
    staticThreshold: 15,
    adaptiveThreshold: 33,
    regime: 'MAINTENANCE_WINDOW',
    multiplier: 2.2,
    reason: 'Automated internal network asset discovery sweep (Lansweeper probe) tolerated. Dynamic port threshold scaled to 33 ports during maintenance hours.',
    preventedAction: 'iptables -A FORWARD -s 192.168.1.1 -j DROP',
  },
  {
    id: 'SUP-0003',
    timestamp: Date.now() - 14 * 60 * 1000,
    category: 'VOLUME_FLOOD',
    sourceIp: '18.232.11.90',
    targetIp: '192.168.1.14',
    rawMetric: 31200,
    metricUnit: 'Bytes',
    staticThreshold: 25000,
    adaptiveThreshold: 55000,
    regime: 'MAINTENANCE_WINDOW',
    multiplier: 2.2,
    reason: 'Batch climate telemetry history sync on Smart Thermostat Hub absorbed by Adaptive Baseline.',
    preventedAction: 'iptables -A FORWARD -s 18.232.11.90 -j DROP',
  },
];

export const PYTHON_CODE_FILES = {
  'usb_monitor.py': `"""
USB & Endpoint Activity Monitor for IoT Threat Detection Gateway
Simulates an endpoint telemetry agent (e.g. on MANAGER-LAPTOP / 192.168.1.15)
that monitors USB mass storage insertions, file copy volume, and air-gapped exfiltration.
"""
import time
from dataclasses import dataclass, asdict
from typing import List, Dict

@dataclass
class USBEvent:
    timestamp: float
    host_name: str
    host_ip: str
    user: str
    action: str
    device_name: str
    vendor_id: str
    drive_letter: str
    bytes_transferred: int
    files_copied: List[str]
    duration_sec: float
    is_authorized: bool

class USBMonitor:
    def __init__(self, host_name="MANAGER-LAPTOP", host_ip="192.168.1.15"):
        self.host_name = host_name
        self.host_ip = host_ip
        self.event_log = []

    def simulate_usb_exfiltration(self, bytes_to_copy=85 * 1024 * 1024, duration_sec=14.5):
        # Generates DLP exfiltration packets sent from endpoint agent to gateway
        ...
`,
  'traffic_simulator.py': `"""
Traffic Simulator for IoT Threat Detection & Hardening Gateway
Simulates normal network traffic for 5 IoT devices and injects 4 attack patterns.
"""
import time, random
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional

@dataclass
class Packet:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length: int
    flags: str
    auth_success: Optional[bool] = None
    payload_info: str = ""
    is_attack: bool = False
    attack_type: Optional[str] = None

@dataclass
class IoTDevice:
    device_id: str
    name: str
    ip: str
    mac: str
    device_type: str
    normal_destinations: List[str]
    normal_ports: List[int]
    normal_protocols: List[str]
    status: str = "ONLINE"

DEFAULT_DEVICES = {
    "192.168.1.10": IoTDevice("cam-01", "Smart Security Camera", "192.168.1.10", "AA:BB:CC:10:20:30", "Security Camera", ["52.14.99.102"], [443, 554], ["HTTPS", "TCP"]),
    "192.168.1.11": IoTDevice("lock-01", "Smart Door Lock", "192.168.1.11", "AA:BB:CC:11:22:33", "Access Control", ["34.210.45.88"], [8883], ["MQTT", "TCP"]),
    "192.168.1.12": IoTDevice("sensor-01", "Temp/Humidity Sensor", "192.168.1.12", "AA:BB:CC:12:24:36", "Environment Sensor", ["104.26.10.4"], [1883], ["MQTT"]),
    "192.168.1.13": IoTDevice("plug-01", "Smart Power Plug", "192.168.1.13", "AA:BB:CC:13:26:39", "Power Controller", ["172.67.180.12"], [80, 443], ["HTTP", "TCP"]),
    "192.168.1.14": IoTDevice("thermo-01", "Smart Thermostat Hub", "192.168.1.14", "AA:BB:CC:14:28:42", "Climate Control", ["18.232.11.90"], [443], ["HTTPS", "TCP"]),
}

class TrafficSimulator:
    def __init__(self, devices=None):
        self.devices = devices or DEFAULT_DEVICES
        self.packet_buffer = []

    def generate_normal_packet(self, device_ip=None):
        if not device_ip:
            device_ip = random.choice(list(self.devices.keys()))
        dev = self.devices[device_ip]
        dest_ip = random.choice(dev.normal_destinations)
        dest_port = random.choice(dev.normal_ports)
        proto = random.choice(dev.normal_protocols)
        pkt = Packet(
            timestamp=time.time(),
            src_ip=dev.ip, dst_ip=dest_ip,
            src_port=random.randint(32768, 61000), dst_port=dest_port,
            protocol=proto, length=random.randint(64, 512),
            flags="ACK,PSH", payload_info=f"Benign {dev.device_type} packet"
        )
        self.packet_buffer.append(pkt)
        return pkt

    def inject_port_scan(self, target_ip="192.168.1.10", attacker_ip="198.51.100.42", num_ports=18):
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 554, 8080, 8443, 8888, 9000, 9999, 1883, 3389][:num_ports]
        pkts, now = [], time.time()
        for idx, port in enumerate(ports):
            pkt = Packet(timestamp=now + (idx * 0.05), src_ip=attacker_ip, dst_ip=target_ip,
                         src_port=random.randint(40000, 60000), dst_port=port, protocol="TCP", length=60,
                         flags="SYN", payload_info=f"Port Recon -> TCP {port}", is_attack=True, attack_type="PORT_SCAN")
            pkts.append(pkt)
            self.packet_buffer.append(pkt)
        return pkts

    def inject_brute_force(self, target_ip="192.168.1.11", attacker_ip="198.51.100.42", attempts=8):
        pkts, now = [], time.time()
        for i in range(attempts):
            pkt = Packet(timestamp=now + (i * 0.2), src_ip=attacker_ip, dst_ip=target_ip,
                         src_port=random.randint(45000, 55000), dst_port=22, protocol="TCP", length=180,
                         flags="ACK,PSH", auth_success=False, payload_info=f"Auth Failed attempt {i+1}", is_attack=True, attack_type="BRUTE_FORCE")
            pkts.append(pkt)
            self.packet_buffer.append(pkt)
        return pkts

    def inject_c2_beaconing(self, compromised_ip="192.168.1.13", c2_ip="203.0.113.88", count=8, interval=2.5):
        pkts, now = [], time.time()
        for i in range(count):
            delta = interval + random.uniform(-0.04, 0.04)
            pkt = Packet(timestamp=now + (i * delta), src_ip=compromised_ip, dst_ip=c2_ip,
                         src_port=random.randint(35000, 42000), dst_port=8443, protocol="HTTPS", length=200,
                         flags="ACK,PSH", payload_info=f"C2 Periodic Heartbeat #{i+1}", is_attack=True, attack_type="C2_BEACONING")
            pkts.append(pkt)
            self.packet_buffer.append(pkt)
        return pkts

    def inject_volume_flood(self, target_ip="192.168.1.10", attacker_ip="198.51.100.42", packet_count=35):
        pkts, now = [], time.time()
        for i in range(packet_count):
            pkt = Packet(timestamp=now + (i * 0.02), src_ip=attacker_ip, dst_ip=target_ip,
                         src_port=random.randint(30000, 60000), dst_port=80, protocol="UDP", length=1400,
                         flags="NONE", payload_info=f"Flood packet #{i+1}", is_attack=True, attack_type="VOLUME_FLOOD")
            pkts.append(pkt)
            self.packet_buffer.append(pkt)
        return pkts
`,
  'detection_engine.py': `"""
Detection Engine for IoT Threat Detection & Hardening Gateway
Rule-based heuristic analysis (Port Scan, Brute-Force, C2 Beaconing, Volume Flood, DLP)
with 'Adaptive Baseline' heuristic for diurnal maintenance window false-positive mitigation.
"""
import time, math
from dataclasses import dataclass, asdict
from typing import List, Dict, Tuple, Optional
from collections import defaultdict

@dataclass
class AdaptiveBaselineConfig:
    enabled: bool = True
    maintenance_start_hour: int = 2        # 02:00
    maintenance_end_hour: int = 5          # 05:00
    maintenance_factor: float = 2.2        # +2.2x threshold expansion during maintenance
    offpeak_factor: float = 1.3            # +1.3x threshold expansion off-peak
    simulated_hour: Optional[float] = None
    auto_suppress_maintenance_spikes: bool = True

class DetectionEngine:
    def __init__(self, adaptive_config=None):
        self.adaptive_config = adaptive_config or AdaptiveBaselineConfig()
        self.alerts = []
        self.suppressed_false_positives = []
        self._counter = 1
        self.PORT_SCAN_PORTS = 15
        self.PORT_SCAN_SEC = 10.0
        self.BRUTE_FORCE_FAILS = 5
        self.FLOOD_BYTES = 25000
        self.FLOOD_SEC = 3.0

    def get_current_regime(self, timestamp=None):
        if not self.adaptive_config.enabled:
            return ("PEAK_HOURS", 1.0, "Adaptive Baseline disabled")
        hour = self.adaptive_config.simulated_hour if self.adaptive_config.simulated_hour is not None else time.localtime().tm_hour
        if self.adaptive_config.maintenance_start_hour <= hour < self.adaptive_config.maintenance_end_hour:
            return ("MAINTENANCE_WINDOW", self.adaptive_config.maintenance_factor, "Scheduled maintenance window active")
        if hour >= 18 or hour < 2 or (5 <= hour < 8):
            return ("OFF_PEAK", self.adaptive_config.offpeak_factor, "Quiescent off-peak window")
        return ("PEAK_HOURS", 1.0, "Daytime active peak window")

    def analyze_packets(self, packets):
        new_alerts = []
        now = time.time()
        regime, mult, _ = self.get_current_regime(now)
        effective_flood = int(self.FLOOD_BYTES * mult)
        effective_ports = int(self.PORT_SCAN_PORTS * mult)

        # 1. Port Scan Check with Adaptive Tolerance
        ps_map = defaultdict(set)
        for p in packets:
            if p.timestamp >= (now - self.PORT_SCAN_SEC):
                ps_map[(p.src_ip, p.dst_ip)].add(p.dst_port)
        for (src, dst), ports in ps_map.items():
            if len(ports) >= self.PORT_SCAN_PORTS:
                if len(ports) < effective_ports and self.adaptive_config.enabled:
                    # Suppressed false positive during maintenance
                    self.suppressed_false_positives.append({"category": "PORT_SCAN", "src": src, "dst": dst, "regime": regime})
                    continue
                new_alerts.append(Alert(f"ALT-{self._counter:04d}", now, "PORT_SCAN", "HIGH", src, dst,
                                        f"Port scan: {len(ports)} ports probed [Regime: {regime}, Limit: {effective_ports}]."))
                self._counter += 1

        # 2. Volume Flood Check with Adaptive Tolerance
        vf_map = defaultdict(int)
        for p in packets:
            if p.timestamp >= (now - self.FLOOD_SEC) and getattr(p, 'protocol', '') != 'USB':
                vf_map[(p.src_ip, p.dst_ip)] += p.length
        for (src, dst), total_bytes in vf_map.items():
            if total_bytes >= self.FLOOD_BYTES:
                if total_bytes < effective_flood and self.adaptive_config.enabled:
                    self.suppressed_false_positives.append({"category": "VOLUME_FLOOD", "src": src, "dst": dst, "regime": regime})
                    continue
                new_alerts.append(Alert(f"ALT-{self._counter:04d}", now, "VOLUME_FLOOD", "HIGH", src, dst,
                                        f"Volume surge: {total_bytes:,}B [Regime: {regime}, Limit: {effective_flood:,}B]."))
                self._counter += 1

        self.alerts.extend(new_alerts)
        return new_alerts
`,
  'response_engine.py': `"""
Response Engine for IoT Threat Detection Gateway
Synthesizes iptables quarantine rules and maintains the IP blocklist.
"""
import time, os, subprocess
from dataclasses import dataclass, asdict

@dataclass
class ResponseAction:
    action_id: str
    timestamp: float
    alert_id: str
    target_ip: str
    category: str
    action: str
    reason: str
    iptables_command: str
    windows_command: str
    executed_live: bool
    status: str

    def to_dict(self):
        return asdict(self)

class ResponseEngine:
    def __init__(self, safety_mode=True):
        self.safety_mode = safety_mode
        self.blocklist = set()
        self.action_history = []
        self._counter = 1

    def process_alert(self, alert):
        ip = alert.source_ip
        self.blocklist.add(ip)
        iptables_cmd = f"iptables -A FORWARD -s {ip} -j DROP && iptables -A INPUT -s {ip} -j DROP"
        windows_cmd = f'netsh advfirewall firewall add rule name="IoT_Quarantine_{ip}" dir=in action=block remoteip={ip}'
        
        print(f"[FIREWALL ACTION] Generated rule for {ip}: {iptables_cmd}")
        action = ResponseAction(
            action_id=f"ACT-{self._counter:04d}",
            timestamp=time.time(),
            alert_id=alert.alert_id,
            target_ip=ip,
            category=alert.category,
            action="ISOLATE",
            reason=f"Automated quarantine triggered by {alert.category} alert.",
            iptables_command=iptables_cmd,
            windows_command=windows_cmd,
            executed_live=not self.safety_mode,
            status="ACTIVE_BLOCK"
        )
        self._counter += 1
        self.action_history.append(action)
        return action

    def unblock_ip(self, ip):
        if ip in self.blocklist:
            self.blocklist.remove(ip)
            for a in self.action_history:
                if a.target_ip == ip and a.status == "ACTIVE_BLOCK":
                    a.status = "REVERTED"
            return True
        return False
`,
  'main.py': `"""
Unified CLI entrypoint. Run 'python main.py' to run full automated demo,
or 'python main.py --web' to run FastAPI dashboard.
"""
import sys, argparse
from traffic_simulator import TrafficSimulator, DEFAULT_DEVICES
from detection_engine import DetectionEngine
from response_engine import ResponseEngine

def run_demo():
    sim = TrafficSimulator()
    det = DetectionEngine()
    resp = ResponseEngine(safety_mode=True)
    print("Running baseline...")
    for _ in range(5): sim.generate_normal_packet()
    
    print("Injecting Port Scan...")
    sim.inject_port_scan()
    for a in det.analyze_packets(sim.packet_buffer):
        resp.process_alert(a)
        
    print("Done! View summary or launch web UI with: python main.py --web")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--web", action="store_true")
    args = parser.parse_args()
    if args.web:
        import uvicorn
        uvicorn.run("dashboard:app", host="0.0.0.0", port=8000, reload=True)
    else:
        run_demo()
`,
  'README.md': `# Setup & Execution Instructions on Windows

1. Install Python 3.9+ and open Command Prompt:
   python --version

2. Create virtual environment:
   python -m venv venv
   venv\\Scripts\\activate.bat

3. Install dependencies:
   pip install -r requirements.txt

4. Run CLI Demo:
   python main.py

5. Or Run Web Dashboard:
   python main.py --web
   (Open http://localhost:8000 in your browser)
`,
};
