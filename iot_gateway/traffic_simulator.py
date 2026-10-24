"""
Traffic Simulator for IoT Threat Detection & Hardening Gateway
==============================================================
Simulates normal network traffic for 5 IoT devices and provides realistic
cyber attack injectors (Port Scan, Brute-Force, C2 Beaconing, Volume Flood).

Author: IoT Gateway Prototype
Designed for easy swap with live network capture (e.g. pyshark / scapy).
"""

import time
import random
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional


@dataclass
class Packet:
    """
    Represents a single captured or simulated network packet.
    Matches standard IP/TCP/UDP packet metadata for detection analysis.
    """
    timestamp: float          # Unix epoch timestamp (seconds)
    src_ip: str              # Source IP address (e.g. 192.168.1.10)
    dst_ip: str              # Destination IP address
    src_port: int            # Source port number
    dst_port: int            # Destination port number (e.g. 80, 443, 22, 1883)
    protocol: str            # Protocol name: 'TCP', 'UDP', 'MQTT', 'HTTP', 'HTTPS'
    length: int              # Packet payload length in bytes
    flags: str               # TCP flags (e.g. 'SYN', 'ACK', 'FIN', 'PSH')
    auth_success: Optional[bool] = None  # None for normal traffic, False for failed auth, True for success
    payload_info: str = ""   # Descriptive summary of packet contents
    is_attack: bool = False  # Ground-truth simulation label (for telemetry evaluation)
    attack_type: Optional[str] = None

    def to_dict(self) -> Dict:
        """Convert packet to JSON-serializable dictionary."""
        return asdict(self)


@dataclass
class IoTDevice:
    """
    Metadata for monitored IoT devices in the local smart home/office network.
    """
    device_id: str
    name: str
    ip: str
    mac: str
    device_type: str
    normal_destinations: List[str]
    normal_ports: List[int]
    normal_protocols: List[str]
    status: str = "ONLINE"  # 'ONLINE', 'COMPROMISED', 'ISOLATED'


# Standard network configuration for simulated local smart environment
GATEWAY_IP = "192.168.1.1"
EXTERNAL_ATTACKER_IP = "198.51.100.42"
C2_SERVER_IP = "203.0.113.88"

# 5 Monitored Local IoT Devices
DEFAULT_DEVICES: Dict[str, IoTDevice] = {
    "192.168.1.10": IoTDevice(
        device_id="cam-01",
        name="Smart Security Camera",
        ip="192.168.1.10",
        mac="AA:BB:CC:10:20:30",
        device_type="Security Camera",
        normal_destinations=["52.14.99.102"],  # Cloud NVR Video Ingestion
        normal_ports=[443, 554],               # HTTPS, RTSP streaming
        normal_protocols=["HTTPS", "TCP"]
    ),
    "192.168.1.11": IoTDevice(
        device_id="lock-01",
        name="Smart Door Lock",
        ip="192.168.1.11",
        mac="AA:BB:CC:11:22:33",
        device_type="Access Control",
        normal_destinations=["34.210.45.88"],  # Smart Lock Cloud Broker
        normal_ports=[8883],                   # Secure MQTT
        normal_protocols=["MQTT", "TCP"]
    ),
    "192.168.1.12": IoTDevice(
        device_id="sensor-01",
        name="Temp/Humidity Sensor",
        ip="192.168.1.12",
        mac="AA:BB:CC:12:24:36",
        device_type="Environment Sensor",
        normal_destinations=["104.26.10.4"],   # Telemetry Cloud
        normal_ports=[1883],                   # MQTT
        normal_protocols=["MQTT"]
    ),
    "192.168.1.13": IoTDevice(
        device_id="plug-01",
        name="Smart Power Plug",
        ip="192.168.1.13",
        mac="AA:BB:CC:13:26:39",
        device_type="Power Controller",
        normal_destinations=["172.67.180.12"], # Cloud Relay
        normal_ports=[80, 443],                # HTTP/HTTPS status check
        normal_protocols=["HTTP", "TCP"]
    ),
    "192.168.1.14": IoTDevice(
        device_id="thermo-01",
        name="Smart Thermostat Hub",
        ip="192.168.1.14",
        mac="AA:BB:CC:14:28:42",
        device_type="Climate Control",
        normal_destinations=["18.232.11.90"],  # Weather API / HVAC Schedule Sync
        normal_ports=[443],                    # HTTPS
        normal_protocols=["HTTPS", "TCP"]
    )
}


class TrafficSimulator:
    """
    Generates realistic traffic flows for the 5 IoT devices, interspersed with
    occasional background benign traffic or injected malicious attack vectors.
    """

    def __init__(self, devices: Optional[Dict[str, IoTDevice]] = None):
        self.devices = devices or DEFAULT_DEVICES
        self.packet_buffer: List[Packet] = []

    def generate_normal_packet(self, device_ip: Optional[str] = None) -> Packet:
        """
        Generates a realistic benign packet for an IoT device based on its normal profile.
        """
        if not device_ip or device_ip not in self.devices:
            device_ip = random.choice(list(self.devices.keys()))

        device = self.devices[device_ip]
        dest_ip = random.choice(device.normal_destinations)
        dest_port = random.choice(device.normal_ports)
        proto = random.choice(device.normal_protocols)

        # Realistic payload sizing per device profile
        if device.device_type == "Security Camera":
            payload_len = random.randint(700, 1450)
            payload_info = "RTSP Video Stream Fragment"
        elif device.device_type == "Access Control":
            payload_len = random.randint(64, 180)
            payload_info = "MQTT Keep-Alive / State: LOCKED"
        elif device.device_type == "Environment Sensor":
            payload_len = random.randint(48, 120)
            payload_info = f"Telemetry: {random.randint(20,26)}C, {random.randint(40,65)}% RH"
        elif device.device_type == "Power Controller":
            payload_len = random.randint(80, 220)
            payload_info = f"Power Metric: {round(random.uniform(12.5, 95.0), 1)}W"
        else:
            payload_len = random.randint(150, 380)
            payload_info = "HVAC Schedule Sync"

        packet = Packet(
            timestamp=time.time(),
            src_ip=device.ip,
            dst_ip=dest_ip,
            src_port=random.randint(32768, 61000),
            dst_port=dest_port,
            protocol=proto,
            length=payload_len,
            flags="ACK,PSH",
            auth_success=None,
            payload_info=payload_info,
            is_attack=False
        )
        self.packet_buffer.append(packet)
        return packet

    # =========================================================================
    # ATTACK INJECTORS
    # =========================================================================

    def inject_port_scan(self, target_ip: str = "192.168.1.10",
                         attacker_ip: str = EXTERNAL_ATTACKER_IP,
                         num_ports: int = 18) -> List[Packet]:
        """
        ATTACK PATTERN A: Port Scan
        A single external source rapidly sweeps across 15+ different ports on a target
        IoT device (e.g. Camera or Thermostat) within a short window to map exposed services.
        """
        scan_ports = [
            21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 554, 8080, 8443,
            8888, 9000, 9999, 1883, 3389, 5000, 8000
        ][:num_ports]

        packets: List[Packet] = []
        now = time.time()

        for idx, port in enumerate(scan_ports):
            pkt = Packet(
                timestamp=now + (idx * 0.05),  # 50ms intervals = rapid sweep
                src_ip=attacker_ip,
                dst_ip=target_ip,
                src_port=random.randint(40000, 60000),
                dst_port=port,
                protocol="TCP",
                length=60,                     # Typical TCP SYN probe size
                flags="SYN",
                auth_success=None,
                payload_info=f"Port Recon Probe -> TCP Port {port}",
                is_attack=True,
                attack_type="PORT_SCAN"
            )
            packets.append(pkt)
            self.packet_buffer.append(pkt)

        return packets

    def inject_brute_force(self, target_ip: str = "192.168.1.11",
                           attacker_ip: str = EXTERNAL_ATTACKER_IP,
                           target_port: int = 22,
                           attempts: int = 8) -> List[Packet]:
        """
        ATTACK PATTERN B: Brute-Force Login
        A malicious host attempts rapid repeated authentication logins (SSH/HTTP/Telnet)
        against an IoT device, resulting in repeated failed authentication responses.
        """
        packets: List[Packet] = []
        now = time.time()

        for i in range(attempts):
            pkt = Packet(
                timestamp=now + (i * 0.25),  # 250ms spacing
                src_ip=attacker_ip,
                dst_ip=target_ip,
                src_port=random.randint(45000, 55000),
                dst_port=target_port,
                protocol="TCP",
                length=random.randint(120, 240),
                flags="ACK,PSH",
                auth_success=False,          # Failed authentication flag
                payload_info=f"Auth Failed: Attempt {i+1}/{attempts} (user=admin/root)",
                is_attack=True,
                attack_type="BRUTE_FORCE"
            )
            packets.append(pkt)
            self.packet_buffer.append(pkt)

        return packets

    def inject_c2_beaconing(self, compromised_ip: str = "192.168.1.13",
                            c2_ip: str = C2_SERVER_IP,
                            count: int = 8,
                            interval: float = 2.5,
                            jitter: float = 0.03) -> List[Packet]:
        """
        ATTACK PATTERN C: Command & Control (C2) Beaconing
        A compromised IoT device phones home to an external malicious server at a
        suspiciously fixed interval with minimal jitter (low variance between heartbeats).
        """
        packets: List[Packet] = []
        now = time.time()

        for i in range(count):
            # Calculate timestamp with strictly minimal random jitter
            actual_delta = interval + random.uniform(-jitter, jitter)
            pkt_time = now + (i * actual_delta)

            pkt = Packet(
                timestamp=pkt_time,
                src_ip=compromised_ip,
                dst_ip=c2_ip,
                src_port=random.randint(35000, 42000),
                dst_port=8443,
                protocol="HTTPS",
                length=random.randint(180, 220),
                flags="ACK,PSH",
                auth_success=None,
                payload_info=f"C2 Heartbeat #{i+1} [Encrypted beacon checkin]",
                is_attack=True,
                attack_type="C2_BEACONING"
            )
            packets.append(pkt)
            self.packet_buffer.append(pkt)

        return packets

    def inject_volume_flood(self, target_ip: str = "192.168.1.10",
                            attacker_ip: str = EXTERNAL_ATTACKER_IP,
                            packet_count: int = 35,
                            bytes_per_packet: int = 1400) -> List[Packet]:
        """
        ATTACK PATTERN D: Volume Flood (DDoS / Data Exfiltration)
        A high-bandwidth burst of packets exceeding the legitimate baseline traffic,
        attempting to overwhelm the IoT device or siphon data.
        """
        packets: List[Packet] = []
        now = time.time()

        for i in range(packet_count):
            pkt = Packet(
                timestamp=now + (i * 0.02),  # Extremely high rate: 50 pkts/sec
                src_ip=attacker_ip,
                dst_ip=target_ip,
                src_port=random.randint(30000, 60000),
                dst_port=80,
                protocol="UDP",
                length=bytes_per_packet,
                flags="NONE",
                auth_success=None,
                payload_info=f"High-Volume Flood Burst #{i+1} ({bytes_per_packet} bytes)",
                is_attack=True,
                attack_type="VOLUME_FLOOD"
            )
            packets.append(pkt)
            self.packet_buffer.append(pkt)

        return packets

    def inject_maintenance_routine(self, target_ip: str = "192.168.1.10",
                                   routine_type: str = "firmware_sync") -> List[Packet]:
        """
        SIMULATED BENIGN MAINTENANCE ACTIVITY:
        Legitimate off-peak or scheduled maintenance window traffic.
        Without an Adaptive Baseline, this causes false positive alert storms and wrongful quarantines!

        Types:
        - 'firmware_sync': 37.5 KB OTA firmware patch chunk (exceeds static 25KB flood limit)
        - 'asset_discovery_scan': 17-port LAN inventory health sweep (exceeds static 15 unique port limit)
        """
        packets: List[Packet] = []
        now = time.time()

        if routine_type == "firmware_sync":
            # 25 chunks * 1500 bytes = 37,500 bytes in ~1.2s from Vendor Cloud OTA CDN (52.14.99.102)
            for i in range(25):
                pkt = Packet(
                    timestamp=now + (i * 0.05),
                    src_ip="52.14.99.102",
                    dst_ip=target_ip,
                    src_port=443,
                    dst_port=random.randint(49152, 65535),
                    protocol="HTTPS",
                    length=1500,
                    flags="ACK,PSH",
                    auth_success=None,
                    payload_info=f"OTA Firmware Update Binary Chunk #{i+1}/25 [v4.2.1-prod signed]",
                    is_attack=False,
                    attack_type=None
                )
                packets.append(pkt)
                self.packet_buffer.append(pkt)

        elif routine_type == "asset_discovery_scan":
            # Internal IT Management Controller (192.168.1.1) checking 17 service ports
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 554, 1883, 3306, 5000, 8080, 8443, 8883, 9000]
            for i, p in enumerate(ports):
                pkt = Packet(
                    timestamp=now + (i * 0.04),
                    src_ip=GATEWAY_IP,
                    dst_ip=target_ip,
                    src_port=random.randint(40000, 50000),
                    dst_port=p,
                    protocol="TCP",
                    length=54,
                    flags="SYN",
                    auth_success=None,
                    payload_info=f"Scheduled Lansweeper / Asset Inventory Probe (port {p})",
                    is_attack=False,
                    attack_type=None
                )
                packets.append(pkt)
                self.packet_buffer.append(pkt)

        return packets

