"""
USB & Endpoint Activity Monitor for IoT Threat Detection Gateway
================================================================
Simulates an endpoint telemetry agent (e.g. on MANAGER-LAPTOP / 192.168.1.15)
that monitors USB mass storage insertions, file copy volume, and potential
air-gapped insider exfiltration attempts.

Why this is necessary:
----------------------
Standard network gateways only inspect packets traversing network interfaces
(routers/switches). When an employee or insider inserts a USB flash drive and
copies sensitive files directly from a host disk, that data NEVER touches the
network wire.

By deploying a lightweight endpoint-aware monitoring agent, local USB events
are forwarded to the security gateway's detection & response pipeline.
"""

import time
import random
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional

try:
    from traffic_simulator import Packet
except ImportError:
    from .traffic_simulator import Packet


@dataclass
class USBEvent:
    """
    Represents an endpoint USB storage event logged by the host telemetry agent.
    """
    timestamp: float
    host_name: str           # e.g. "MANAGER-LAPTOP"
    host_ip: str             # e.g. "192.168.1.15"
    user: str                # e.g. "operator.kumar"
    action: str              # 'INSERT', 'WRITE_FILES', 'EJECT'
    device_name: str         # e.g. "SanDisk Ultra 3.0"
    vendor_id: str           # e.g. "0781:5581"
    drive_letter: str        # e.g. "E:\\" or "/media/usb0"
    bytes_transferred: int   # Volume in bytes
    files_copied: List[str]  # List of filenames targeted
    duration_sec: float      # Time taken for the transfer
    is_authorized: bool      # False if unauthorized peripheral

    def to_dict(self) -> Dict:
        return asdict(self)


class USBMonitor:
    """
    Simulates endpoint telemetry gathering and bridges local USB storage activity
    into the gateway's detection pipeline.
    """

    def __init__(self, host_name: str = "MANAGER-LAPTOP", host_ip: str = "192.168.1.15"):
        self.host_name = host_name
        self.host_ip = host_ip
        self.event_log: List[USBEvent] = []

    def simulate_authorized_transfer(self) -> Packet:
        """
        Simulates legitimate, low-volume document transfer (e.g. 2 MB PDF report).
        """
        now = time.time()
        event = USBEvent(
            timestamp=now,
            host_name=self.host_name,
            host_ip=self.host_ip,
            user="operator.kumar",
            action="WRITE_FILES",
            device_name="Kingston DataTraveler (Approved Company Drive)",
            vendor_id="0951:1666",
            drive_letter="E:\\",
            bytes_transferred=2 * 1024 * 1024,  # 2 MB
            files_copied=["Q3_Meeting_Minutes.pdf"],
            duration_sec=3.2,
            is_authorized=True
        )
        self.event_log.append(event)

        # Bridge event to gateway telemetry packet
        return Packet(
            timestamp=now,
            src_ip=self.host_ip,
            dst_ip="USB://Kingston_Approved",
            src_port=44501,
            dst_port=445,
            protocol="USB",
            length=event.bytes_transferred,
            flags="DLP_AUDIT",
            auth_success=True,
            payload_info=f"Endpoint USB write: 2.0MB to Approved Kingston drive",
            is_attack=False
        )

    def simulate_usb_exfiltration(self,
                                  bytes_to_copy: int = 85 * 1024 * 1024, # 85 MB
                                  duration_sec: float = 14.5) -> List[Packet]:
        """
        ATTACK PATTERN E: Air-Gapped USB Data Exfiltration
        Insider plugs in an unauthorized portable flash drive and copies massive
        confidential databases and keys directly from host storage.
        """
        now = time.time()
        files = [
            "customer_vault_backup.sql (48MB)",
            "employee_payroll_records.tar.gz (24MB)",
            "iot_gateway_private_keys.pem (13MB)"
        ]

        event = USBEvent(
            timestamp=now,
            host_name=self.host_name,
            host_ip=self.host_ip,
            user="insider_contractor",
            action="WRITE_FILES",
            device_name="SanDisk Ultra USB 3.0 [UNAUTHORIZED]",
            vendor_id="0781:5581",
            drive_letter="F:\\",
            bytes_transferred=bytes_to_copy,
            files_copied=files,
            duration_sec=duration_sec,
            is_authorized=False
        )
        self.event_log.append(event)

        # Generate telemetry packets sent from endpoint agent to gateway
        packets: List[Packet] = []
        
        # 1. USB insertion event packet
        packets.append(Packet(
            timestamp=now,
            src_ip=self.host_ip,
            dst_ip="USB://SanDisk_Ultra_3.0",
            src_port=49152,
            dst_port=0,
            protocol="USB",
            length=512,
            flags="USB_ATTACH",
            auth_success=False,
            payload_info=f"Unauthorized USB Storage Attached: {event.device_name} (VID:{event.vendor_id})",
            is_attack=True,
            attack_type="USB_EXFILTRATION"
        ))

        # 2. Large file copy mass storage transfer telemetry
        packets.append(Packet(
            timestamp=now + 0.5,
            src_ip=self.host_ip,
            dst_ip="USB://SanDisk_Ultra_3.0",
            src_port=49153,
            dst_port=0,
            protocol="USB",
            length=bytes_to_copy,
            flags="USB_WRITE",
            auth_success=False,
            payload_info=f"DLP Alert: {round(bytes_to_copy/(1024*1024), 1)}MB written to unauthorized USB drive ({', '.join(files)})",
            is_attack=True,
            attack_type="USB_EXFILTRATION"
        ))

        return packets
