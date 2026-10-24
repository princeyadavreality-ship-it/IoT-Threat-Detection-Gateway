"""
Detection Engine for IoT Threat Detection & Hardening Gateway
============================================================
Performs rule-based network security analysis on packet flows inspired by
IDS/IPS systems like Suricata and Snort, written in transparent, readable Python.

Detects:
1. Port Scanning: Sweeping multiple ports on a target device in a short time
2. Brute-Force Auth: Repeated failed authentication attempts
3. C2 Beaconing: Machine-like periodic connections characterized by ultra-low jitter
4. Volume Flood: High data volume surges exceeding legitimate device baselines
5. USB Exfiltration: Endpoint mass storage data copy exceeding DLP limits (air-gapped theft)
"""

import time
import math
from dataclasses import dataclass, asdict
from typing import List, Dict, Tuple, Optional
from collections import defaultdict

try:
    from traffic_simulator import Packet
except ImportError:
    from .traffic_simulator import Packet


@dataclass
class Alert:
    """
    Structured alert generated when traffic violates security thresholds.
    """
    alert_id: str
    timestamp: float
    category: str        # 'PORT_SCAN', 'BRUTE_FORCE', 'C2_BEACONING', 'VOLUME_FLOOD', 'USB_EXFILTRATION'
    severity: str        # 'LOW', 'MEDIUM', 'HIGH'
    source_ip: str       # Attacker, compromised device IP, or endpoint host IP
    target_ip: str       # Victim, C2 destination IP, or USB peripheral target
    detail: str          # Human-readable explanation of why this was flagged
    evidence: Dict       # Statistical and forensic evidence behind the trigger

    def to_dict(self) -> Dict:
        return asdict(self)


class DetectionThresholds:
    """
    Tunable thresholds for threat detection rules.
    Values can be customized based on IoT environment baselines.
    """
    # 1. Port Scan Thresholds
    PORT_SCAN_UNIQUE_PORTS: int = 15      # >= 15 unique destination ports
    PORT_SCAN_WINDOW_SEC: float = 10.0    # within 10.0 seconds

    # 2. Brute-Force Thresholds
    BRUTE_FORCE_FAILURES: int = 5         # >= 5 failed auth attempts
    BRUTE_FORCE_WINDOW_SEC: float = 10.0  # within 10.0 seconds

    # 3. C2 Beaconing Thresholds
    BEACONING_MIN_PACKETS: int = 5        # >= 5 consecutive sessions to same host
    BEACONING_MAX_JITTER_SEC: float = 0.25 # Standard deviation of delta-t < 0.25s
    BEACONING_WINDOW_SEC: float = 30.0    # Lookback window

    # 4. Volume Flood Thresholds
    VOLUME_FLOOD_BYTES: int = 25000       # >= 25,000 bytes
    VOLUME_FLOOD_WINDOW_SEC: float = 3.0  # within 3.0 seconds

    # 5. USB Exfiltration Thresholds (Endpoint DLP)
    USB_EXFILTRATION_BYTES: int = 50 * 1024 * 1024  # >= 50 MB mass storage copy
    USB_EXFILTRATION_WINDOW_SEC: float = 30.0       # within 30.0 seconds


class DetectionEngine:
    """
    Stateful detection engine that ingests packets, maintains sliding time windows,
    and applies signature/heuristic rules to detect IoT security threats.
    """

    def __init__(self, thresholds: Optional[DetectionThresholds] = None):
        self.thresholds = thresholds or DetectionThresholds()
        self.alerts: List[Alert] = []
        self._alert_counter: int = 1

        # Track recent alerted signatures to prevent duplicate alert storms
        self._suppression_cache: Dict[Tuple[str, str, str], float] = {}
        self.SUPPRESSION_TIME_SEC = 15.0

    def analyze_packets(self, packets: List[Packet]) -> List[Alert]:
        """
        Main entrypoint: analyzes a list of packets (batch or sliding window)
        and returns any new alerts detected.
        """
        new_alerts: List[Alert] = []
        if not packets:
            return new_alerts

        # Run all 5 rule detection pipelines
        new_alerts.extend(self._detect_port_scans(packets))
        new_alerts.extend(self._detect_brute_force(packets))
        new_alerts.extend(self._detect_c2_beaconing(packets))
        new_alerts.extend(self._detect_volume_floods(packets))
        new_alerts.extend(self._detect_usb_exfiltration(packets))

        # Store in historical log
        self.alerts.extend(new_alerts)
        return new_alerts

    # =========================================================================
    # RULE 1: PORT SCAN DETECTION
    # Logic: Look for single source IP hitting X unique ports on target within Y sec
    # =========================================================================
    def _detect_port_scans(self, packets: List[Packet]) -> List[Alert]:
        alerts: List[Alert] = []
        now = time.time()
        window_start = now - self.thresholds.PORT_SCAN_WINDOW_SEC

        # Group ports by (source_ip, target_ip) within the time window
        flows: Dict[Tuple[str, str], List[Tuple[int, float]]] = defaultdict(list)
        for pkt in packets:
            if pkt.timestamp >= window_start:
                flows[(pkt.src_ip, pkt.dst_ip)].append((pkt.dst_port, pkt.timestamp))

        for (src_ip, dst_ip), hits in flows.items():
            unique_ports = {port for port, _ in hits}
            if len(unique_ports) >= self.thresholds.PORT_SCAN_UNIQUE_PORTS:
                if self._is_suppressed("PORT_SCAN", src_ip, dst_ip):
                    continue

                alert = Alert(
                    alert_id=f"ALT-{self._alert_counter:04d}",
                    timestamp=now,
                    category="PORT_SCAN",
                    severity="HIGH",
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    detail=(
                        f"Port scan reconnaissance detected from {src_ip}: probed {len(unique_ports)} "
                        f"unique ports on target {dst_ip} within {self.thresholds.PORT_SCAN_WINDOW_SEC}s."
                    ),
                    evidence={
                        "unique_ports_count": len(unique_ports),
                        "ports_probed_sample": sorted(list(unique_ports))[:10],
                        "total_probes": len(hits),
                        "time_window_sec": self.thresholds.PORT_SCAN_WINDOW_SEC
                    }
                )
                self._alert_counter += 1
                self._record_suppression("PORT_SCAN", src_ip, dst_ip)
                alerts.append(alert)

        return alerts

    # =========================================================================
    # RULE 2: BRUTE FORCE DETECTION
    # Logic: Look for >= X failed authentication attempts from a source within Y sec
    # =========================================================================
    def _detect_brute_force(self, packets: List[Packet]) -> List[Alert]:
        alerts: List[Alert] = []
        now = time.time()
        window_start = now - self.thresholds.BRUTE_FORCE_WINDOW_SEC

        # Count failed auth packets per (src_ip, dst_ip, dst_port)
        failed_attempts: Dict[Tuple[str, str, int], List[Packet]] = defaultdict(list)
        for pkt in packets:
            if pkt.timestamp >= window_start and pkt.auth_success is False:
                failed_attempts[(pkt.src_ip, pkt.dst_ip, pkt.dst_port)].append(pkt)

        for (src_ip, dst_ip, port), failed_pkts in failed_attempts.items():
            if len(failed_pkts) >= self.thresholds.BRUTE_FORCE_FAILURES:
                if self._is_suppressed("BRUTE_FORCE", src_ip, dst_ip):
                    continue

                alert = Alert(
                    alert_id=f"ALT-{self._alert_counter:04d}",
                    timestamp=now,
                    category="BRUTE_FORCE",
                    severity="HIGH",
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    detail=(
                        f"Credential brute-force detected from {src_ip} targeting {dst_ip}:{port} "
                        f"({len(failed_pkts)} failed authentication attempts in {self.thresholds.BRUTE_FORCE_WINDOW_SEC}s)."
                    ),
                    evidence={
                        "failed_attempts": len(failed_pkts),
                        "target_port": port,
                        "time_window_sec": self.thresholds.BRUTE_FORCE_WINDOW_SEC
                    }
                )
                self._alert_counter += 1
                self._record_suppression("BRUTE_FORCE", src_ip, dst_ip)
                alerts.append(alert)

        return alerts

    # =========================================================================
    # RULE 3: C2 BEACONING DETECTION
    # Logic: Repeated connections at fixed time interval with low jitter (variance)
    # =========================================================================
    def _detect_c2_beaconing(self, packets: List[Packet]) -> List[Alert]:
        alerts: List[Alert] = []
        now = time.time()
        window_start = now - self.thresholds.BEACONING_WINDOW_SEC

        # Group packet timestamps by (src_ip, dst_ip)
        pair_timestamps: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        for pkt in sorted(packets, key=lambda p: p.timestamp):
            if pkt.timestamp >= window_start:
                pair_timestamps[(pkt.src_ip, pkt.dst_ip)].append(pkt.timestamp)

        for (src_ip, dst_ip), timestamps in pair_timestamps.items():
            if len(timestamps) < self.thresholds.BEACONING_MIN_PACKETS:
                continue

            # Calculate delta times between successive connections
            deltas = [
                timestamps[i] - timestamps[i - 1]
                for i in range(1, len(timestamps))
                if (timestamps[i] - timestamps[i - 1]) > 0.001
            ]

            if len(deltas) < (self.thresholds.BEACONING_MIN_PACKETS - 1):
                continue

            # Calculate mean and standard deviation (jitter metric)
            mean_delta = sum(deltas) / len(deltas)
            variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
            std_dev = math.sqrt(variance)

            # A true automated C2 beacon has a fixed sleep cycle, yielding very low std_dev
            if std_dev <= self.thresholds.BEACONING_MAX_JITTER_SEC and mean_delta >= 1.0:
                if self._is_suppressed("C2_BEACONING", src_ip, dst_ip):
                    continue

                alert = Alert(
                    alert_id=f"ALT-{self._alert_counter:04d}",
                    timestamp=now,
                    category="C2_BEACONING",
                    severity="HIGH",
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    detail=(
                        f"Compromised host beaconing behavior identified on {src_ip} -> {dst_ip}. "
                        f"Periodic heartbeat every ~{mean_delta:.2f}s with ultra-low jitter (std-dev: {std_dev:.3f}s)."
                    ),
                    evidence={
                        "packet_count": len(timestamps),
                        "mean_interval_sec": round(mean_delta, 2),
                        "jitter_std_dev_sec": round(std_dev, 4),
                        "sample_deltas": [round(d, 2) for d in deltas[:6]]
                    }
                )
                self._alert_counter += 1
                self._record_suppression("C2_BEACONING", src_ip, dst_ip)
                alerts.append(alert)

        return alerts

    # =========================================================================
    # RULE 4: VOLUME FLOOD DETECTION
    # Logic: Byte surge or packet flood exceeding threshold within window
    # =========================================================================
    def _detect_volume_floods(self, packets: List[Packet]) -> List[Alert]:
        alerts: List[Alert] = []
        now = time.time()
        window_start = now - self.thresholds.VOLUME_FLOOD_WINDOW_SEC

        volume_stats: Dict[Tuple[str, str], Dict] = defaultdict(
            lambda: {"total_bytes": 0, "packet_count": 0}
        )

        for pkt in packets:
            # BUG FIX: Protocol check to avoid cross-contamination.
            # Volume flood is strictly a NETWORK transport attack (UDP/TCP flood).
            # Endpoint USB storage writes must not be counted here!
            if getattr(pkt, 'protocol', '') in ('USB', 'ENDPOINT_DLP', 'STORAGE'):
                continue

            if pkt.timestamp >= window_start:
                key = (pkt.src_ip, pkt.dst_ip)
                volume_stats[key]["total_bytes"] += pkt.length
                volume_stats[key]["packet_count"] += 1

        for (src_ip, dst_ip), stats in volume_stats.items():
            if stats["total_bytes"] >= self.thresholds.VOLUME_FLOOD_BYTES:
                if self._is_suppressed("VOLUME_FLOOD", src_ip, dst_ip):
                    continue

                alert = Alert(
                    alert_id=f"ALT-{self._alert_counter:04d}",
                    timestamp=now,
                    category="VOLUME_FLOOD",
                    severity="HIGH",
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    detail=(
                        f"High-volume traffic surge / Denial of Service pattern from {src_ip} -> {dst_ip}: "
                        f"{stats['total_bytes']:,} bytes transmitted in {self.thresholds.VOLUME_FLOOD_WINDOW_SEC}s."
                    ),
                    evidence={
                        "total_bytes": stats["total_bytes"],
                        "packet_count": stats["packet_count"],
                        "time_window_sec": self.thresholds.VOLUME_FLOOD_WINDOW_SEC,
                        "bytes_per_second": round(stats["total_bytes"] / self.thresholds.VOLUME_FLOOD_WINDOW_SEC, 1)
                    }
                )
                self._alert_counter += 1
                self._record_suppression("VOLUME_FLOOD", src_ip, dst_ip)
                alerts.append(alert)

        return alerts

    # =========================================================================
    # RULE 5: USB EXFILTRATION DETECTION (ENDPOINT DLP)
    # Logic: Endpoint reports USB mass storage write exceeding threshold in window
    # =========================================================================
    def _detect_usb_exfiltration(self, packets: List[Packet]) -> List[Alert]:
        alerts: List[Alert] = []
        now = time.time()
        window_start = now - self.thresholds.USB_EXFILTRATION_WINDOW_SEC

        usb_stats: Dict[Tuple[str, str], Dict] = defaultdict(
            lambda: {"total_bytes": 0, "events": 0, "details": []}
        )

        for pkt in packets:
            if getattr(pkt, 'protocol', '') == 'USB' and pkt.timestamp >= window_start:
                key = (pkt.src_ip, pkt.dst_ip)
                usb_stats[key]["total_bytes"] += pkt.length
                usb_stats[key]["events"] += 1
                if pkt.payload_info:
                    usb_stats[key]["details"].append(pkt.payload_info)

        for (src_ip, dst_ip), stats in usb_stats.items():
            if stats["total_bytes"] >= self.thresholds.USB_EXFILTRATION_BYTES:
                if self._is_suppressed("USB_EXFILTRATION", src_ip, dst_ip):
                    continue

                mb_copied = round(stats["total_bytes"] / (1024 * 1024), 1)
                alert = Alert(
                    alert_id=f"ALT-{self._alert_counter:04d}",
                    timestamp=now,
                    category="USB_EXFILTRATION",
                    severity="HIGH",
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    detail=(
                        f"Air-gapped data exfiltration detected on endpoint {src_ip}: "
                        f"{mb_copied} MB copied to mass storage {dst_ip} within "
                        f"{self.thresholds.USB_EXFILTRATION_WINDOW_SEC}s (DLP threshold exceeded)."
                    ),
                    evidence={
                        "bytes_exfiltrated": stats["total_bytes"],
                        "megabytes_exfiltrated": mb_copied,
                        "time_window_sec": self.thresholds.USB_EXFILTRATION_WINDOW_SEC,
                        "telemetry_events": stats["events"],
                        "sample_payloads": stats["details"][:4]
                    }
                )
                self._alert_counter += 1
                self._record_suppression("USB_EXFILTRATION", src_ip, dst_ip)
                alerts.append(alert)

        return alerts

    # =========================================================================
    # HELPER UTILITIES
    # =========================================================================
    def _is_suppressed(self, category: str, src_ip: str, dst_ip: str) -> bool:
        """Suppresses duplicate alert spam for the same incident within 15 seconds."""
        key = (category, src_ip, dst_ip)
        last_time = self._suppression_cache.get(key)
        if last_time and (time.time() - last_time) < self.SUPPRESSION_TIME_SEC:
            return True
        return False

    def _record_suppression(self, category: str, src_ip: str, dst_ip: str):
        self._suppression_cache[(category, src_ip, dst_ip)] = time.time()
