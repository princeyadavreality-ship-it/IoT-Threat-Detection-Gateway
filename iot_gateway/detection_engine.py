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


@dataclass
class SuppressedEvent:
    """
    Record of a benign network surge or probe that would have triggered a false
    positive alert under static rules, but was safely absorbed by the Adaptive Baseline.
    """
    timestamp: float
    category: str
    source_ip: str
    target_ip: str
    metric_value: float
    static_threshold: float
    adaptive_threshold: float
    regime: str             # 'MAINTENANCE_WINDOW', 'OFF_PEAK', 'PEAK_HOURS'
    multiplier: float
    reason: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class AdaptiveBaselineConfig:
    """
    Configuration for the Adaptive Baseline heuristic.
    Dynamically modulates alert sensitivity based on time-of-day diurnal rhythms
    and scheduled maintenance windows.
    """
    enabled: bool = True
    maintenance_start_hour: int = 2        # 02:00 (2 AM)
    maintenance_end_hour: int = 5          # 05:00 (5 AM)
    maintenance_factor: float = 2.2        # Relax thresholds by 2.2x during maintenance
    offpeak_factor: float = 1.3            # Moderate 1.3x relaxation off-peak
    simulated_hour: Optional[float] = None # Overrides system clock for simulation / test bench
    auto_suppress_maintenance_spikes: bool = True

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

    def clone(self) -> 'DetectionThresholds':
        cloned = DetectionThresholds()
        cloned.PORT_SCAN_UNIQUE_PORTS = self.PORT_SCAN_UNIQUE_PORTS
        cloned.PORT_SCAN_WINDOW_SEC = self.PORT_SCAN_WINDOW_SEC
        cloned.BRUTE_FORCE_FAILURES = self.BRUTE_FORCE_FAILURES
        cloned.BRUTE_FORCE_WINDOW_SEC = self.BRUTE_FORCE_WINDOW_SEC
        cloned.BEACONING_MIN_PACKETS = self.BEACONING_MIN_PACKETS
        cloned.BEACONING_MAX_JITTER_SEC = self.BEACONING_MAX_JITTER_SEC
        cloned.BEACONING_WINDOW_SEC = self.BEACONING_WINDOW_SEC
        cloned.VOLUME_FLOOD_BYTES = self.VOLUME_FLOOD_BYTES
        cloned.VOLUME_FLOOD_WINDOW_SEC = self.VOLUME_FLOOD_WINDOW_SEC
        cloned.USB_EXFILTRATION_BYTES = self.USB_EXFILTRATION_BYTES
        cloned.USB_EXFILTRATION_WINDOW_SEC = self.USB_EXFILTRATION_WINDOW_SEC
        return cloned


class DetectionEngine:
    """
    Stateful detection engine that ingests packets, maintains sliding time windows,
    and applies signature/heuristic rules to detect IoT security threats.
    Includes the 'Adaptive Baseline' heuristic to automatically modulate sensitivity
    based on the time of day and scheduled maintenance windows.
    """

    def __init__(self, thresholds: Optional[DetectionThresholds] = None,
                 adaptive_config: Optional[AdaptiveBaselineConfig] = None):
        self.thresholds = thresholds or DetectionThresholds()
        self.adaptive_config = adaptive_config or AdaptiveBaselineConfig()
        self.alerts: List[Alert] = []
        self.suppressed_false_positives: List[SuppressedEvent] = []
        self._alert_counter: int = 1

        # Track recent alerted signatures to prevent duplicate alert storms
        self._suppression_cache: Dict[Tuple[str, str, str], float] = {}
        self.SUPPRESSION_TIME_SEC = 15.0

    def get_current_regime(self, timestamp: Optional[float] = None) -> Tuple[str, float, str]:
        """
        Determines the current operational time regime based on time-of-day diurnal profile:
        - 'MAINTENANCE_WINDOW' (e.g. 02:00 - 05:00): Scheduled low-traffic maintenance window
        - 'OFF_PEAK' (e.g. 18:00 - 02:00, 05:00 - 08:00): Quiescent night/evening operation
        - 'PEAK_HOURS' (e.g. 08:00 - 18:00): Active daytime operation
        Returns: (regime_name, multiplier, explanation)
        """
        if not self.adaptive_config.enabled:
            return ("PEAK_HOURS", 1.0, "Adaptive Baseline disabled (static 1.0x baseline active)")

        if self.adaptive_config.simulated_hour is not None:
            hour = self.adaptive_config.simulated_hour % 24.0
        else:
            ts = timestamp or time.time()
            lt = time.localtime(ts)
            hour = lt.tm_hour + (lt.tm_min / 60.0)

        # Check maintenance window (handles range or midnight wrap)
        m_start = self.adaptive_config.maintenance_start_hour
        m_end = self.adaptive_config.maintenance_end_hour
        in_maint = False
        if m_start < m_end:
            in_maint = (m_start <= hour < m_end)
        else:
            in_maint = (hour >= m_start or hour < m_end)

        if in_maint:
            return (
                "MAINTENANCE_WINDOW",
                self.adaptive_config.maintenance_factor,
                f"Scheduled low-traffic maintenance window ({m_start:02d}:00 - {m_end:02d}:00): "
                f"Automated firmware updates, DB syncs, and discovery sweeps tolerated (+{self.adaptive_config.maintenance_factor}x factor)."
            )

        # Check Off-peak: 18:00 to 02:00 or 05:00 to 08:00
        is_offpeak = (hour >= 18.0 or hour < 2.0 or (5.0 <= hour < 8.0))
        if is_offpeak:
            return (
                "OFF_PEAK",
                self.adaptive_config.offpeak_factor,
                f"Off-peak quiescent period ({int(hour):02d}:{int((hour%1)*60):02d}): "
                f"Slightly relaxed baseline (+{self.adaptive_config.offpeak_factor}x factor)."
            )

        return (
            "PEAK_HOURS",
            1.0,
            f"Active peak operational window ({int(hour):02d}:{int((hour%1)*60):02d}): "
            "High vigilance standard baseline (1.0x factor)."
        )

    def get_effective_thresholds(self, timestamp: Optional[float] = None) -> Tuple[DetectionThresholds, str, float]:
        """
        Calculates effective thresholds by scaling base thresholds by current regime multiplier.
        """
        regime, multiplier, _ = self.get_current_regime(timestamp)
        effective = self.thresholds.clone()
        if self.adaptive_config.enabled and multiplier != 1.0:
            effective.PORT_SCAN_UNIQUE_PORTS = int(round(self.thresholds.PORT_SCAN_UNIQUE_PORTS * multiplier))
            effective.BRUTE_FORCE_FAILURES = int(round(self.thresholds.BRUTE_FORCE_FAILURES * multiplier))
            effective.VOLUME_FLOOD_BYTES = int(round(self.thresholds.VOLUME_FLOOD_BYTES * multiplier))
            # Beacon jitter tolerance slightly relaxed during maintenance to avoid flagging synchronized sync pulses
            effective.BEACONING_MAX_JITTER_SEC = round(self.thresholds.BEACONING_MAX_JITTER_SEC * (1.0 + (multiplier - 1.0) * 0.4), 3)
        return effective, regime, multiplier

    def analyze_packets(self, packets: List[Packet]) -> List[Alert]:
        """
        Main entrypoint: analyzes a list of packets (batch or sliding window)
        and returns any new alerts detected, taking into account the Adaptive Baseline heuristic.
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
        effective_thresh, regime, multiplier = self.get_effective_thresholds(now)
        window_start = now - effective_thresh.PORT_SCAN_WINDOW_SEC

        # Group ports by (source_ip, target_ip) within the time window
        flows: Dict[Tuple[str, str], List[Tuple[int, float]]] = defaultdict(list)
        for pkt in packets:
            if pkt.timestamp >= window_start:
                flows[(pkt.src_ip, pkt.dst_ip)].append((pkt.dst_port, pkt.timestamp))

        for (src_ip, dst_ip), hits in flows.items():
            unique_ports = {port for port, _ in hits}
            port_count = len(unique_ports)

            # Check if static baseline is exceeded
            if port_count >= self.thresholds.PORT_SCAN_UNIQUE_PORTS:
                # Check Adaptive Baseline: Is it within the relaxed maintenance window tolerance?
                if (port_count < effective_thresh.PORT_SCAN_UNIQUE_PORTS and
                        self.adaptive_config.enabled and
                        self.adaptive_config.auto_suppress_maintenance_spikes):
                    # Suppress false positive during maintenance window (e.g. vulnerability scanner or asset sweep)
                    if not self._is_suppressed("SUPPRESSED_PORT_SCAN", src_ip, dst_ip):
                        self.suppressed_false_positives.append(SuppressedEvent(
                            timestamp=now,
                            category="PORT_SCAN",
                            source_ip=src_ip,
                            target_ip=dst_ip,
                            metric_value=port_count,
                            static_threshold=self.thresholds.PORT_SCAN_UNIQUE_PORTS,
                            adaptive_threshold=effective_thresh.PORT_SCAN_UNIQUE_PORTS,
                            regime=regime,
                            multiplier=multiplier,
                            reason=(
                                f"Port sweep ({port_count} ports) tolerated under Adaptive Baseline during {regime}. "
                                f"Threshold expanded from {self.thresholds.PORT_SCAN_UNIQUE_PORTS} to {effective_thresh.PORT_SCAN_UNIQUE_PORTS} "
                                f"to accommodate scheduled asset discovery scans without triggering quarantine."
                            )
                        ))
                        self._record_suppression("SUPPRESSED_PORT_SCAN", src_ip, dst_ip)
                    continue

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
                        f"Port scan reconnaissance detected from {src_ip}: probed {port_count} "
                        f"unique ports on target {dst_ip} within {effective_thresh.PORT_SCAN_WINDOW_SEC}s"
                        f"{f' [Regime: {regime}, Threshold: {effective_thresh.PORT_SCAN_UNIQUE_PORTS}]' if multiplier > 1.0 else ''}."
                    ),
                    evidence={
                        "unique_ports_count": port_count,
                        "ports_probed_sample": sorted(list(unique_ports))[:10],
                        "total_probes": len(hits),
                        "time_window_sec": effective_thresh.PORT_SCAN_WINDOW_SEC,
                        "adaptive_baseline": {
                            "regime": regime,
                            "multiplier": multiplier,
                            "effective_threshold": effective_thresh.PORT_SCAN_UNIQUE_PORTS,
                            "baseline_adjusted": multiplier != 1.0
                        }
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
        effective_thresh, regime, multiplier = self.get_effective_thresholds(now)
        window_start = now - effective_thresh.BRUTE_FORCE_WINDOW_SEC

        # Count failed auth packets per (src_ip, dst_ip, dst_port)
        failed_attempts: Dict[Tuple[str, str, int], List[Packet]] = defaultdict(list)
        for pkt in packets:
            if pkt.timestamp >= window_start and pkt.auth_success is False:
                failed_attempts[(pkt.src_ip, pkt.dst_ip, pkt.dst_port)].append(pkt)

        for (src_ip, dst_ip, port), failed_pkts in failed_attempts.items():
            fail_count = len(failed_pkts)

            if fail_count >= self.thresholds.BRUTE_FORCE_FAILURES:
                # Check Adaptive Baseline tolerance
                if (fail_count < effective_thresh.BRUTE_FORCE_FAILURES and
                        self.adaptive_config.enabled and
                        self.adaptive_config.auto_suppress_maintenance_spikes):
                    if not self._is_suppressed("SUPPRESSED_BRUTE_FORCE", src_ip, dst_ip):
                        self.suppressed_false_positives.append(SuppressedEvent(
                            timestamp=now,
                            category="BRUTE_FORCE",
                            source_ip=src_ip,
                            target_ip=dst_ip,
                            metric_value=fail_count,
                            static_threshold=self.thresholds.BRUTE_FORCE_FAILURES,
                            adaptive_threshold=effective_thresh.BRUTE_FORCE_FAILURES,
                            regime=regime,
                            multiplier=multiplier,
                            reason=(
                                f"Failed auth surge ({fail_count} attempts on port {port}) tolerated under Adaptive Baseline during {regime}. "
                                f"Threshold expanded to {effective_thresh.BRUTE_FORCE_FAILURES} to absorb automated credential rotation retries."
                            )
                        ))
                        self._record_suppression("SUPPRESSED_BRUTE_FORCE", src_ip, dst_ip)
                    continue

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
                        f"({fail_count} failed authentication attempts in {effective_thresh.BRUTE_FORCE_WINDOW_SEC}s)."
                    ),
                    evidence={
                        "failed_attempts": fail_count,
                        "target_port": port,
                        "time_window_sec": effective_thresh.BRUTE_FORCE_WINDOW_SEC,
                        "adaptive_baseline": {
                            "regime": regime,
                            "multiplier": multiplier,
                            "effective_threshold": effective_thresh.BRUTE_FORCE_FAILURES
                        }
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
        effective_thresh, regime, multiplier = self.get_effective_thresholds(now)
        window_start = now - effective_thresh.BEACONING_WINDOW_SEC

        # Group packet timestamps by (src_ip, dst_ip)
        pair_timestamps: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        for pkt in sorted(packets, key=lambda p: p.timestamp):
            if pkt.timestamp >= window_start:
                pair_timestamps[(pkt.src_ip, pkt.dst_ip)].append(pkt.timestamp)

        for (src_ip, dst_ip), timestamps in pair_timestamps.items():
            if len(timestamps) < effective_thresh.BEACONING_MIN_PACKETS:
                continue

            # Calculate delta times between successive connections
            deltas = [
                timestamps[i] - timestamps[i - 1]
                for i in range(1, len(timestamps))
                if (timestamps[i] - timestamps[i - 1]) > 0.001
            ]

            if len(deltas) < (effective_thresh.BEACONING_MIN_PACKETS - 1):
                continue

            # Calculate mean and standard deviation (jitter metric)
            mean_delta = sum(deltas) / len(deltas)
            variance = sum((d - mean_delta) ** 2 for d in deltas) / len(deltas)
            std_dev = math.sqrt(variance)

            # A true automated C2 beacon has a fixed sleep cycle, yielding very low std_dev
            if std_dev <= effective_thresh.BEACONING_MAX_JITTER_SEC and mean_delta >= 1.0:
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
                        "sample_deltas": [round(d, 2) for d in deltas[:6]],
                        "adaptive_baseline": {
                            "regime": regime,
                            "multiplier": multiplier,
                            "jitter_limit_sec": effective_thresh.BEACONING_MAX_JITTER_SEC
                        }
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
        effective_thresh, regime, multiplier = self.get_effective_thresholds(now)
        window_start = now - effective_thresh.VOLUME_FLOOD_WINDOW_SEC

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
            byte_sum = stats["total_bytes"]

            if byte_sum >= self.thresholds.VOLUME_FLOOD_BYTES:
                # Check Adaptive Baseline tolerance during maintenance window or off-peak
                if (byte_sum < effective_thresh.VOLUME_FLOOD_BYTES and
                        self.adaptive_config.enabled and
                        self.adaptive_config.auto_suppress_maintenance_spikes):
                    if not self._is_suppressed("SUPPRESSED_VOLUME_FLOOD", src_ip, dst_ip):
                        self.suppressed_false_positives.append(SuppressedEvent(
                            timestamp=now,
                            category="VOLUME_FLOOD",
                            source_ip=src_ip,
                            target_ip=dst_ip,
                            metric_value=byte_sum,
                            static_threshold=self.thresholds.VOLUME_FLOOD_BYTES,
                            adaptive_threshold=effective_thresh.VOLUME_FLOOD_BYTES,
                            regime=regime,
                            multiplier=multiplier,
                            reason=(
                                f"Traffic volume surge ({byte_sum:,} bytes) tolerated under Adaptive Baseline during {regime}. "
                                f"Threshold scaled from {self.thresholds.VOLUME_FLOOD_BYTES:,} to {effective_thresh.VOLUME_FLOOD_BYTES:,} bytes "
                                f"to allow scheduled OTA firmware updates, sensor rollups, and cloud backups without false isolation."
                            )
                        ))
                        self._record_suppression("SUPPRESSED_VOLUME_FLOOD", src_ip, dst_ip)
                    continue

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
                        f"{byte_sum:,} bytes transmitted in {effective_thresh.VOLUME_FLOOD_WINDOW_SEC}s"
                        f"{f' [Regime: {regime}, Threshold: {effective_thresh.VOLUME_FLOOD_BYTES:,}B]' if multiplier > 1.0 else ''}."
                    ),
                    evidence={
                        "total_bytes": byte_sum,
                        "packet_count": stats["packet_count"],
                        "time_window_sec": effective_thresh.VOLUME_FLOOD_WINDOW_SEC,
                        "bytes_per_second": round(byte_sum / effective_thresh.VOLUME_FLOOD_WINDOW_SEC, 1),
                        "adaptive_baseline": {
                            "regime": regime,
                            "multiplier": multiplier,
                            "effective_threshold_bytes": effective_thresh.VOLUME_FLOOD_BYTES
                        }
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
