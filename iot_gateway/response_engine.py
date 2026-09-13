"""
Response & Hardening Engine for IoT Threat Detection Gateway
=============================================================
Translates detected security alerts into automated firewall enforcement actions.

Capabilities:
1. Policy Evaluation: Determines whether to ISOLATE or MONITOR based on category.
2. Firewall Command Synthesis: Generates Linux `iptables` quarantine rules (and Windows netsh equivalent).
3. Safety Flag: Defaults to simulation mode (dry-run). Only executes actual system
   firewall commands if `safety_mode` is explicitly set to False (i.e. real hardware deployment).
4. Blocklist Ledger: Maintains active state of quarantined IPs with full audit trail.
"""

import os
import time
import subprocess
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Set

try:
    from detection_engine import Alert
except ImportError:
    from .detection_engine import Alert


@dataclass
class ResponseAction:
    """
    Record of a hardening action taken or evaluated for an alert.
    """
    action_id: str
    timestamp: float
    alert_id: str
    target_ip: str          # The IP address to block or monitor
    category: str           # Alert category
    action: str             # 'ISOLATE' or 'MONITOR'
    reason: str             # Explanatory policy reason
    iptables_command: str   # Generated Linux iptables rule
    windows_command: str    # Equivalent Windows Firewall command
    executed_live: bool     # True if real command was invoked; False if simulated
    status: str             # 'ACTIVE_BLOCK', 'MONITORING', 'REVERTED'

    def to_dict(self) -> Dict:
        return asdict(self)


class ResponseEngine:
    """
    Evaluates alerts and enforces automated isolation rules to shield the IoT subnet.
    """

    def __init__(self, safety_mode: bool = True):
        """
        :param safety_mode: When True (default), iptables commands are strictly simulated
                            and printed to logs. When False, invokes actual OS firewall commands.
        """
        self.safety_mode: bool = safety_mode
        self.blocklist: Set[str] = set()
        self.action_history: List[ResponseAction] = []
        self._action_counter: int = 1

        # Policy matrix: Map alert category to default response action
        # In IoT environments, active threats are typically isolated immediately
        self.policy_matrix: Dict[str, str] = {
            "PORT_SCAN": "ISOLATE",       # Isolate scanning source
            "BRUTE_FORCE": "ISOLATE",     # Isolate brute-forcing source
            "C2_BEACONING": "ISOLATE",    # Isolate compromised internal device
            "VOLUME_FLOOD": "ISOLATE",    # Drop flood traffic immediately
        }

    def process_alert(self, alert: Alert) -> ResponseAction:
        """
        Evaluates an alert, decides action, synthesizes firewall commands,
        and applies or simulates isolation.
        """
        # Determine target IP to isolate:
        # For C2 beaconing, we want to isolate the compromised internal source IP
        # For inbound attacks (port scan, brute force, flood), we block the source IP
        ip_to_isolate = alert.source_ip

        # Check policy
        decision = self.policy_matrix.get(alert.category, "MONITOR")

        # Generate exact iptables rules:
        # 1. FORWARD chain: Drops forwarded traffic crossing the gateway (to/from the Internet)
        # 2. INPUT chain: Drops traffic directly hitting the gateway itself
        iptables_cmd = f"iptables -A FORWARD -s {ip_to_isolate} -j DROP && iptables -A INPUT -s {ip_to_isolate} -j DROP"
        windows_cmd = f'netsh advfirewall firewall add rule name="IoT_Quarantine_{ip_to_isolate}" dir=in action=block remoteip={ip_to_isolate}'

        reason = (
            f"Automated policy triggered: {alert.category} alert from {ip_to_isolate}. "
            f"Risk severity: {alert.severity}. Isolating to prevent lateral movement or data exfiltration."
        )

        action_status = "MONITORING"
        executed_live = False

        if decision == "ISOLATE":
            self.blocklist.add(ip_to_isolate)
            action_status = "ACTIVE_BLOCK"

            print("\n" + "="*70)
            print(f"[RESPONSE ENGINE] 🚨 ALERT TRIGGERED: {alert.category}")
            print(f"[RESPONSE ENGINE] Target IP to isolate: {ip_to_isolate}")
            print(f"[RESPONSE ENGINE] Decision: {decision}")

            if self.safety_mode:
                print(f"[RESPONSE ENGINE] [SIMULATION MODE - Safety Flag ON]")
                print(f"[RESPONSE ENGINE] Iptables command that WOULD run on Linux / Raspberry Pi:")
                print(f"    >>> {iptables_cmd}")
                print(f"[RESPONSE ENGINE] Windows equivalent command:")
                print(f"    >>> {windows_cmd}")
                print("="*70 + "\n")
            else:
                # Live execution when deployed on actual hardware (e.g. Raspberry Pi)
                print(f"[RESPONSE ENGINE] ⚠️ SAFETY FLAG OFF: Executing real firewall rule...")
                executed_live = self._execute_live_command(iptables_cmd, windows_cmd)
                print("="*70 + "\n")

        action = ResponseAction(
            action_id=f"ACT-{self._action_counter:04d}",
            timestamp=time.time(),
            alert_id=alert.alert_id,
            target_ip=ip_to_isolate,
            category=alert.category,
            action=decision,
            reason=reason,
            iptables_command=iptables_cmd,
            windows_command=windows_cmd,
            executed_live=executed_live,
            status=action_status
        )
        self._action_counter += 1
        self.action_history.append(action)
        return action

    def unblock_ip(self, ip: str) -> bool:
        """
        Manually lifts quarantine for an IP address and runs/simulates teardown rules.
        """
        if ip in self.blocklist:
            self.blocklist.remove(ip)
            teardown_iptables = f"iptables -D FORWARD -s {ip} -j DROP && iptables -D INPUT -s {ip} -j DROP"
            teardown_windows = f'netsh advfirewall firewall delete rule name="IoT_Quarantine_{ip}"'

            print(f"[RESPONSE ENGINE] 🟢 IP {ip} unblocked. Reverted rule: {teardown_iptables}")
            if not self.safety_mode:
                self._execute_live_command(teardown_iptables, teardown_windows)

            # Update history statuses
            for item in self.action_history:
                if item.target_ip == ip and item.status == "ACTIVE_BLOCK":
                    item.status = "REVERTED"
            return True
        return False

    def is_blocked(self, ip: str) -> bool:
        """Checks if an IP is currently marked as quarantined in the active blocklist."""
        return ip in self.blocklist

    def set_safety_mode(self, enabled: bool):
        """Toggle simulation dry-run safety mode."""
        self.safety_mode = enabled
        status = "ENABLED (Simulate only, safe for dev)" if enabled else "DISABLED (REAL system commands will execute)"
        print(f"[RESPONSE ENGINE] Safety flag updated: {status}")

    def _execute_live_command(self, linux_cmd: str, windows_cmd: str) -> bool:
        """Invokes OS command depending on platform."""
        try:
            if os.name == "nt":  # Windows
                subprocess.run(windows_cmd, shell=True, check=True)
            else:  # Linux / Raspberry Pi
                subprocess.run(linux_cmd, shell=True, check=True)
            return True
        except Exception as e:
            print(f"[RESPONSE ENGINE] Error executing live firewall rule: {e}")
            return False
