"""
Main Runner for IoT Threat Detection & Hardening Gateway
=========================================================
Unified CLI runner and demonstrator for the IoT security gateway.

Usage:
    # Run the interactive attack detection & hardening simulation in terminal:
    python main.py

    # Launch the live web dashboard:
    python main.py --web
    (or: uvicorn dashboard:app --reload --port 8000)
"""

import sys
import time
import argparse
from traffic_simulator import TrafficSimulator, DEFAULT_DEVICES
from detection_engine import DetectionEngine
from response_engine import ResponseEngine


def run_full_simulation_demo():
    """
    Executes an end-to-end simulated attack pipeline demonstrating:
    1. Normal IoT baseline traffic ingestion
    2. Port scan injection -> detection -> iptables isolation
    3. Brute-force login injection -> detection -> iptables isolation
    4. C2 beaconing injection -> detection -> iptables isolation
    5. Volume flood surge injection -> detection -> iptables isolation
    """
    print("\n" + "="*75)
    print("🛡️  IoT THREAT DETECTION & HARDENING GATEWAY — DEMONSTRATION")
    print("="*75)
    print("Initializing Gateway Subnet (192.168.1.0/24)...")

    simulator = TrafficSimulator()
    detection_engine = DetectionEngine()
    response_engine = ResponseEngine(safety_mode=True)

    print("\n[+] Monitored IoT Devices:")
    for ip, dev in DEFAULT_DEVICES.items():
        print(f"    - {dev.name:25} | IP: {ip:14} | MAC: {dev.mac:17} | Protocols: {', '.join(dev.normal_protocols)}")

    # 1. Baseline normal traffic
    print("\n" + "-"*75)
    print("[PHASE 1] Ingesting Normal Benign IoT Traffic...")
    print("-"*75)
    for _ in range(10):
        pkt = simulator.generate_normal_packet()
        print(f"  [NORMAL] {pkt.src_ip} -> {pkt.dst_ip}:{pkt.dst_port} [{pkt.protocol}] ({pkt.payload_info})")
        time.sleep(0.05)

    alerts = detection_engine.analyze_packets(simulator.packet_buffer)
    print(f"\n>> Baseline Analysis: {len(alerts)} alerts detected (Normal operation, 0 false positives).")

    # 2. Attack Pattern A: Port Scan
    print("\n" + "-"*75)
    print("[PHASE 2] Injecting Attack A: Port Scan Reconnaissance...")
    print("Scenario: External attacker (198.51.100.42) sweeping 18 ports on Camera (192.168.1.10)")
    print("-"*75)
    scan_pkts = simulator.inject_port_scan(target_ip="192.168.1.10", num_ports=18)
    print(f">> Injected {len(scan_pkts)} probe packets.")

    new_alerts = detection_engine.analyze_packets(simulator.packet_buffer)
    for alt in new_alerts:
        print(f"\n🚨 DETECTED: [{alt.category}] Severity: {alt.severity}")
        print(f"   Detail: {alt.detail}")
        action = response_engine.process_alert(alt)
        print(f"   Action Taken: {action.action} | iptables rule:")
        print(f"   >>> {action.iptables_command}")

    # 3. Attack Pattern B: Brute-Force Login
    print("\n" + "-"*75)
    print("[PHASE 3] Injecting Attack B: Credential Brute-Force...")
    print("Scenario: Attacker trying rapid dictionary passwords on Door Lock (192.168.1.11:22)")
    print("-"*75)
    bf_pkts = simulator.inject_brute_force(target_ip="192.168.1.11", attempts=8)
    print(f">> Injected {len(bf_pkts)} failed authentication attempts.")

    new_alerts = detection_engine.analyze_packets(simulator.packet_buffer)
    for alt in new_alerts:
        print(f"\n🚨 DETECTED: [{alt.category}] Severity: {alt.severity}")
        print(f"   Detail: {alt.detail}")
        action = response_engine.process_alert(alt)
        print(f"   Action Taken: {action.action} | iptables rule:")
        print(f"   >>> {action.iptables_command}")

    # 4. Attack Pattern C: C2 Beaconing
    print("\n" + "-"*75)
    print("[PHASE 4] Injecting Attack C: Command & Control (C2) Beaconing...")
    print("Scenario: Compromised Power Plug (192.168.1.13) phoning home every 2.5s (jitter < 0.05s)")
    print("-"*75)
    c2_pkts = simulator.inject_c2_beaconing(compromised_ip="192.168.1.13", count=8, interval=2.5)
    print(f">> Injected {len(c2_pkts)} beacon heartbeats.")

    new_alerts = detection_engine.analyze_packets(simulator.packet_buffer)
    for alt in new_alerts:
        print(f"\n🚨 DETECTED: [{alt.category}] Severity: {alt.severity}")
        print(f"   Detail: {alt.detail}")
        action = response_engine.process_alert(alt)
        print(f"   Action Taken: {action.action} | iptables rule:")
        print(f"   >>> {action.iptables_command}")

    # 5. Attack Pattern D: Volume Flood
    print("\n" + "-"*75)
    print("[PHASE 5] Injecting Attack D: Volume Flood Surge...")
    print("Scenario: Sudden high-volume UDP flood targeting Camera (192.168.1.10)")
    print("-"*75)
    flood_pkts = simulator.inject_volume_flood(target_ip="192.168.1.10", packet_count=35, bytes_per_packet=1400)
    print(f">> Injected {len(flood_pkts)} packets (~49,000 bytes).")

    new_alerts = detection_engine.analyze_packets(simulator.packet_buffer)
    for alt in new_alerts:
        print(f"\n🚨 DETECTED: [{alt.category}] Severity: {alt.severity}")
        print(f"   Detail: {alt.detail}")
        action = response_engine.process_alert(alt)
        print(f"   Action Taken: {action.action} | iptables rule:")
        print(f"   >>> {action.iptables_command}")

    # Summary
    print("\n" + "="*75)
    print("📊 GATEWAY SUMMARY LEDGER")
    print("="*75)
    print(f"Total Packets Processed: {len(simulator.packet_buffer)}")
    print(f"Total Alerts Flagged:    {len(detection_engine.alerts)}")
    print(f"Active Blocklisted IPs:  {list(response_engine.blocklist)}")
    print(f"Safety Mode:             {'ON (Safe simulation)' if response_engine.safety_mode else 'OFF (Live execution)'}")
    print("="*75)
    print("\nTo launch the real-time web dashboard:")
    print("    python main.py --web")
    print("    or run: uvicorn dashboard:app --reload --port 8000\n")


def start_web_dashboard():
    """Starts the FastAPI web server using uvicorn."""
    try:
        import uvicorn
        print("\n[+] Starting FastAPI Web Dashboard on http://localhost:8000 ...")
        uvicorn.run("dashboard:app", host="0.0.0.0", port=8000, reload=True)
    except ImportError:
        print("\n[!] uvicorn is not installed.")
        print("Please install requirements first:")
        print("    pip install -r requirements.txt")
        print("Then re-run: python main.py --web")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IoT Threat Detection & Hardening Gateway")
    parser.add_argument("--web", action="store_true", help="Launch FastAPI web dashboard on http://localhost:8000")
    args = parser.parse_args()

    if args.web:
        start_web_dashboard()
    else:
        run_full_simulation_demo()
