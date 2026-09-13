# Security Policy

## Supported Versions

We actively maintain and provide security updates for the latest version of the IoT Threat Detection Gateway:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## 🔒 Safety Mode Notice

By default, the Python response engine (`iot_gateway/response_engine.py`) operates with `safety_mode = True`.

In **Safety Mode**:
- The engine synthesizes and logs the exact `iptables` and Windows `netsh` firewall rules to standard output and the SOC ledger.
- It **does NOT** execute host-level network drops or kernel command subprocesses on your workstation.
- When deploying to production on dedicated Linux hardware (e.g. Raspberry Pi gateway router), you can explicitly set `safety_mode = False` to enforce live kernel packet dropping.

---

## 🚨 Reporting a Security Vulnerability

If you discover a potential vulnerability or security flaw within the application:

1. **Do not create a public GitHub issue.**
2. Please report the issue privately by opening a [GitHub Security Advisory](https://github.com/<your-username>/iot-threat-detection-gateway/security/advisories/new) or contacting the maintainers directly.
3. Include detailed steps to reproduce the behavior, along with sample packet captures or environment configurations where applicable.

We take security vulnerabilities seriously and will acknowledge receipt within 48 hours and provide a remediation timeline.
