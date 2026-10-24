import React, { useState, useEffect, useRef, useMemo } from 'react';
import { Sidebar, NavTab } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { TacticalRadarView } from './components/TacticalRadarView';
import { StatCardsRow } from './components/StatCardsRow';
import { ObservabilityChart } from './components/ObservabilityChart';
import { AlertsDataTable } from './components/AlertsDataTable';
import { ResponseActionsTable } from './components/ResponseActionsTable';
import { DeviceListPanel } from './components/DeviceListPanel';
import { BlocklistPanel } from './components/BlocklistPanel';
import { PacketTerminal } from './components/PacketTerminal';
import { TopologyPanel } from './components/TopologyPanel';
import { SettingsPanel } from './components/SettingsPanel';
import { AttackSimulatorDrawer } from './components/AttackSimulatorDrawer';
import { PythonProjectViewer } from './components/PythonProjectViewer';
import { VoiceAlertHUD } from './components/VoiceAlertHUD';
import { MTBITrendAnalysis } from './components/MTBITrendAnalysis';
import { ThreatHeatmap } from './components/ThreatHeatmap';
import { AdaptiveBaselineHUD } from './components/AdaptiveBaselineHUD';
import { INITIAL_DEVICES, DEFAULT_THRESHOLDS, DEFAULT_ADAPTIVE_CONFIG, INITIAL_SUPPRESSED_EVENTS, EXTERNAL_ATTACKER_IP, C2_SERVER_IP, getInitialAlerts } from './data/mockData';
import { IoTDevice, Packet, ThreatAlert, ResponseAction, DetectionThresholds, AlertCategory, AdaptiveBaselineConfig, SuppressedFalsePositive, OperationalRegime } from './types';
import { speechEngine } from './utils/speechNotification';
import { Crosshair, KeyRound, Radio, Zap, ShieldAlert, ArrowUpRight, Filter, Clock } from 'lucide-react';

export default function App() {
  // State
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [currentTab, setCurrentTab] = useState<NavTab>('radar');
  const [devices, setDevices] = useState<IoTDevice[]>(INITIAL_DEVICES);
  const [packets, setPackets] = useState<Packet[]>([]);
  const [alerts, setAlerts] = useState<ThreatAlert[]>(() => getInitialAlerts());
  const [selectedSeverity, setSelectedSeverity] = useState<'ALL' | 'LOW' | 'MEDIUM' | 'HIGH'>('ALL');
  const [responseActions, setResponseActions] = useState<ResponseAction[]>([]);
  const [blocklist, setBlocklist] = useState<string[]>([]);
  const [safetyMode, setSafetyMode] = useState<boolean>(true); // default dry-run simulation mode
  const [monitoringActive, setMonitoringActive] = useState<boolean>(true); // auto traffic on
  const [ttsEnabled, setTtsEnabled] = useState<boolean>(speechEngine.isEnabled());
  const [isSpeakingTts, setIsSpeakingTts] = useState<boolean>(false);
  const [thresholds, setThresholds] = useState<DetectionThresholds>(DEFAULT_THRESHOLDS);
  const [adaptiveConfig, setAdaptiveConfig] = useState<AdaptiveBaselineConfig>(DEFAULT_ADAPTIVE_CONFIG);
  const [suppressedEvents, setSuppressedEvents] = useState<SuppressedFalsePositive[]>(INITIAL_SUPPRESSED_EVENTS);
  const [lastScanTime, setLastScanTime] = useState<number>(Date.now());
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [isAttackDrawerOpen, setIsAttackDrawerOpen] = useState<boolean>(false);
  const [isInjecting, setIsInjecting] = useState<boolean>(false);
  const [isPacketStreamPaused, setIsPacketStreamPaused] = useState<boolean>(false);
  const [uptimeSeconds, setUptimeSeconds] = useState<number>(142);
  const [packetRate, setPacketRate] = useState<number>(1.8);

  const alertCounterRef = useRef(4);
  const actionCounterRef = useRef(1);
  const suppressionMapRef = useRef<Map<string, number>>(new Map());
  const devicesRef = useRef(devices);
  devicesRef.current = devices;
  const blocklistRef = useRef(blocklist);
  blocklistRef.current = blocklist;

  // Subscribe to speech synthesis state
  useEffect(() => {
    return speechEngine.subscribe((speaking) => {
      setIsSpeakingTts(speaking);
      setTtsEnabled(speechEngine.isEnabled());
    });
  }, []);

  // Uptime ticker
  useEffect(() => {
    const timer = setInterval(() => {
      setUptimeSeconds((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  // Seed initial baseline benign packets
  useEffect(() => {
    const seedPackets: Packet[] = [];
    const now = Date.now();
    for (let i = 0; i < 20; i++) {
      const dev = INITIAL_DEVICES[i % INITIAL_DEVICES.length];
      const proto = dev.normalProtocols[0];
      const dest = dev.normalDestinations[0];
      const port = dev.normalPorts[0];
      seedPackets.push({
        id: `pkt-seed-${i}`,
        timestamp: now - (20 - i) * 1100,
        srcIp: dev.ip,
        dstIp: dest,
        srcPort: 38000 + i * 150,
        dstPort: port,
        protocol: proto,
        length: 76 + (i * 32) % 400,
        flags: 'ACK,PSH',
        authSuccess: null,
        payloadInfo: `Standard ${dev.deviceType} heartbeat telemetry`,
        isAttack: false,
      });
    }
    setPackets(seedPackets);
  }, []);

  // Background benign traffic generator (runs if monitoringActive is true)
  useEffect(() => {
    if (!monitoringActive || isPacketStreamPaused) return;

    const interval = setInterval(() => {
      // Pick random online device not quarantined
      const onlineDevs = devicesRef.current.filter((d) => !blocklistRef.current.includes(d.ip));
      if (onlineDevs.length === 0) return;

      const randomDev = onlineDevs[Math.floor(Math.random() * onlineDevs.length)];
      const destIp = randomDev.normalDestinations[Math.floor(Math.random() * randomDev.normalDestinations.length)];
      const port = randomDev.normalPorts[Math.floor(Math.random() * randomDev.normalPorts.length)];
      const proto = randomDev.normalProtocols[Math.floor(Math.random() * randomDev.normalProtocols.length)];

      let payloadDesc = 'Telemetry ping';
      let len = 88;
      if (randomDev.deviceType === 'Security Camera') {
        payloadDesc = 'RTSP H.264 Video Substream (1080p)';
        len = 1140;
      } else if (randomDev.deviceType === 'Access Control') {
        payloadDesc = 'MQTT Keepalive / Door Status: LATCHED';
        len = 120;
      } else if (randomDev.deviceType === 'Environment Sensor') {
        payloadDesc = 'MQTT Ingestion: 21.8C, 44% Humidity';
        len = 72;
      } else if (randomDev.deviceType === 'Power Controller') {
        payloadDesc = 'HTTP Telemetry: 120V / 0.4A load';
        len = 148;
      } else if (randomDev.deviceType === 'Climate Control') {
        payloadDesc = 'HTTP API Status: Target 22C, Fan AUTO';
        len = 192;
      }

      const newPkt: Packet = {
        id: `pkt-${Date.now()}-${Math.random().toString(36).substr(2, 4)}`,
        timestamp: Date.now(),
        srcIp: randomDev.ip,
        dstIp: destIp,
        srcPort: Math.floor(32000 + Math.random() * 28000),
        dstPort: port,
        protocol: proto,
        length: len,
        flags: 'ACK,PSH',
        authSuccess: null,
        payloadInfo: payloadDesc,
        isAttack: false,
      };

      setPackets((prev) => [...prev.slice(-400), newPkt]);
      setPacketRate(1.2 + Math.random() * 1.5);

      // Update device telemetry metrics
      setDevices((prev) =>
        prev.map((d) =>
          d.id === randomDev.id
            ? {
                ...d,
                packetsSent: d.packetsSent + 1,
                bytesTotal: d.bytesTotal + len,
                lastSeen: Date.now(),
              }
            : d
        )
      );
    }, 2000);

    return () => clearInterval(interval);
  }, [monitoringActive, isPacketStreamPaused]);

  // Compute time of day, operational regime, and effective thresholds
  const currentHour = useMemo(() => {
    if (adaptiveConfig.mode === 'MANUAL_SIMULATED') {
      return adaptiveConfig.simulatedHour;
    }
    const d = new Date();
    return d.getHours() + d.getMinutes() / 60;
  }, [adaptiveConfig.mode, adaptiveConfig.simulatedHour]);

  const { regime, multiplier } = useMemo(() => {
    if (!adaptiveConfig.enabled) {
      return { regime: 'PEAK_HOURS' as OperationalRegime, multiplier: 1.0 };
    }
    const mStart = adaptiveConfig.maintenanceStartHour;
    const mEnd = adaptiveConfig.maintenanceEndHour;
    let inM = false;
    if (mStart < mEnd) {
      inM = currentHour >= mStart && currentHour < mEnd;
    } else {
      inM = currentHour >= mStart || currentHour < mEnd;
    }

    if (inM) {
      return { regime: 'MAINTENANCE_WINDOW' as OperationalRegime, multiplier: adaptiveConfig.maintenanceFactor };
    }

    const isOff = currentHour >= 18 || currentHour < 2 || (currentHour >= 5 && currentHour < 8);
    if (isOff) {
      return { regime: 'OFF_PEAK' as OperationalRegime, multiplier: adaptiveConfig.offpeakFactor };
    }

    return { regime: 'PEAK_HOURS' as OperationalRegime, multiplier: 1.0 };
  }, [adaptiveConfig, currentHour]);

  const effectiveThresholds = useMemo(() => {
    const m = adaptiveConfig.enabled ? multiplier : 1.0;
    return {
      portScanUniquePorts: Math.round(thresholds.portScanUniquePorts * m),
      portScanWindowSec: thresholds.portScanWindowSec,
      bruteForceFailures: Math.round(thresholds.bruteForceFailures * m),
      bruteForceWindowSec: thresholds.bruteForceWindowSec,
      beaconingMinPackets: thresholds.beaconingMinPackets,
      beaconingMaxJitterSec: Number((thresholds.beaconingMaxJitterSec * (1 + (m - 1) * 0.4)).toFixed(3)),
      beaconingWindowSec: thresholds.beaconingWindowSec,
      volumeFloodBytes: Math.round(thresholds.volumeFloodBytes * m),
      volumeFloodWindowSec: thresholds.volumeFloodWindowSec,
      usbExfiltrationBytes: thresholds.usbExfiltrationBytes,
      usbExfiltrationWindowSec: thresholds.usbExfiltrationWindowSec,
    };
  }, [thresholds, adaptiveConfig.enabled, multiplier]);

  // Core Rule-Based Detection Engine Heuristics
  const runDetectionScan = (packetList?: Packet[]) => {
    setIsScanning(true);
    const now = Date.now();
    setLastScanTime(now);

    const pktsToInspect = packetList || packets;
    const newAlerts: ThreatAlert[] = [];
    const newActions: ResponseAction[] = [];

    const isSuppressed = (category: string, src: string, dst: string) => {
      const key = `${category}:${src}:${dst}`;
      const last = suppressionMapRef.current.get(key);
      if (last && now - last < 12000) return true;
      suppressionMapRef.current.set(key, now);
      return false;
    };

    // 1. Port Scan Detection (Unique destination ports >= threshold)
    const scanWindowMs = effectiveThresholds.portScanWindowSec * 1000;
    const scanMap = new Map<string, Set<number>>();
    pktsToInspect.forEach((p) => {
      if (now - p.timestamp <= scanWindowMs) {
        const key = `${p.srcIp}->${p.dstIp}`;
        if (!scanMap.has(key)) scanMap.set(key, new Set());
        scanMap.get(key)!.add(p.dstPort);
      }
    });

    scanMap.forEach((ports, key) => {
      const [src, dst] = key.split('->');
      if (ports.size >= thresholds.portScanUniquePorts) {
        // Adaptive Baseline Check: Is this within the expanded maintenance allowance?
        if (
          ports.size < effectiveThresholds.portScanUniquePorts &&
          adaptiveConfig.enabled &&
          adaptiveConfig.autoSuppressMaintenanceSpikes
        ) {
          if (!isSuppressed('SUPPRESSED_PORT_SCAN', src, dst)) {
            setSuppressedEvents((prev) => [
              {
                id: `SUP-${String(Date.now()).slice(-4)}`,
                timestamp: now,
                category: 'PORT_SCAN',
                sourceIp: src,
                targetIp: dst,
                rawMetric: ports.size,
                metricUnit: 'Ports',
                staticThreshold: thresholds.portScanUniquePorts,
                adaptiveThreshold: effectiveThresholds.portScanUniquePorts,
                regime: regime,
                multiplier: multiplier,
                reason: `Automated asset discovery probe (${ports.size} ports) safely absorbed under Adaptive Baseline during ${regime}. Preserved node connectivity.`,
                preventedAction: `iptables -A FORWARD -s ${src} -j DROP`,
              },
              ...prev.slice(0, 49),
            ]);
          }
          return;
        }

        if (!isSuppressed('PORT_SCAN', src, dst)) {
          const alertId = `ALT-${String(alertCounterRef.current++).padStart(4, '0')}`;
          newAlerts.push({
            id: alertId,
            timestamp: now,
            category: 'PORT_SCAN',
            severity: 'HIGH',
            sourceIp: src,
            targetIp: dst,
            detail: `Rapid TCP port scan detected from ${src}: probed ${ports.size} ports on ${dst} within ${thresholds.portScanWindowSec}s${
              multiplier > 1.0 ? ` [Regime: ${regime}, Adaptive Limit: ${effectiveThresholds.portScanUniquePorts}]` : ''
            }.`,
            evidence: {
              uniquePortsCount: ports.size,
              samplePorts: Array.from(ports).slice(0, 8),
              windowSec: thresholds.portScanWindowSec,
              adaptiveBaseline: {
                regime,
                multiplier,
                effectiveThreshold: effectiveThresholds.portScanUniquePorts,
                baselineAdjusted: multiplier > 1.0,
              },
            },
            status: 'ACTIVE',
          });
        }
      }
    });

    // 2. Brute Force Login Detection (Failed auth count >= threshold)
    const bruteWindowMs = effectiveThresholds.bruteForceWindowSec * 1000;
    const bruteMap = new Map<string, number>();
    pktsToInspect.forEach((p) => {
      if (now - p.timestamp <= bruteWindowMs && p.authSuccess === false) {
        const key = `${p.srcIp}->${p.dstIp}:${p.dstPort}`;
        bruteMap.set(key, (bruteMap.get(key) || 0) + 1);
      }
    });

    bruteMap.forEach((count, key) => {
      const [src, rest] = key.split('->');
      const [dst, port] = rest.split(':');
      if (count >= thresholds.bruteForceFailures) {
        // Adaptive Baseline Check
        if (
          count < effectiveThresholds.bruteForceFailures &&
          adaptiveConfig.enabled &&
          adaptiveConfig.autoSuppressMaintenanceSpikes
        ) {
          if (!isSuppressed('SUPPRESSED_BRUTE_FORCE', src, dst)) {
            setSuppressedEvents((prev) => [
              {
                id: `SUP-${String(Date.now()).slice(-4)}`,
                timestamp: now,
                category: 'BRUTE_FORCE',
                sourceIp: src,
                targetIp: dst,
                rawMetric: count,
                metricUnit: 'Attempts',
                staticThreshold: thresholds.bruteForceFailures,
                adaptiveThreshold: effectiveThresholds.bruteForceFailures,
                regime: regime,
                multiplier: multiplier,
                reason: `Failed auth surge (${count} attempts on port ${port}) tolerated under Adaptive Baseline during ${regime}. Absorbed automated credential rotation.`,
                preventedAction: `iptables -A FORWARD -s ${src} -j DROP`,
              },
              ...prev.slice(0, 49),
            ]);
          }
          return;
        }

        if (!isSuppressed('BRUTE_FORCE', src, dst)) {
          const alertId = `ALT-${String(alertCounterRef.current++).padStart(4, '0')}`;
          newAlerts.push({
            id: alertId,
            timestamp: now,
            category: 'BRUTE_FORCE',
            severity: 'HIGH',
            sourceIp: src,
            targetIp: dst,
            detail: `Credential brute-force login surge from ${src} targeting ${dst}:${port} (${count} failed attempts).`,
            evidence: {
              failedAttempts: count,
              targetPort: Number(port),
              windowSec: thresholds.bruteForceWindowSec,
              adaptiveBaseline: {
                regime,
                multiplier,
                effectiveThreshold: effectiveThresholds.bruteForceFailures,
              },
            },
            status: 'ACTIVE',
          });
        }
      }
    });

    // 3. C2 Beaconing Detection (Low jitter periodicity)
    const beaconWindowMs = effectiveThresholds.beaconingWindowSec * 1000;
    const beaconMap = new Map<string, number[]>();
    const sorted = [...pktsToInspect].sort((a, b) => a.timestamp - b.timestamp);
    sorted.forEach((p) => {
      if (now - p.timestamp <= beaconWindowMs) {
        const key = `${p.srcIp}->${p.dstIp}`;
        if (!beaconMap.has(key)) beaconMap.set(key, []);
        beaconMap.get(key)!.push(p.timestamp);
      }
    });

    beaconMap.forEach((timestamps, key) => {
      if (timestamps.length >= effectiveThresholds.beaconingMinPackets) {
        const deltas: number[] = [];
        for (let i = 1; i < timestamps.length; i++) {
          const delta = (timestamps[i] - timestamps[i - 1]) / 1000;
          if (delta > 0.001) deltas.push(delta);
        }

        if (deltas.length >= effectiveThresholds.beaconingMinPackets - 1) {
          const mean = deltas.reduce((a, b) => a + b, 0) / deltas.length;
          const variance = deltas.reduce((acc, d) => acc + Math.pow(d - mean, 2), 0) / deltas.length;
          const stdDev = Math.sqrt(variance);
          const [src, dst] = key.split('->');

          if (mean >= 0.5 && stdDev <= effectiveThresholds.beaconingMaxJitterSec && !isSuppressed('C2_BEACONING', src, dst)) {
            const alertId = `ALT-${String(alertCounterRef.current++).padStart(4, '0')}`;
            newAlerts.push({
              id: alertId,
              timestamp: now,
              category: 'C2_BEACONING',
              severity: 'HIGH',
              sourceIp: src,
              targetIp: dst,
              detail: `Command & Control (C2) beacon detected: ${src} -> ${dst} checkin pulses every ~${mean.toFixed(2)}s with minimal jitter (std-dev: ${stdDev.toFixed(4)}s).`,
              evidence: {
                pulsesObserved: timestamps.length,
                meanIntervalSec: Number(mean.toFixed(2)),
                jitterStdDevSec: Number(stdDev.toFixed(4)),
                sampleDeltas: deltas.slice(0, 4).map((d) => Number(d.toFixed(2))),
                adaptiveBaseline: {
                  regime,
                  multiplier,
                  jitterLimit: effectiveThresholds.beaconingMaxJitterSec,
                },
              },
              status: 'ACTIVE',
            });
          }
        }
      }
    });

    // 4. Volume Flood Detection (Total bytes >= threshold in window)
    const floodWindowMs = effectiveThresholds.volumeFloodWindowSec * 1000;
    const floodMap = new Map<string, { bytes: number; count: number }>();
    pktsToInspect.forEach((p) => {
      // Protocol filter: ignore USB/Endpoint DLP writes to prevent cross-contamination
      if (now - p.timestamp <= floodWindowMs && p.protocol !== 'USB') {
        const key = `${p.srcIp}->${p.dstIp}`;
        const curr = floodMap.get(key) || { bytes: 0, count: 0 };
        floodMap.set(key, { bytes: curr.bytes + p.length, count: curr.count + 1 });
      }
    });

    floodMap.forEach((stat, key) => {
      const [src, dst] = key.split('->');
      if (stat.bytes >= thresholds.volumeFloodBytes) {
        // Adaptive Baseline Check
        if (
          stat.bytes < effectiveThresholds.volumeFloodBytes &&
          adaptiveConfig.enabled &&
          adaptiveConfig.autoSuppressMaintenanceSpikes
        ) {
          if (!isSuppressed('SUPPRESSED_VOLUME_FLOOD', src, dst)) {
            setSuppressedEvents((prev) => [
              {
                id: `SUP-${String(Date.now()).slice(-4)}`,
                timestamp: now,
                category: 'VOLUME_FLOOD',
                sourceIp: src,
                targetIp: dst,
                rawMetric: stat.bytes,
                metricUnit: 'Bytes',
                staticThreshold: thresholds.volumeFloodBytes,
                adaptiveThreshold: effectiveThresholds.volumeFloodBytes,
                regime: regime,
                multiplier: multiplier,
                reason: `OTA firmware binary / maintenance backup surge of ${(stat.bytes / 1024).toFixed(1)} KB safely absorbed under Adaptive Baseline during ${regime}. Prevented false positive isolation.`,
                preventedAction: `iptables -A FORWARD -s ${src} -j DROP`,
              },
              ...prev.slice(0, 49),
            ]);
          }
          return;
        }

        if (!isSuppressed('VOLUME_FLOOD', src, dst)) {
          const alertId = `ALT-${String(alertCounterRef.current++).padStart(4, '0')}`;
          newAlerts.push({
            id: alertId,
            timestamp: now,
            category: 'VOLUME_FLOOD',
            severity: 'HIGH',
            sourceIp: src,
            targetIp: dst,
            detail: `Volume flood DDoS surge from ${src} -> ${dst}: ${stat.bytes.toLocaleString()} bytes transmitted in ${thresholds.volumeFloodWindowSec}s${
              multiplier > 1.0 ? ` [Regime: ${regime}, Adaptive Limit: ${effectiveThresholds.volumeFloodBytes.toLocaleString()}B]` : ''
            }.`,
            evidence: {
              totalBytes: stat.bytes,
              packetCount: stat.count,
              windowSec: thresholds.volumeFloodWindowSec,
              bandwidthRate: `${Math.round(stat.bytes / thresholds.volumeFloodWindowSec / 1024)} KB/s`,
              adaptiveBaseline: {
                regime,
                multiplier,
                effectiveThresholdBytes: effectiveThresholds.volumeFloodBytes,
              },
            },
            status: 'ACTIVE',
          });
        }
      }
    });

    // 5. Air-Gapped USB Data Exfiltration Detection (USB write volume >= threshold in window)
    const usbWindowMs = (thresholds.usbExfiltrationWindowSec || 30.0) * 1000;
    const usbMap = new Map<string, { bytes: number; count: number; files: string[]; device: string }>();
    pktsToInspect.forEach((p) => {
      if (now - p.timestamp <= usbWindowMs && p.protocol === 'USB') {
        const key = p.srcIp;
        const curr = usbMap.get(key) || { bytes: 0, count: 0, files: [], device: 'SanDisk Ultra USB 3.0' };
        const fileMatch = p.payloadInfo.match(/File: ([\w\-.]+)/);
        if (fileMatch && !curr.files.includes(fileMatch[1])) {
          curr.files.push(fileMatch[1]);
        }
        usbMap.set(key, { bytes: curr.bytes + p.length, count: curr.count + 1, files: curr.files, device: curr.device });
      }
    });

    usbMap.forEach((stat, srcIp) => {
      const usbThreshold = thresholds.usbExfiltrationBytes || 50 * 1024 * 1024;
      if (stat.bytes >= usbThreshold && !isSuppressed('USB_EXFILTRATION', srcIp, 'USB_MASS_STORAGE')) {
        const alertId = `ALT-${String(alertCounterRef.current++).padStart(4, '0')}`;
        newAlerts.push({
          id: alertId,
          timestamp: now,
          category: 'USB_EXFILTRATION',
          severity: 'HIGH',
          sourceIp: srcIp,
          targetIp: 'USB_MASS_STORAGE (E:)',
          detail: `Air-Gapped USB Data Exfiltration detected on ${srcIp}: ${(stat.bytes / (1024 * 1024)).toFixed(1)} MB copied to unauthorized ${stat.device} in ${thresholds.usbExfiltrationWindowSec || 30}s without network traversal.`,
          evidence: {
            totalBytes: stat.bytes,
            transferredMB: Number((stat.bytes / (1024 * 1024)).toFixed(2)),
            filesExfiltrated: stat.files.length > 0 ? stat.files : ['customer_pii_dump_2026.sql.gz', 'tls_private_keys.tar.enc'],
            usbDevice: stat.device,
            driveLetter: 'E:\\',
            detectionMechanism: 'Endpoint DLP Telemetry Agent (usb_monitor.py)',
          },
          status: 'ACTIVE',
        });
      }
    });

    // Response Engine: Synthesize isolation rules for alerts
    const newlyBlockedIps: string[] = [];
    newAlerts.forEach((alt) => {
      const ipToIsolate = alt.sourceIp;
      newlyBlockedIps.push(ipToIsolate);

      let iptablesRule = `iptables -A FORWARD -s ${ipToIsolate} -j DROP && iptables -A INPUT -s ${ipToIsolate} -j DROP`;
      let windowsRule = `netsh advfirewall firewall add rule name="IoT_Quarantine_${ipToIsolate}" dir=in action=block remoteip=${ipToIsolate}`;
      let reason = `Automated policy triggered: ${alt.category} flagged. Dropping ${ipToIsolate} in iptables FORWARD/INPUT chains.`;

      if (alt.category === 'USB_EXFILTRATION') {
        windowsRule = `reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" /v Start /t REG_DWORD /d 4 /f`;
        iptablesRule = `modprobe -r usb_storage && echo 'blacklist usb-storage' >> /etc/modprobe.d/blacklist.conf`;
        reason = `Air-gapped DLP response: Network iptables cannot stop physical USB. Enforced endpoint driver lockdown (USBSTOR Start=4 / modprobe blacklist) on ${ipToIsolate}.`;
      }

      newActions.push({
        id: `ACT-${String(actionCounterRef.current++).padStart(4, '0')}`,
        timestamp: now,
        alertId: alt.id,
        targetIp: ipToIsolate,
        category: alt.category,
        action: 'ISOLATE',
        reason: reason,
        iptablesCommand: iptablesRule,
        windowsCommand: windowsRule,
        executedLive: !safetyMode,
        status: 'ACTIVE_BLOCK',
      });
    });

    if (newAlerts.length > 0) {
      setAlerts((prev) => [...prev, ...newAlerts]);
      setResponseActions((prev) => [...prev, ...newActions]);
      setBlocklist((prev) => Array.from(new Set([...prev, ...newlyBlockedIps])));

      // Trigger browser-based Text-to-Speech notification for HIGH severity threat alerts
      const highAlerts = newAlerts.filter((alt) => alt.severity === 'HIGH');
      if (highAlerts.length > 0 && ttsEnabled) {
        speechEngine.speakBatchHighAlerts(highAlerts);
      }

      // Mark compromised internal IoT devices
      setDevices((prev) =>
        prev.map((dev) =>
          newlyBlockedIps.includes(dev.ip)
            ? { ...dev, status: 'QUARANTINED', compromised: true }
            : dev
        )
      );
    }

    setTimeout(() => setIsScanning(false), 300);
  };

  // Attack Injection Handler
  const handleInjectAttack = (category: AlertCategory, targetIp: string) => {
    setIsInjecting(true);
    const now = Date.now();
    const injectedPackets: Packet[] = [];

    if (category === 'PORT_SCAN') {
      const scanPorts = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 554, 8080, 8443, 8888, 9000, 9999, 1883, 3389];
      scanPorts.forEach((port, idx) => {
        injectedPackets.push({
          id: `attack-scan-${now}-${idx}`,
          timestamp: now + idx * 40,
          srcIp: EXTERNAL_ATTACKER_IP,
          dstIp: targetIp,
          srcPort: 42000 + idx * 10,
          dstPort: port,
          protocol: 'TCP',
          length: 60,
          flags: 'SYN',
          authSuccess: null,
          payloadInfo: `TCP SYN Port Recon Probe -> Port ${port}`,
          isAttack: true,
          attackType: 'PORT_SCAN',
        });
      });
    } else if (category === 'BRUTE_FORCE') {
      for (let i = 0; i < 8; i++) {
        injectedPackets.push({
          id: `attack-bf-${now}-${i}`,
          timestamp: now + i * 200,
          srcIp: EXTERNAL_ATTACKER_IP,
          dstIp: targetIp,
          srcPort: 48100 + i,
          dstPort: 22,
          protocol: 'TCP',
          length: 184,
          flags: 'ACK,PSH',
          authSuccess: false,
          payloadInfo: `SSH Auth Failed: user=root/admin attempt ${i + 1}/8`,
          isAttack: true,
          attackType: 'BRUTE_FORCE',
        });
      }
    } else if (category === 'C2_BEACONING') {
      for (let i = 0; i < 8; i++) {
        const jitter = (Math.random() - 0.5) * 0.04;
        injectedPackets.push({
          id: `attack-c2-${now}-${i}`,
          timestamp: now + i * 2400 + jitter * 1000,
          srcIp: targetIp, // The infected IoT device
          dstIp: C2_SERVER_IP,
          srcPort: 39100 + i,
          dstPort: 8443,
          protocol: 'HTTPS',
          length: 210,
          flags: 'ACK,PSH',
          authSuccess: null,
          payloadInfo: `C2 Heartbeat Pulse #${i + 1} [Encrypted checkin payload]`,
          isAttack: true,
          attackType: 'C2_BEACONING',
        });
      }
    } else if (category === 'VOLUME_FLOOD') {
      for (let i = 0; i < 35; i++) {
        injectedPackets.push({
          id: `attack-flood-${now}-${i}`,
          timestamp: now + i * 20,
          srcIp: EXTERNAL_ATTACKER_IP,
          dstIp: targetIp,
          srcPort: 51000 + i,
          dstPort: 80,
          protocol: 'UDP',
          length: 1400,
          flags: 'NONE',
          authSuccess: null,
          payloadInfo: `High-Volume UDP Flood Packet #${i + 1} (1400B)`,
          isAttack: true,
          attackType: 'VOLUME_FLOOD',
        });
      }
    } else if (category === 'USB_EXFILTRATION') {
      const files = [
        { name: 'customer_pii_dump_2026.sql.gz', bytes: 48 * 1024 * 1024 },
        { name: 'tls_private_keys_backup.tar.enc', bytes: 22 * 1024 * 1024 },
        { name: 'iot_gateway_firmware_signing.key', bytes: 15 * 1024 * 1024 },
      ];
      const hostIp = targetIp || '192.168.1.15';
      files.forEach((f, idx) => {
        injectedPackets.push({
          id: `attack-usb-${now}-${idx}`,
          timestamp: now + idx * 4500,
          srcIp: hostIp,
          dstIp: 'USB_STORAGE_E:',
          srcPort: 0,
          dstPort: 0,
          protocol: 'USB',
          length: f.bytes,
          flags: 'DLP_WRITE',
          authSuccess: null,
          payloadInfo: `[ENDPOINT DLP] File: ${f.name} -> SanDisk Ultra 3.0 (E:) | ${(f.bytes / (1024 * 1024)).toFixed(1)}MB`,
          isAttack: true,
          attackType: 'USB_EXFILTRATION',
        });
      });
    }

    const updated = [...packets, ...injectedPackets];
    setPackets(updated);

    setTimeout(() => {
      runDetectionScan(updated);
      setIsInjecting(false);
      setIsAttackDrawerOpen(false);
    }, 450);
  };

  // Maintenance Routine Simulation Handler (Adaptive Baseline Test)
  const handleTriggerMaintenanceTest = (routineType: 'firmware_sync' | 'asset_discovery_scan') => {
    setIsInjecting(true);
    const now = Date.now();
    const injectedPackets: Packet[] = [];
    const targetCameraIp = '192.168.1.10';

    if (routineType === 'firmware_sync') {
      // 25 chunks * 1500 bytes = 37,500 bytes (exceeds static 25KB, within adaptive 55KB)
      for (let i = 0; i < 25; i++) {
        injectedPackets.push({
          id: `maint-fw-${now}-${i}`,
          timestamp: now + i * 40,
          srcIp: '52.14.99.102',
          dstIp: targetCameraIp,
          srcPort: 443,
          dstPort: 49152 + i,
          protocol: 'HTTPS',
          length: 1500,
          flags: 'ACK,PSH',
          authSuccess: null,
          payloadInfo: `[MAINTENANCE ROUTINE] OTA Firmware Update Chunk #${i + 1}/25 [v4.2.1-prod signed]`,
          isAttack: false,
        });
      }
    } else if (routineType === 'asset_discovery_scan') {
      // 17 ports probe from Gateway (exceeds static 15, within adaptive 33)
      const ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 554, 1883, 3306, 5000, 8080, 8443, 8883, 9000];
      ports.forEach((p, idx) => {
        injectedPackets.push({
          id: `maint-scan-${now}-${idx}`,
          timestamp: now + idx * 35,
          srcIp: '192.168.1.1',
          dstIp: targetCameraIp,
          srcPort: 42000 + idx,
          dstPort: p,
          protocol: 'TCP',
          length: 54,
          flags: 'SYN',
          authSuccess: null,
          payloadInfo: `[MAINTENANCE ROUTINE] Scheduled Lansweeper / Inventory Discovery Probe (port ${p})`,
          isAttack: false,
        });
      });
    }

    const updated = [...packets, ...injectedPackets];
    setPackets(updated);

    setTimeout(() => {
      runDetectionScan(updated);
      setIsInjecting(false);
    }, 400);
  };

  // Manual Isolation Toggle
  const handleToggleIsolate = (ip: string) => {
    if (blocklist.includes(ip)) {
      handleUnblock(ip);
    } else {
      setBlocklist((prev) => [...prev, ip]);
      const now = Date.now();
      const iptablesRule = `iptables -A FORWARD -s ${ip} -j DROP && iptables -A INPUT -s ${ip} -j DROP`;
      const windowsRule = `netsh advfirewall firewall add rule name="IoT_Quarantine_${ip}" dir=in action=block remoteip=${ip}`;

      setResponseActions((prev) => [
        ...prev,
        {
          id: `ACT-${String(actionCounterRef.current++).padStart(4, '0')}`,
          timestamp: now,
          alertId: 'MANUAL',
          targetIp: ip,
          category: 'PORT_SCAN',
          action: 'ISOLATE',
          reason: `Manual quarantine enforcement by operator for IP ${ip}.`,
          iptablesCommand: iptablesRule,
          windowsCommand: windowsRule,
          executedLive: !safetyMode,
          status: 'ACTIVE_BLOCK',
        },
      ]);

      setDevices((prev) =>
        prev.map((d) => (d.ip === ip ? { ...d, status: 'QUARANTINED' } : d))
      );
    }
  };

  const handleUnblock = (ip: string) => {
    setBlocklist((prev) => prev.filter((item) => item !== ip));
    setResponseActions((prev) =>
      prev.map((act) =>
        act.targetIp === ip && act.status === 'ACTIVE_BLOCK'
          ? { ...act, status: 'REVERTED' }
          : act
      )
    );
    setDevices((prev) =>
      prev.map((d) => (d.ip === ip ? { ...d, status: 'ONLINE', compromised: false } : d))
    );
  };

  const handleClearAlerts = () => {
    setAlerts([]);
    suppressionMapRef.current.clear();
  };

  return (
    <div className={`min-h-screen flex flex-col font-sans select-none antialiased transition-colors ${
      theme === 'dark' ? 'bg-[#0B0F17] text-slate-100' : 'bg-slate-100/70 text-slate-900'
    }`}>
      
      {/* Top Status Bar */}
      <TopBar
        monitoringActive={monitoringActive}
        onToggleMonitoring={() => setMonitoringActive(!monitoringActive)}
        deviceCount={devices.length}
        lastScanTime={lastScanTime}
        safetyMode={safetyMode}
        onToggleSafety={() => setSafetyMode(!safetyMode)}
        onRunScanNow={() => runDetectionScan()}
        isScanning={isScanning}
        onOpenThresholds={() => setCurrentTab('settings')}
        ttsEnabled={ttsEnabled}
        onToggleTts={() => {
          const next = !ttsEnabled;
          speechEngine.setEnabled(next);
          setTtsEnabled(next);
        }}
        isSpeakingTts={isSpeakingTts}
        onTestTts={() => speechEngine.testVoiceAlert()}
        theme={theme}
        onToggleTheme={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
        onOpenAttackDrawer={() => setIsAttackDrawerOpen(true)}
        adaptiveRegime={regime}
        adaptiveMultiplier={multiplier}
        onOpenBaseline={() => setCurrentTab('baseline')}
      />

      {/* Main Layout Body: Persistent Left Sidebar + Main Content */}
      <div className="flex-1 flex overflow-hidden">
        
        {/* Persistent Left Sidebar */}
        <Sidebar
          currentTab={currentTab}
          onSelectTab={(tab) => setCurrentTab(tab)}
          alertCount={alerts.length}
          blocklistCount={blocklist.length}
          deviceCount={devices.length}
          isSimulating={isInjecting}
          onOpenAttackDrawer={() => setIsAttackDrawerOpen(true)}
          mitigatedCount={suppressedEvents.length}
          theme={theme}
        />

        {/* Center Main Stage Content */}
        <main className={`flex-1 overflow-y-auto p-4 lg:p-6 space-y-4 transition-colors ${
          theme === 'dark' ? 'bg-[#0B0F17]' : 'bg-slate-50'
        }`}>
          
          {/* Top Quick Adversary Trigger Ribbon */}
          <div className={`border rounded-xl px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 transition-colors ${
            theme === 'dark' ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
          }`}>
            <div className="flex items-center gap-2.5">
              <span className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></span>
              <span className="font-mono text-xs font-bold uppercase tracking-wider">
                Adversary Vector Injection:
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
              <button
                onClick={() => handleInjectAttack('PORT_SCAN', '192.168.1.10')}
                className={`px-3 py-1.5 rounded-lg border flex items-center gap-1.5 cursor-pointer font-semibold transition-all ${
                  theme === 'dark' 
                    ? 'bg-[#141B28] text-slate-300 hover:text-white border-[#222E42] hover:border-blue-500/50' 
                    : 'bg-slate-100 text-slate-700 hover:text-slate-900 border-slate-200 hover:border-blue-300'
                }`}
                title="Inject 18-port TCP sweep"
              >
                <Crosshair className="w-3.5 h-3.5 text-blue-500" />
                <span>Port Scan</span>
              </button>

              <button
                onClick={() => handleInjectAttack('BRUTE_FORCE', '192.168.1.11')}
                className={`px-3 py-1.5 rounded-lg border flex items-center gap-1.5 cursor-pointer font-semibold transition-all ${
                  theme === 'dark' 
                    ? 'bg-[#141B28] text-slate-300 hover:text-white border-[#222E42] hover:border-rose-500/50' 
                    : 'bg-slate-100 text-slate-700 hover:text-slate-900 border-slate-200 hover:border-rose-300'
                }`}
                title="Inject SSH failed auth burst"
              >
                <KeyRound className="w-3.5 h-3.5 text-rose-500" />
                <span>Brute Force</span>
              </button>

              <button
                onClick={() => handleInjectAttack('C2_BEACONING', '192.168.1.12')}
                className={`px-3 py-1.5 rounded-lg border flex items-center gap-1.5 cursor-pointer font-semibold transition-all ${
                  theme === 'dark' 
                    ? 'bg-[#141B28] text-slate-300 hover:text-white border-[#222E42] hover:border-amber-500/50' 
                    : 'bg-slate-100 text-slate-700 hover:text-slate-900 border-slate-200 hover:border-amber-300'
                }`}
                title="Inject low-jitter C2 beacon pulses"
              >
                <Radio className="w-3.5 h-3.5 text-amber-500" />
                <span>C2 Beacon</span>
              </button>

              <button
                onClick={() => handleInjectAttack('VOLUME_FLOOD', '192.168.1.14')}
                className={`px-3 py-1.5 rounded-lg border flex items-center gap-1.5 cursor-pointer font-semibold transition-all ${
                  theme === 'dark' 
                    ? 'bg-[#141B28] text-slate-300 hover:text-white border-[#222E42] hover:border-purple-500/50' 
                    : 'bg-slate-100 text-slate-700 hover:text-slate-900 border-slate-200 hover:border-purple-300'
                }`}
                title="Inject 49KB UDP burst"
              >
                <Zap className="w-3.5 h-3.5 text-purple-500" />
                <span>Volume Flood</span>
              </button>

              <button
                onClick={() => setIsAttackDrawerOpen(true)}
                className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-bold cursor-pointer transition-all shadow-xs"
              >
                Simulator Console &rarr;
              </button>
            </div>
          </div>

          {/* TAB 0: TACTICAL RADAR HUD */}
          {currentTab === 'radar' && (
            <TacticalRadarView
              devices={devices}
              packets={packets}
              alerts={alerts}
              blocklist={blocklist}
              onToggleIsolate={handleToggleIsolate}
              onInjectAttack={handleInjectAttack}
              safetyMode={safetyMode}
              packetRate={packetRate}
              theme={theme}
            />
          )}

          {/* TAB 1: OVERVIEW */}
          {currentTab === 'overview' && (
            <div className="space-y-4">
              {/* Stat Cards */}
              <StatCardsRow
                totalEvents={packets.length}
                alertsCount={alerts.length}
                highSeverityCount={alerts.filter((a) => a.severity === 'HIGH').length}
                quarantinedCount={blocklist.length}
                totalDevices={devices.length}
                uptimeSeconds={uptimeSeconds}
                packetRate={packetRate}
                alerts={alerts}
                mitigatedFalsePositives={suppressedEvents.length}
                theme={theme}
              />

              {/* Trend Analysis: Mean Time Between Incidents (MTBI) & Security Posture Improvement */}
              <MTBITrendAnalysis
                alerts={alerts}
                uptimeSeconds={uptimeSeconds}
                blocklist={blocklist}
                theme={theme}
              />

              {/* Operational Observability: Recharts 60-Min Events & Threats Line Chart */}
              <ObservabilityChart
                packets={packets}
                alerts={alerts}
                packetRate={packetRate}
                theme={theme}
              />

              {/* Threat & Activity Heatmap: Grid-Based Frequency Matrix with Anomalous Spikes */}
              <ThreatHeatmap
                devices={devices}
                packets={packets}
                alerts={alerts}
                blocklist={blocklist}
                onToggleIsolate={handleToggleIsolate}
                onSelectAlertIp={(ip) => handleToggleIsolate(ip)}
                theme={theme}
              />

              {/* Severity Filter Buttons above AlertsDataTable */}
              <div
                className={`p-3 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 transition-colors ${
                  theme === 'dark' ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <div className={`p-1.5 rounded-lg ${theme === 'dark' ? 'bg-blue-500/10 text-blue-400' : 'bg-blue-50 text-blue-600'}`}>
                    <Filter className="w-4 h-4" />
                  </div>
                  <div>
                    <span className="text-xs font-semibold">Filter by Severity:</span>
                    <span className={`text-[11px] ml-2 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-500'}`}>
                      Filter security events across severity levels
                    </span>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-1.5">
                  {(
                    [
                      { id: 'ALL', label: 'All', count: alerts.length },
                      { id: 'LOW', label: 'Low', count: alerts.filter((a) => a.severity === 'LOW').length },
                      { id: 'MEDIUM', label: 'Medium', count: alerts.filter((a) => a.severity === 'MEDIUM').length },
                      { id: 'HIGH', label: 'High', count: alerts.filter((a) => a.severity === 'HIGH').length },
                    ] as const
                  ).map((btn) => {
                    const isSelected = selectedSeverity === btn.id;
                    return (
                      <button
                        key={btn.id}
                        onClick={() => setSelectedSeverity(btn.id)}
                        className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-2 transition-all cursor-pointer ${
                          isSelected
                            ? btn.id === 'HIGH'
                              ? 'bg-rose-600 text-white font-semibold shadow-xs'
                              : btn.id === 'MEDIUM'
                              ? 'bg-amber-600 text-white font-semibold shadow-xs'
                              : btn.id === 'LOW'
                              ? 'bg-sky-600 text-white font-semibold shadow-xs'
                              : 'bg-blue-600 text-white font-semibold shadow-xs'
                            : theme === 'dark'
                            ? 'bg-[#141B28] text-slate-300 hover:text-white border border-[#222E42] hover:border-slate-700'
                            : 'bg-slate-100 text-slate-700 hover:text-slate-900 border border-slate-200 hover:border-slate-300'
                        }`}
                        title={`Show ${btn.label} severity alerts`}
                      >
                        <span>{btn.label}</span>
                        <span
                          className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full ${
                            isSelected
                              ? 'bg-white/20 text-white font-bold'
                              : theme === 'dark'
                              ? 'bg-slate-800 text-slate-400'
                              : 'bg-slate-200 text-slate-600'
                          }`}
                        >
                          {btn.count}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Alerts Data Table */}
              <AlertsDataTable
                alerts={alerts}
                packets={packets}
                blocklist={blocklist}
                selectedSeverity={selectedSeverity}
                onSeverityChange={setSelectedSeverity}
                onClearAlerts={handleClearAlerts}
                onSelectAlertIp={(ip) => handleToggleIsolate(ip)}
                theme={theme}
              />

              {/* Response & Enforcement Ledger */}
              <ResponseActionsTable
                actions={responseActions}
                blocklist={blocklist}
                safetyMode={safetyMode}
                onUnblock={handleUnblock}
                theme={theme}
              />

              {/* Subnet Device Inventory */}
              <DeviceListPanel
                devices={devices}
                onToggleIsolate={handleToggleIsolate}
                blocklist={blocklist}
                theme={theme}
              />
            </div>
          )}

          {/* TAB 1.5: ADAPTIVE BASELINE HEURISTIC */}
          {currentTab === 'baseline' && (
            <AdaptiveBaselineHUD
              config={adaptiveConfig}
              onUpdateConfig={setAdaptiveConfig}
              thresholds={thresholds}
              suppressedEvents={suppressedEvents}
              onTriggerMaintenanceTest={handleTriggerMaintenanceTest}
              onClearSuppressedEvents={() => setSuppressedEvents([])}
              theme={theme}
            />
          )}

          {/* TAB 2: THREAT ALERTS */}
          {currentTab === 'alerts' && (
            <div className="space-y-4">
              {/* Severity Filter Buttons above AlertsDataTable */}
              <div
                className={`p-3 rounded-xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 transition-colors ${
                  theme === 'dark' ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <div className={`p-1.5 rounded-lg ${theme === 'dark' ? 'bg-blue-500/10 text-blue-400' : 'bg-blue-50 text-blue-600'}`}>
                    <Filter className="w-4 h-4" />
                  </div>
                  <div>
                    <span className="text-xs font-semibold">Filter by Severity:</span>
                    <span className={`text-[11px] ml-2 ${theme === 'dark' ? 'text-slate-400' : 'text-slate-500'}`}>
                      Filter security events across severity levels
                    </span>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-1.5">
                  {(
                    [
                      { id: 'ALL', label: 'All', count: alerts.length },
                      { id: 'LOW', label: 'Low', count: alerts.filter((a) => a.severity === 'LOW').length },
                      { id: 'MEDIUM', label: 'Medium', count: alerts.filter((a) => a.severity === 'MEDIUM').length },
                      { id: 'HIGH', label: 'High', count: alerts.filter((a) => a.severity === 'HIGH').length },
                    ] as const
                  ).map((btn) => {
                    const isSelected = selectedSeverity === btn.id;
                    return (
                      <button
                        key={btn.id}
                        onClick={() => setSelectedSeverity(btn.id)}
                        className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-2 transition-all cursor-pointer ${
                          isSelected
                            ? btn.id === 'HIGH'
                              ? 'bg-rose-600 text-white font-semibold shadow-xs'
                              : btn.id === 'MEDIUM'
                              ? 'bg-amber-600 text-white font-semibold shadow-xs'
                              : btn.id === 'LOW'
                              ? 'bg-sky-600 text-white font-semibold shadow-xs'
                              : 'bg-blue-600 text-white font-semibold shadow-xs'
                            : theme === 'dark'
                            ? 'bg-[#141B28] text-slate-300 hover:text-white border border-[#222E42] hover:border-slate-700'
                            : 'bg-slate-100 text-slate-700 hover:text-slate-900 border border-slate-200 hover:border-slate-300'
                        }`}
                        title={`Show ${btn.label} severity alerts`}
                      >
                        <span>{btn.label}</span>
                        <span
                          className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full ${
                            isSelected
                              ? 'bg-white/20 text-white font-bold'
                              : theme === 'dark'
                              ? 'bg-slate-800 text-slate-400'
                              : 'bg-slate-200 text-slate-600'
                          }`}
                        >
                          {btn.count}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </div>

              <AlertsDataTable
                alerts={alerts}
                packets={packets}
                blocklist={blocklist}
                selectedSeverity={selectedSeverity}
                onSeverityChange={setSelectedSeverity}
                onClearAlerts={handleClearAlerts}
                onSelectAlertIp={(ip) => handleToggleIsolate(ip)}
                theme={theme}
              />
              <ResponseActionsTable
                actions={responseActions}
                blocklist={blocklist}
                safetyMode={safetyMode}
                onUnblock={handleUnblock}
                theme={theme}
              />
            </div>
          )}

          {/* TAB 3: DEVICES */}
          {currentTab === 'devices' && (
            <div className="space-y-4">
              <DeviceListPanel
                devices={devices}
                onToggleIsolate={handleToggleIsolate}
                blocklist={blocklist}
                theme={theme}
              />
            </div>
          )}

          {/* TAB 4: BLOCKLIST */}
          {currentTab === 'blocklist' && (
            <div className="space-y-4">
              <BlocklistPanel
                blocklist={blocklist}
                onUnblock={handleUnblock}
                onManualBlock={(ip) => handleToggleIsolate(ip)}
                safetyMode={safetyMode}
                theme={theme}
              />
              <ResponseActionsTable
                actions={responseActions}
                blocklist={blocklist}
                safetyMode={safetyMode}
                onUnblock={handleUnblock}
                theme={theme}
              />
            </div>
          )}

          {/* TAB 5: PACKET INSPECTION */}
          {currentTab === 'traffic' && (
            <div className="space-y-4">
              <PacketTerminal
                packets={packets}
                onClear={() => setPackets([])}
                isPaused={isPacketStreamPaused}
                onTogglePause={() => setIsPacketStreamPaused(!isPacketStreamPaused)}
                theme={theme}
              />
            </div>
          )}

          {/* TAB 6: NETWORK TOPOLOGY */}
          {currentTab === 'topology' && (
            <div className="space-y-4">
              <TopologyPanel
                devices={devices}
                blocklist={blocklist}
                recentAlerts={alerts}
                onToggleIsolate={handleToggleIsolate}
                theme={theme}
              />
            </div>
          )}

          {/* TAB 7: RULES & THRESHOLDS */}
          {currentTab === 'settings' && (
            <div className="space-y-4">
              <SettingsPanel
                thresholds={thresholds}
                onSave={(newThresh) => setThresholds(newThresh)}
                safetyMode={safetyMode}
                onToggleSafety={() => setSafetyMode(!safetyMode)}
                ttsEnabled={ttsEnabled}
                onToggleTts={() => {
                  const next = !ttsEnabled;
                  speechEngine.setEnabled(next);
                  setTtsEnabled(next);
                }}
                adaptiveConfig={adaptiveConfig}
                onUpdateAdaptiveConfig={setAdaptiveConfig}
                theme={theme}
              />
            </div>
          )}

          {/* TAB 8: PYTHON CODE & RASPBERRY PI INTEGRATION */}
          {currentTab === 'python' && (
            <div className="space-y-4">
              <PythonProjectViewer theme={theme} />
            </div>
          )}

        </main>

      </div>

      {/* Attack Simulator Modal Drawer */}
      <AttackSimulatorDrawer
        isOpen={isAttackDrawerOpen}
        onClose={() => setIsAttackDrawerOpen(false)}
        devices={devices}
        onInject={handleInjectAttack}
        isInjecting={isInjecting}
        theme={theme}
      />

      {/* Browser Text-to-Speech (TTS) HUD Notification */}
      <VoiceAlertHUD theme={theme} />

    </div>
  );
}
