export type ProtocolType = 'TCP' | 'UDP' | 'HTTP' | 'HTTPS' | 'MQTT' | 'CoAP' | 'USB';
export type DeviceStatus = 'ONLINE' | 'SUSPECT' | 'QUARANTINED';
export type AlertCategory = 'PORT_SCAN' | 'BRUTE_FORCE' | 'C2_BEACONING' | 'VOLUME_FLOOD' | 'USB_EXFILTRATION';
export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH';
export type ActionType = 'ISOLATE' | 'MONITOR';

export interface IoTDevice {
  id: string;
  name: string;
  ip: string;
  mac: string;
  deviceType: string;
  normalDestinations: string[];
  normalPorts: number[];
  normalProtocols: ProtocolType[];
  status: DeviceStatus;
  packetsSent: number;
  packetsReceived: number;
  bytesTotal: number;
  lastSeen: number;
  compromised?: boolean;
}

export interface Packet {
  id: string;
  timestamp: number;
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  protocol: ProtocolType;
  length: number;
  flags: string;
  authSuccess?: boolean | null;
  payloadInfo: string;
  isAttack?: boolean;
  attackType?: AlertCategory | null;
}

export interface AlertEvidence {
  [key: string]: any;
}

export interface ThreatAlert {
  id: string;
  timestamp: number;
  category: AlertCategory;
  severity: SeverityLevel;
  sourceIp: string;
  targetIp: string;
  detail: string;
  evidence: AlertEvidence;
  status: 'ACTIVE' | 'RESOLVED' | 'SUPPRESSED';
}

export interface ResponseAction {
  id: string;
  timestamp: number;
  alertId: string;
  targetIp: string;
  category: AlertCategory;
  action: ActionType;
  reason: string;
  iptablesCommand: string;
  windowsCommand: string;
  executedLive: boolean;
  status: 'ACTIVE_BLOCK' | 'MONITORING' | 'REVERTED';
}

export interface DetectionThresholds {
  portScanUniquePorts: number;
  portScanWindowSec: number;
  bruteForceFailures: number;
  bruteForceWindowSec: number;
  beaconingMinPackets: number;
  beaconingMaxJitterSec: number;
  beaconingWindowSec: number;
  volumeFloodBytes: number;
  volumeFloodWindowSec: number;
  usbExfiltrationBytes: number;
  usbExfiltrationWindowSec: number;
}

export type OperationalRegime = 'PEAK_HOURS' | 'OFF_PEAK' | 'MAINTENANCE_WINDOW';

export interface AdaptiveBaselineConfig {
  enabled: boolean;
  maintenanceStartHour: number; // e.g. 2 (02:00)
  maintenanceEndHour: number;   // e.g. 5 (05:00)
  maintenanceFactor: number;    // e.g. 2.2x
  offpeakFactor: number;        // e.g. 1.3x
  mode: 'AUTO_CLOCK' | 'MANUAL_SIMULATED';
  simulatedHour: number;        // 0.0 - 23.99
  autoSuppressMaintenanceSpikes: boolean;
}

export interface SuppressedFalsePositive {
  id: string;
  timestamp: number;
  category: AlertCategory;
  sourceIp: string;
  targetIp: string;
  rawMetric: number;
  metricUnit: string;
  staticThreshold: number;
  adaptiveThreshold: number;
  regime: OperationalRegime;
  multiplier: number;
  reason: string;
  preventedAction: string;
}

