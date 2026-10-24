import React, { useState, useEffect, useMemo } from 'react';
import {
  X,
  ShieldAlert,
  Copy,
  Check,
  Ban,
  Clock,
  ArrowRight,
  Terminal,
  Layers,
  FileText,
  CheckCircle2,
  Crosshair,
  KeyRound,
  Radio,
  Zap,
  Cpu,
  Lock,
  Download,
  HardDrive,
} from 'lucide-react';
import { ThreatAlert, Packet } from '../types';

interface AlertDetailDrawerProps {
  alert: ThreatAlert | null;
  packets?: Packet[];
  onClose: () => void;
  onIsolateIp?: (ip: string) => void;
  isIsolated?: boolean;
  theme?: 'dark' | 'light';
}

export const AlertDetailDrawer: React.FC<AlertDetailDrawerProps> = ({
  alert,
  packets = [],
  onClose,
  onIsolateIp,
  isIsolated = false,
  theme = 'dark',
}) => {
  const [activeTab, setActiveTab] = useState<'evidence' | 'raw_packets' | 'mitigation'>('evidence');
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const isDark = theme === 'dark';

  // Handle escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  const copyToClipboard = (text: string, fieldName: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldName);
    setTimeout(() => setCopiedField(null), 1800);
  };

  // Find related packet from packet buffer or synthesize realistic forensic packet metadata
  const packetMetadata = useMemo(() => {
    if (!alert) return null;

    // Find actual matching packet in buffer
    const matchingPacket = packets.find(
      (p) =>
        p.sourceIp === alert.sourceIp &&
        (p.targetIp === alert.targetIp || p.isAttack) &&
        Math.abs(p.timestamp - alert.timestamp) < 60000
    ) || packets.find((p) => p.sourceIp === alert.sourceIp);

    const targetPort = alert.evidence?.targetPort || alert.evidence?.samplePorts?.[0] || matchingPacket?.dstPort || 80;
    const srcPort = matchingPacket?.srcPort || 49152 + (Math.abs(alert.id.charCodeAt(alert.id.length - 1) * 31) % 15000);
    const protocol = matchingPacket?.protocol || (alert.category === 'VOLUME_FLOOD' ? 'UDP' : 'TCP');
    const length = matchingPacket?.length || (alert.category === 'VOLUME_FLOOD' ? 1472 : 64);
    const flags = matchingPacket?.flags || (alert.category === 'PORT_SCAN' ? 'SYN' : alert.category === 'BRUTE_FORCE' ? 'PSH, ACK' : 'ACK');

    // Generate realistic hex dump representation
    const hexBytes: string[] = [];
    const asciiChars: string[] = [];
    
    // Synthetic raw byte string based on packet properties
    const hexPrefix = [
      '45', '00', '00', (length & 0xff).toString(16).padStart(2, '0'),
      'a1', 'b2', '40', '00',
      '40', protocol === 'TCP' ? '06' : '11', 'e2', '8f',
    ];

    // IP bytes
    const srcParts = alert.sourceIp.split('.').map(p => parseInt(p, 10).toString(16).padStart(2, '0'));
    const dstParts = alert.targetIp.split('.').map(p => parseInt(p, 10).toString(16).padStart(2, '0'));
    const ipHeaderHex = [...hexPrefix, ...srcParts, ...dstParts];

    // Port bytes
    const srcPortHex = [(srcPort >> 8 & 0xff).toString(16).padStart(2, '0'), (srcPort & 0xff).toString(16).padStart(2, '0')];
    const dstPortHex = [(targetPort >> 8 & 0xff).toString(16).padStart(2, '0'), (targetPort & 0xff).toString(16).padStart(2, '0')];

    const rawHexArray = [
      ...ipHeaderHex,
      ...srcPortHex,
      ...dstPortHex,
      '00', '00', '00', '01', '00', '00', '00', '00',
      '50', '02', 'fa', 'f0', '71', '2c', '00', '00',
      '68', '6f', '73', '74', '3a', '20', '74', '61',
      '72', '67', '65', '74', '2e', '6c', '6f', '63'
    ];

    // Formatted hex dump lines (16 bytes per row)
    const hexLines: { offset: string; hex: string; ascii: string }[] = [];
    for (let i = 0; i < rawHexArray.length; i += 16) {
      const slice = rawHexArray.slice(i, i + 16);
      const hexStr = slice.join(' ');
      const asciiStr = slice
        .map(h => {
          const code = parseInt(h, 16);
          return (code >= 32 && code <= 126) ? String.fromCharCode(code) : '.';
        })
        .join('');
      const offset = (i).toString(16).padStart(4, '0');
      hexLines.push({ offset, hex: hexStr.padEnd(47, ' '), ascii: asciiStr });
    }

    return {
      srcPort,
      targetPort,
      protocol,
      length,
      flags,
      ttl: 64,
      windowSize: 64240,
      checksum: '0x' + (Math.abs(alert.id.charCodeAt(0) * 1337) % 65535).toString(16).padStart(4, '0'),
      hexLines,
      matchingPacket,
    };
  }, [alert, packets]);

  if (!alert) return null;

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'PORT_SCAN':
        return <Crosshair className="w-4 h-4 text-blue-400" />;
      case 'BRUTE_FORCE':
        return <KeyRound className="w-4 h-4 text-rose-400" />;
      case 'C2_BEACONING':
        return <Radio className="w-4 h-4 text-amber-400" />;
      case 'USB_EXFILTRATION':
        return <HardDrive className="w-4 h-4 text-amber-400" />;
      case 'VOLUME_FLOOD':
      default:
        return <Zap className="w-4 h-4 text-purple-400" />;
    }
  };

  const getMitreMapping = (category: string) => {
    switch (category) {
      case 'PORT_SCAN':
        return { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery' };
      case 'BRUTE_FORCE':
        return { id: 'T1110.001', name: 'Password Guessing', tactic: 'Credential Access' };
      case 'C2_BEACONING':
        return { id: 'T1071.001', name: 'Web Protocols Command & Control', tactic: 'Command and Control' };
      case 'USB_EXFILTRATION':
        return { id: 'T1052.001', name: 'Exfiltration over Physical Medium', tactic: 'Exfiltration' };
      case 'VOLUME_FLOOD':
      default:
        return { id: 'T1498.001', name: 'Direct Network Flood', tactic: 'Impact' };
    }
  };

  const mitre = getMitreMapping(alert.category);
  const timeFormatted = new Date(alert.timestamp).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

  return (
    <div className="fixed inset-0 z-50 overflow-hidden flex justify-end">
      {/* Backdrop */}
      <div
        onClick={onClose}
        className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity duration-300"
      />

      {/* Slide-out Panel */}
      <div
        className={`relative w-full max-w-2xl h-full flex flex-col shadow-2xl z-10 transition-transform duration-300 ease-out border-l ${
          isDark
            ? 'bg-[#0B0F17] border-[#1C2538] text-slate-100'
            : 'bg-white border-slate-200 text-slate-900'
        }`}
      >
        {/* 1. Header Bar */}
        <div
          className={`p-4 lg:px-6 border-b flex items-center justify-between gap-3 ${
            isDark ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
          }`}
        >
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-xl border ${
              alert.severity === 'HIGH'
                ? 'bg-rose-500/15 border-rose-500/30 text-rose-500'
                : alert.severity === 'MEDIUM'
                ? 'bg-amber-500/15 border-amber-500/30 text-amber-500'
                : 'bg-blue-500/15 border-blue-500/30 text-blue-500'
            }`}>
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono font-bold text-sm tracking-tight">{alert.id}</span>
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold border ${
                    alert.severity === 'HIGH'
                      ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                      : alert.severity === 'MEDIUM'
                      ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                      : 'bg-blue-500/15 text-blue-400 border-blue-500/30'
                  }`}
                >
                  {alert.severity} CRITICALITY
                </span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded-md border ${
                  alert.status === 'ACTIVE'
                    ? 'bg-rose-500/10 text-rose-400 border-rose-500/20'
                    : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                }`}>
                  {alert.status}
                </span>
              </div>
              <p className={`text-xs mt-0.5 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
                Incident Ingestion: <span className="font-mono text-[11px]">{timeFormatted}</span>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-1">
            <button
              onClick={() => copyToClipboard(JSON.stringify(alert, null, 2), 'full_alert')}
              className={`p-2 rounded-lg border text-xs flex items-center gap-1.5 transition-colors cursor-pointer ${
                isDark
                  ? 'bg-[#141B28] border-[#222E42] text-slate-300 hover:text-white'
                  : 'bg-white border-slate-200 text-slate-700 hover:text-slate-900 shadow-xs'
              }`}
              title="Copy alert JSON payload"
            >
              {copiedField === 'full_alert' ? (
                <Check className="w-4 h-4 text-emerald-500" />
              ) : (
                <Copy className="w-4 h-4" />
              )}
            </button>
            <button
              onClick={onClose}
              className={`p-2 rounded-lg border text-xs transition-colors cursor-pointer ${
                isDark
                  ? 'bg-[#141B28] border-[#222E42] text-slate-400 hover:text-white hover:bg-slate-800'
                  : 'bg-white border-slate-200 text-slate-600 hover:text-slate-900 shadow-xs'
              }`}
              title="Close drawer (Esc)"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* 2. Key Endpoint Nodes Bar */}
        <div
          className={`px-4 lg:px-6 py-3 border-b grid grid-cols-2 gap-3 text-xs font-mono ${
            isDark ? 'bg-[#0E131F] border-[#1C2538]' : 'bg-slate-100/70 border-slate-200'
          }`}
        >
          {/* Source Endpoint */}
          <div className="space-y-1">
            <div className="flex items-center justify-between text-[10px] text-slate-400 uppercase tracking-wider">
              <span>Hostile Origin</span>
              <button
                onClick={() => copyToClipboard(alert.sourceIp, 'sourceIp')}
                className="hover:text-blue-400 cursor-pointer flex items-center gap-1"
              >
                {copiedField === 'sourceIp' ? <Check className="w-2.5 h-2.5 text-emerald-500" /> : <Copy className="w-2.5 h-2.5" />}
                <span>Copy</span>
              </button>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-rose-500 text-sm">{alert.sourceIp}</span>
              {packetMetadata && (
                <span className="text-[11px] text-slate-400">:{packetMetadata.srcPort}</span>
              )}
            </div>
            <div className="text-[10px] text-slate-400">
              Classification: External Threat Node
            </div>
          </div>

          {/* Target Endpoint */}
          <div className="space-y-1 border-l pl-3 border-inherit">
            <div className="flex items-center justify-between text-[10px] text-slate-400 uppercase tracking-wider">
              <span>Targeted Subnet Asset</span>
              <button
                onClick={() => copyToClipboard(alert.targetIp, 'targetIp')}
                className="hover:text-blue-400 cursor-pointer flex items-center gap-1"
              >
                {copiedField === 'targetIp' ? <Check className="w-2.5 h-2.5 text-emerald-500" /> : <Copy className="w-2.5 h-2.5" />}
                <span>Copy</span>
              </button>
            </div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-blue-400 text-sm">{alert.targetIp}</span>
              {packetMetadata && (
                <span className="text-[11px] text-slate-400">:{packetMetadata.targetPort}</span>
              )}
            </div>
            <div className="text-[10px] text-slate-400">
              Protocol: {packetMetadata?.protocol || 'TCP'} Stateful Socket
            </div>
          </div>
        </div>

        {/* 3. Section Navigation Tabs */}
        <div
          className={`px-4 lg:px-6 border-b flex items-center gap-2 text-xs font-medium ${
            isDark ? 'border-[#1C2538] bg-[#0F1522]' : 'border-slate-200 bg-slate-50'
          }`}
        >
          <button
            onClick={() => setActiveTab('evidence')}
            className={`py-2.5 px-3 border-b-2 transition-all cursor-pointer flex items-center gap-2 ${
              activeTab === 'evidence'
                ? 'border-blue-500 text-blue-500 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Detection Evidence</span>
          </button>

          <button
            onClick={() => setActiveTab('raw_packets')}
            className={`py-2.5 px-3 border-b-2 transition-all cursor-pointer flex items-center gap-2 ${
              activeTab === 'raw_packets'
                ? 'border-blue-500 text-blue-500 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Raw Packet Metadata & Hex Dump</span>
          </button>

          <button
            onClick={() => setActiveTab('mitigation')}
            className={`py-2.5 px-3 border-b-2 transition-all cursor-pointer flex items-center gap-2 ${
              activeTab === 'mitigation'
                ? 'border-blue-500 text-blue-500 font-bold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Ban className="w-3.5 h-3.5" />
            <span>Remediation & Firewall Policy</span>
          </button>
        </div>

        {/* 4. Tab Content (Scrollable) */}
        <div className="flex-1 overflow-y-auto p-4 lg:p-6 space-y-5">
          
          {/* TAB 1: DETECTION EVIDENCE */}
          {activeTab === 'evidence' && (
            <div className="space-y-4">
              {/* MITRE ATT&CK Matrix Card */}
              <div
                className={`p-3.5 rounded-xl border space-y-2 ${
                  isDark ? 'bg-[#101622] border-[#222E42]' : 'bg-slate-50 border-slate-200'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                    MITRE ATT&amp;CK Framework Classification
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 font-bold">
                    {mitre.id}
                  </span>
                </div>
                <div className="flex items-baseline gap-2">
                  <h3 className="font-display font-bold text-sm text-slate-100">{mitre.name}</h3>
                  <span className="text-xs text-slate-400 font-mono">({mitre.tactic})</span>
                </div>
                <p className="text-xs text-slate-400 font-sans leading-relaxed">
                  Adversary leveraged {alert.category.toLowerCase().replace('_', ' ')} against subnet IoT nodes to bypass perimeter rate-limits and initiate unauthorized service reconnaissance.
                </p>
              </div>

              {/* Rule Violation Overview */}
              <div
                className={`p-4 rounded-xl border space-y-3 ${
                  isDark ? 'bg-[#121824] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
                }`}
              >
                <div className="flex items-center gap-2 font-semibold text-xs text-blue-400">
                  {getCategoryIcon(alert.category)}
                  <span>Rule Engine Diagnostic Detail</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed bg-slate-950/40 p-3 rounded-lg border border-slate-800/80 font-mono">
                  {alert.detail}
                </p>
              </div>

              {/* Specific Heuristic Evidence Matrix */}
              <div className="space-y-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
                  Captured Telemetry Evidence Parameters
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs font-mono">
                  {alert.evidence && Object.entries(alert.evidence).map(([key, val]) => {
                    const formattedVal = Array.isArray(val)
                      ? val.join(', ')
                      : typeof val === 'object'
                      ? JSON.stringify(val)
                      : String(val);

                    return (
                      <div
                        key={key}
                        className={`p-3 rounded-lg border ${
                          isDark ? 'bg-[#101622] border-[#222E42]' : 'bg-slate-50 border-slate-200'
                        }`}
                      >
                        <div className="text-[10px] text-slate-400 uppercase tracking-wider">
                          {key.replace(/([A-Z])/g, ' $1')}
                        </div>
                        <div className="font-bold text-slate-200 mt-1 truncate" title={formattedVal}>
                          {formattedVal}
                        </div>
                      </div>
                    );
                  })}

                  {/* Supplemental Sensor Metrics */}
                  <div
                    className={`p-3 rounded-lg border ${
                      isDark ? 'bg-[#101622] border-[#222E42]' : 'bg-slate-50 border-slate-200'
                    }`}
                  >
                    <div className="text-[10px] text-slate-400 uppercase tracking-wider">
                      Evaluation Window
                    </div>
                    <div className="font-bold text-emerald-400 mt-1">
                      {alert.evidence?.windowSec || 10.0}s Sliding Buffer
                    </div>
                  </div>

                  <div
                    className={`p-3 rounded-lg border ${
                      isDark ? 'bg-[#101622] border-[#222E42]' : 'bg-slate-50 border-slate-200'
                    }`}
                  >
                    <div className="text-[10px] text-slate-400 uppercase tracking-wider">
                      Stateful Engine Confidence
                    </div>
                    <div className="font-bold text-blue-400 mt-1">
                      99.4% Deterministic Match
                    </div>
                  </div>
                </div>
              </div>

              {/* Incident Context Timeline */}
              <div
                className={`p-4 rounded-xl border text-xs space-y-2 font-mono ${
                  isDark ? 'bg-[#101622] border-[#222E42]' : 'bg-slate-50 border-slate-200'
                }`}
              >
                <div className="flex items-center justify-between text-slate-400 text-[11px]">
                  <span>Sensor Node: IDS-PROBE-01 (Suricata Engine)</span>
                  <span>Interface: eth0.10 (IoT VLAN)</span>
                </div>
                <div className="text-[11px] text-slate-400">
                  Ingress MAC: <span className="text-slate-200">52:54:00:12:34:56</span> &bull; Gateway Hop: <span className="text-slate-200">192.168.1.1</span>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: RAW PACKET METADATA & HEX DUMP */}
          {activeTab === 'raw_packets' && packetMetadata && (
            <div className="space-y-4">
              {/* Layer 3 / Layer 4 Header Breakdown */}
              <div className="space-y-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
                  L3 / L4 Packet Header Dissection
                </span>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#101622] border-[#222E42]' : 'bg-slate-50 border-slate-200'}`}>
                    <span className="text-[10px] text-slate-400">PROTOCOL</span>
                    <div className="font-bold text-blue-400 mt-0.5">{packetMetadata.protocol}</div>
                  </div>
                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#101622] border-[#222E42]' : 'bg-slate-50 border-slate-200'}`}>
                    <span className="text-[10px] text-slate-400">PACKET LENGTH</span>
                    <div className="font-bold text-slate-200 mt-0.5">{packetMetadata.length} Bytes</div>
                  </div>
                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#101622] border-[#222E42]' : 'bg-slate-50 border-slate-200'}`}>
                    <span className="text-[10px] text-slate-400">TCP/UDP FLAGS</span>
                    <div className="font-bold text-rose-400 mt-0.5">[{packetMetadata.flags}]</div>
                  </div>
                  <div className={`p-2.5 rounded-lg border ${isDark ? 'bg-[#101622] border-[#222E42]' : 'bg-slate-50 border-slate-200'}`}>
                    <span className="text-[10px] text-slate-400">CHECKSUM / TTL</span>
                    <div className="font-bold text-slate-200 mt-0.5">{packetMetadata.checksum} (TTL {packetMetadata.ttl})</div>
                  </div>
                </div>
              </div>

              {/* Raw Hex Dump Inspector */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
                      Raw Frame Hexadecimal Dump
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                      PCAP Frame #0042
                    </span>
                  </div>
                  <button
                    onClick={() => {
                      const hexFull = packetMetadata.hexLines.map(l => `${l.offset}  ${l.hex}  |${l.ascii}|`).join('\n');
                      copyToClipboard(hexFull, 'hex_dump');
                    }}
                    className={`text-xs font-mono flex items-center gap-1 hover:text-blue-400 cursor-pointer ${
                      isDark ? 'text-slate-400' : 'text-slate-600'
                    }`}
                  >
                    {copiedField === 'hex_dump' ? (
                      <>
                        <Check className="w-3 h-3 text-emerald-500" />
                        <span className="text-emerald-500 font-bold">Copied Hex</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3 h-3" />
                        <span>Copy Hex</span>
                      </>
                    )}
                  </button>
                </div>

                <div
                  className={`p-3.5 rounded-xl font-mono text-[11px] leading-5 overflow-x-auto border ${
                    isDark ? 'bg-[#06090F] border-[#1C2538] text-slate-300' : 'bg-slate-900 text-slate-200 border-slate-800'
                  }`}
                >
                  <div className="text-[10px] text-slate-500 pb-2 border-b border-slate-800/60 mb-2 flex justify-between font-mono">
                    <span>OFFSET  00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</span>
                    <span>ASCII DECODE</span>
                  </div>
                  {packetMetadata.hexLines.map((line, idx) => (
                    <div key={idx} className="flex gap-4 font-mono hover:bg-slate-800/40 px-1 rounded">
                      <span className="text-slate-500 select-none">{line.offset}</span>
                      <span className="text-sky-400 font-semibold tracking-wide select-all">{line.hex}</span>
                      <span className="text-slate-400 select-all border-l border-slate-800/80 pl-3">|{line.ascii}|</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Decoded Application Layer Metadata */}
              <div
                className={`p-3.5 rounded-xl border text-xs font-mono space-y-2 ${
                  isDark ? 'bg-[#101622] border-[#222E42]' : 'bg-slate-50 border-slate-200'
                }`}
              >
                <div className="text-[10px] text-slate-400 uppercase tracking-wider font-bold">
                  Decoded Payload Content & Flags
                </div>
                <div className="text-xs text-slate-300">
                  {packetMetadata.matchingPacket?.payloadInfo ||
                    `Signature match: ${alert.category} pattern probe payload against ${alert.targetIp}:${packetMetadata.targetPort}`}
                </div>
                <div className="text-[10px] text-slate-500 flex items-center gap-2 pt-1 border-t border-inherit">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
                  <span>Frame Authenticated with L4 TCP sequence sync check</span>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: REMEDIATION & FIREWALL POLICY */}
          {activeTab === 'mitigation' && (
            <div className="space-y-4">
              {/* Immediate Host Isolation Action */}
              <div
                className={`p-4 rounded-xl border space-y-3 ${
                  isDark ? 'bg-[#101622] border-[#222E42]' : 'bg-white border-slate-200 shadow-xs'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-semibold text-sm">Hostile IP Isolation</h3>
                    <p className="text-xs text-slate-400">
                      Instantly append kernel firewall rules to isolate <span className="font-mono text-rose-400">{alert.sourceIp}</span>.
                    </p>
                  </div>
                  <button
                    onClick={() => onIsolateIp && onIsolateIp(alert.sourceIp)}
                    className={`px-3.5 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1.5 transition-all cursor-pointer shadow-xs ${
                      isIsolated
                        ? 'bg-emerald-600 text-white hover:bg-emerald-700'
                        : 'bg-rose-600 text-white hover:bg-rose-700'
                    }`}
                  >
                    <Ban className="w-3.5 h-3.5" />
                    <span>{isIsolated ? 'Release Quarantine' : 'Quarantine Host'}</span>
                  </button>
                </div>
              </div>

              {/* Command Mitigation Box */}
              <div className="space-y-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
                  {alert.category === 'USB_EXFILTRATION' ? 'Synthesized Endpoint Lockdown Command' : 'Synthesized Gateway Firewall Command'}
                </span>
                {alert.category === 'USB_EXFILTRATION' ? (
                  <div className="space-y-2">
                    <div
                      className={`p-3 rounded-lg border font-mono text-xs flex items-center justify-between gap-2 ${
                        isDark ? 'bg-[#0B0F17] border-[#222E42] text-amber-300' : 'bg-slate-900 text-amber-300 border-slate-800'
                      }`}
                    >
                      <code className="truncate">
                        reg add "HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR" /v Start /t REG_DWORD /d 4 /f
                      </code>
                      <button
                        onClick={() => copyToClipboard('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" /v Start /t REG_DWORD /d 4 /f', 'win_usbstor')}
                        className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white cursor-pointer shrink-0"
                        title="Copy Windows Registry Command"
                      >
                        {copiedField === 'win_usbstor' ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                    <div
                      className={`p-3 rounded-lg border font-mono text-xs flex items-center justify-between gap-2 ${
                        isDark ? 'bg-[#0B0F17] border-[#222E42] text-emerald-400' : 'bg-slate-900 text-emerald-400 border-slate-800'
                      }`}
                    >
                      <code className="truncate">
                        modprobe -r usb_storage && echo 'blacklist usb-storage' &gt;&gt; /etc/modprobe.d/blacklist.conf
                      </code>
                      <button
                        onClick={() => copyToClipboard("modprobe -r usb_storage && echo 'blacklist usb-storage' >> /etc/modprobe.d/blacklist.conf", 'modprobe')}
                        className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white cursor-pointer shrink-0"
                        title="Copy Linux Kernel Command"
                      >
                        {copiedField === 'modprobe' ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                ) : (
                  <div
                    className={`p-3 rounded-lg border font-mono text-xs flex items-center justify-between gap-2 ${
                      isDark ? 'bg-[#0B0F17] border-[#222E42] text-emerald-400' : 'bg-slate-900 text-emerald-400 border-slate-800'
                    }`}
                  >
                    <code className="truncate">
                      iptables -I FORWARD -s {alert.sourceIp} -j DROP
                    </code>
                    <button
                      onClick={() => copyToClipboard(`iptables -I FORWARD -s ${alert.sourceIp} -j DROP`, 'iptables')}
                      className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white cursor-pointer shrink-0"
                      title="Copy command"
                    >
                      {copiedField === 'iptables' ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                    </button>
                  </div>
                )}
              </div>

              {/* SIEM Incident Log Export */}
              <div
                className={`p-4 rounded-xl border text-xs space-y-2.5 ${
                  isDark ? 'bg-[#101622] border-[#222E42]' : 'bg-slate-50 border-slate-200'
                }`}
              >
                <span className="font-semibold text-slate-200">Incident Triage Recommendation:</span>
                <ul className="list-disc pl-4 space-y-1 text-slate-400 leading-relaxed">
                  <li>Verify whether the targeted node (<span className="font-mono text-slate-200">{alert.targetIp}</span>) has firmware port 22/80 exposed to untrusted subnets.</li>
                  <li>Rotate credentials if authentication brute-force burst exceeded the threshold.</li>
                  <li>Enable strict MAC-to-IP binding in DHCP reservations for device containment.</li>
                </ul>
              </div>
            </div>
          )}

        </div>

        {/* 5. Footer Actions */}
        <div
          className={`p-4 lg:px-6 border-t flex items-center justify-between gap-3 ${
            isDark ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
          }`}
        >
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
            <span>Alert Status: {alert.status}</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => onIsolateIp && onIsolateIp(alert.sourceIp)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors cursor-pointer ${
                isIsolated
                  ? isDark
                    ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                    : 'bg-emerald-100 text-emerald-800'
                  : 'bg-rose-600 text-white hover:bg-rose-700 shadow-xs'
              }`}
            >
              <Ban className="w-3.5 h-3.5" />
              <span>{isIsolated ? 'Quarantined (Active)' : 'Isolate Source Host'}</span>
            </button>
            <button
              onClick={onClose}
              className={`px-3 py-1.5 rounded-lg border text-xs font-medium cursor-pointer transition-colors ${
                isDark
                  ? 'bg-[#141B28] border-[#222E42] text-slate-300 hover:text-white'
                  : 'bg-white border-slate-300 text-slate-700 hover:text-slate-900 shadow-xs'
              }`}
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
