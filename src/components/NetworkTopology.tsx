import React, { useState } from 'react';
import { Shield, ShieldAlert, Wifi, Server, Laptop, Lock, Camera, Plug, Thermometer, Cpu, Globe, ArrowRight, Ban } from 'lucide-react';
import { IoTDevice, ThreatAlert } from '../types';

interface NetworkTopologyProps {
  devices: IoTDevice[];
  blocklist: string[];
  recentAlerts: ThreatAlert[];
  onToggleIsolate: (ip: string) => void;
}

export const NetworkTopology: React.FC<NetworkTopologyProps> = ({
  devices,
  blocklist,
  recentAlerts,
  onToggleIsolate,
}) => {
  const [selectedNode, setSelectedNode] = useState<any | null>(null);

  const isQuarantined = (ip: string) => blocklist.includes(ip);

  // Check if a node was involved in a recent high alert
  const hasRecentAlert = (ip: string) => {
    return recentAlerts.some((a) => a.sourceIp === ip || a.targetIp === ip);
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <div className="flex items-center justify-between pb-3.5 mb-6 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <Wifi className="w-4 h-4 text-blue-400" />
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Network Topology &amp; Traffic Flow Map
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Visual map of external hosts, the hardening gateway (192.168.1.1), and monitored local IoT devices.
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs text-slate-400">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span> Normal Flow
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span> Threat Injected
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-900 border border-rose-500"></span> Quarantined / Dropped
          </span>
        </div>
      </div>

      {/* Visual Diagram */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
        
        {/* Left Column: External Hosts / Internet */}
        <div className="lg:col-span-3 space-y-3">
          <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <Globe className="w-3.5 h-3.5 text-slate-400" />
            <span>External Internet (WAN)</span>
          </div>

          {/* Attacker Node */}
          <div
            onClick={() => setSelectedNode({
              name: 'External Adversary (Scanner/Brute Force)',
              ip: '198.51.100.42',
              type: 'Threat Actor',
              desc: 'Origin IP for rapid port scanning and credential brute force attacks.',
              blocked: isQuarantined('198.51.100.42'),
            })}
            className={`p-3 rounded-lg border transition-all cursor-pointer ${
              isQuarantined('198.51.100.42')
                ? 'bg-rose-950/40 border-rose-600 text-rose-300'
                : 'bg-slate-800/80 border-slate-700 hover:border-slate-500 text-slate-200'
            }`}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Laptop className="w-4 h-4 text-rose-400" />
                <div>
                  <div className="text-xs font-bold">Attacker Source</div>
                  <div className="font-mono text-[11px] text-slate-400">198.51.100.42</div>
                </div>
              </div>
              {isQuarantined('198.51.100.42') ? (
                <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                  BLOCKED
                </span>
              ) : (
                <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-amber-500/20 text-amber-400">
                  ACTIVE
                </span>
              )}
            </div>
          </div>

          {/* C2 Server Node */}
          <div
            onClick={() => setSelectedNode({
              name: 'Command & Control (C2) Server',
              ip: '203.0.113.88',
              type: 'C2 Malicious Host',
              desc: 'Target endpoint receiving low-jitter beacon pulses from compromised IoT hardware.',
              blocked: isQuarantined('203.0.113.88'),
            })}
            className="p-3 rounded-lg border bg-slate-800/80 border-slate-700 hover:border-slate-500 text-slate-200 cursor-pointer transition-all"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-amber-400" />
                <div>
                  <div className="text-xs font-bold">Malicious C2 Server</div>
                  <div className="font-mono text-[11px] text-slate-400">203.0.113.88:8443</div>
                </div>
              </div>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-purple-500/20 text-purple-300">
                LISTENER
              </span>
            </div>
          </div>

          {/* Legitimate Cloud Hosts */}
          <div
            onClick={() => setSelectedNode({
              name: 'Legitimate Cloud Services',
              ip: '52.14.99.102 / 34.210.45.88',
              type: 'Legitimate SaaS',
              desc: 'Cloud NVR Video Ingestion, Home Assistant & Weather API endpoints.',
              blocked: false,
            })}
            className="p-3 rounded-lg border bg-slate-800/40 border-slate-700/60 text-slate-300 cursor-pointer hover:border-slate-600 transition-all"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-blue-400" />
                <div>
                  <div className="text-xs font-medium">Legitimate Cloud APIs</div>
                  <div className="font-mono text-[11px] text-slate-500">NVR / MQTT Broker</div>
                </div>
              </div>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-emerald-500/10 text-emerald-400">
                ALLOWED
              </span>
            </div>
          </div>
        </div>

        {/* Center Column: Security Gateway */}
        <div className="lg:col-span-4 flex flex-col items-center justify-center p-4">
          <div className="w-full max-w-xs bg-slate-950 border-2 border-blue-500/40 rounded-2xl p-5 text-center shadow-xl shadow-blue-500/5 relative">
            <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-0.5 bg-blue-600 rounded-full text-[10px] font-bold text-white uppercase tracking-wider shadow">
              Core Inspection Engine
            </div>

            <div className="w-14 h-14 mx-auto rounded-xl bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400 mb-3 mt-1">
              <Shield className="w-8 h-8" />
            </div>

            <h3 className="text-sm font-bold text-white">Hardening Security Gateway</h3>
            <div className="font-mono text-xs text-blue-400 mt-0.5">192.168.1.1</div>

            <div className="mt-4 pt-3 border-t border-slate-800 text-left space-y-1.5 text-[11px]">
              <div className="flex justify-between text-slate-400">
                <span>Active Blocked Rules:</span>
                <span className="font-mono font-bold text-rose-400">{blocklist.length} IPs</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Inspection Chains:</span>
                <span className="font-mono text-slate-200">FORWARD, INPUT</span>
              </div>
              <div className="flex justify-between text-slate-400">
                <span>Subnet Managed:</span>
                <span className="font-mono text-emerald-400">5 IoT Devices</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: 5 Local IoT Devices */}
        <div className="lg:col-span-5 space-y-2.5">
          <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
            <Wifi className="w-3.5 h-3.5 text-slate-400" />
            <span>Local IoT Subnet (192.168.1.0/24)</span>
          </div>

          {devices.map((dev) => {
            const blocked = isQuarantined(dev.ip);
            const alertTriggered = hasRecentAlert(dev.ip);
            return (
              <div
                key={dev.id}
                onClick={() => setSelectedNode({
                  name: dev.name,
                  ip: dev.ip,
                  mac: dev.mac,
                  type: dev.deviceType,
                  desc: `Monitored node. Protocols: ${dev.normalProtocols.join(', ')}. Normal ports: ${dev.normalPorts.join(', ')}.`,
                  blocked: blocked,
                })}
                className={`p-3 rounded-lg border transition-all cursor-pointer ${
                  blocked
                    ? 'bg-rose-950/40 border-rose-600/80 text-rose-200'
                    : alertTriggered
                    ? 'bg-amber-950/30 border-amber-500/70 text-amber-200'
                    : 'bg-slate-800/80 border-slate-700/80 hover:border-slate-500 text-slate-200'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <div className="w-7 h-7 rounded bg-slate-900 border border-slate-700 flex items-center justify-center shrink-0">
                      {dev.deviceType === 'Security Camera' && <Camera className="w-3.5 h-3.5 text-blue-400" />}
                      {dev.deviceType === 'Access Control' && <Lock className="w-3.5 h-3.5 text-amber-400" />}
                      {dev.deviceType === 'Environment Sensor' && <Thermometer className="w-3.5 h-3.5 text-emerald-400" />}
                      {dev.deviceType === 'Power Controller' && <Plug className="w-3.5 h-3.5 text-purple-400" />}
                      {dev.deviceType === 'Climate Control' && <Cpu className="w-3.5 h-3.5 text-cyan-400" />}
                    </div>
                    <div>
                      <div className="text-xs font-semibold">{dev.name}</div>
                      <div className="font-mono text-[11px] text-slate-400">{dev.ip}</div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {blocked ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40 flex items-center gap-1">
                        <Ban className="w-2.5 h-2.5 text-rose-400" />
                        <span>ISOLATED</span>
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        MONITORED
                      </span>
                    )}

                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        onToggleIsolate(dev.ip);
                      }}
                      className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-900 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
                    >
                      {blocked ? 'Lift' : 'Isolate'}
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

      </div>

      {/* Selected Node Details Drawer */}
      {selectedNode && (
        <div className="mt-6 p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <h4 className="text-xs font-bold text-white uppercase tracking-wider">{selectedNode.name}</h4>
              <span className="font-mono text-xs text-blue-400">({selectedNode.ip})</span>
              {selectedNode.blocked && (
                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400">
                  DROPPED IN IPTABLES
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-1">{selectedNode.desc}</p>
          </div>
          <button
            onClick={() => setSelectedNode(null)}
            className="text-xs text-slate-500 hover:text-slate-300 cursor-pointer"
          >
            Close Details
          </button>
        </div>
      )}
    </div>
  );
};
