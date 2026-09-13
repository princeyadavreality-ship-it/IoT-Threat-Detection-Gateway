import React, { useState } from 'react';
import { Radio, Server, Laptop, Lock, Camera, Plug, Thermometer, Cpu, Globe, Ban, ShieldCheck, Shield, Network } from 'lucide-react';
import { IoTDevice, ThreatAlert } from '../types';

interface TopologyPanelProps {
  devices: IoTDevice[];
  blocklist: string[];
  recentAlerts: ThreatAlert[];
  onToggleIsolate: (ip: string) => void;
  theme?: 'dark' | 'light';
}

export const TopologyPanel: React.FC<TopologyPanelProps> = ({
  devices,
  blocklist,
  recentAlerts,
  onToggleIsolate,
  theme = 'dark',
}) => {
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const isDark = theme === 'dark';

  const isQuarantined = (ip: string) => blocklist.includes(ip);
  const hasAlert = (ip: string) => recentAlerts.some((a) => a.sourceIp === ip || a.targetIp === ip);

  return (
    <div className={`border rounded-xl p-4 lg:p-5 space-y-4 transition-colors ${
      isDark ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
    }`}>
      
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-inherit gap-3">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-blue-500/10 text-blue-500">
            <Network className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-display font-bold text-sm">Network Topology &amp; Ingress Boundary</span>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold border ${
                isDark ? 'bg-slate-800 text-blue-400 border-slate-700' : 'bg-blue-50 text-blue-700 border-blue-200'
              }`}>
                Subnet 192.168.1.0/24
              </span>
            </div>
            <div className="text-xs text-slate-400 mt-0.5">
              WAN Ingress &bull; Physical Gateway eth0 &bull; Isolated IoT VLAN 10
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs font-mono">
          <span className="flex items-center gap-1.5 text-emerald-500 font-medium">
            <span className="w-2 h-2 rounded-full bg-emerald-500"></span> Permitted
          </span>
          <span className="flex items-center gap-1.5 text-rose-500 font-medium">
            <span className="w-2 h-2 rounded-full bg-rose-500"></span> Quarantined Drop
          </span>
        </div>
      </div>

      {/* Topology 3-Column Visual Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-stretch font-mono">
        
        {/* WAN Ingress Zone */}
        <div className={`lg:col-span-4 border p-4 rounded-xl space-y-3 ${
          isDark ? 'bg-[#121824] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
        }`}>
          <div className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center justify-between border-b border-inherit pb-2">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-blue-500" />
              <span>External WAN Ingress</span>
            </div>
            <span className="text-[10px]">Untrusted Zone</span>
          </div>

          {/* Adversary Scanner */}
          <div 
            onClick={() => setSelectedIp('198.51.100.42')}
            className={`p-3 rounded-lg border cursor-pointer transition-all ${
              isQuarantined('198.51.100.42')
                ? isDark
                  ? 'bg-rose-500/10 border-rose-500/40 text-rose-300'
                  : 'bg-rose-50 border-rose-200 text-rose-800'
                : isDark
                  ? 'bg-[#151D2C] border-[#222E42] hover:border-blue-500/50'
                  : 'bg-white border-slate-200 hover:border-blue-300 shadow-xs'
            }`}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <Laptop className="w-4 h-4 text-rose-500" />
                <div>
                  <div className="font-bold text-xs">Adversary Scanner</div>
                  <div className="text-[11px] text-slate-400">198.51.100.42</div>
                </div>
              </div>
              <span className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase border ${
                isQuarantined('198.51.100.42')
                  ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
                  : 'bg-amber-500/20 text-amber-400 border-amber-500/30'
              }`}>
                {isQuarantined('198.51.100.42') ? 'DROPPED' : 'UNTRUSTED'}
              </span>
            </div>
          </div>

          {/* C2 Malicious Server */}
          <div 
            onClick={() => setSelectedIp('203.0.113.88')}
            className={`p-3 rounded-lg border cursor-pointer transition-all ${
              isDark
                ? 'bg-[#151D2C] border-[#222E42] hover:border-blue-500/50'
                : 'bg-white border-slate-200 hover:border-blue-300 shadow-xs'
            }`}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <Server className="w-4 h-4 text-amber-500" />
                <div>
                  <div className="font-bold text-xs">C2 Endpoint Host</div>
                  <div className="text-[11px] text-slate-400">203.0.113.88:8443</div>
                </div>
              </div>
              <span className="px-2 py-0.5 text-[10px] font-medium rounded border border-slate-600/40 text-slate-400">
                WAN
              </span>
            </div>
          </div>

          {/* Legitimate Cloud Endpoint */}
          <div className={`p-3 rounded-lg border ${
            isDark ? 'bg-[#151D2C] border-[#222E42]' : 'bg-white border-slate-200 shadow-xs'
          }`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <Globe className="w-4 h-4 text-emerald-500" />
                <div>
                  <div className="font-bold text-xs">Authorized Cloud Broker</div>
                  <div className="text-[11px] text-slate-400">52.14.99.102:8883</div>
                </div>
              </div>
              <span className={`px-2 py-0.5 text-[10px] font-semibold rounded border ${
                isDark 
                  ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' 
                  : 'bg-emerald-50 text-emerald-700 border-emerald-200'
              }`}>
                PERMITTED
              </span>
            </div>
          </div>
        </div>

        {/* Security Gateway Central Node */}
        <div className={`lg:col-span-4 border p-4 lg:p-5 rounded-xl flex flex-col justify-between relative overflow-hidden ${
          isDark ? 'bg-[#141B28] border-[#222E42]' : 'bg-slate-100 border-slate-300'
        }`}>
          <div>
            <div className="flex items-center justify-between border-b border-inherit pb-2 text-xs text-blue-500 font-bold">
              <span>SECURITY GATEWAY</span>
              <span>192.168.1.1</span>
            </div>

            <div className="py-8 text-center">
              <div className="w-14 h-14 mx-auto rounded-xl bg-blue-500/10 text-blue-500 border border-blue-500/20 flex items-center justify-center mb-3">
                <ShieldCheck className="w-8 h-8" />
              </div>
              <div className="text-base font-bold font-display tracking-tight">
                Linux Kernel Intercept Engine
              </div>
              <div className="text-xs text-slate-400 font-mono mt-1">
                Suricata L4/L7 Inspection &bull; Netfilter iptables
              </div>
            </div>

            <div className="space-y-2 text-xs border-t border-inherit pt-3">
              <div className="flex justify-between">
                <span className="text-slate-400">FORWARD CHAIN:</span>
                <span className="text-emerald-500 font-bold">ACTIVE DROPS</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">CONNTRACK:</span>
                <span className="font-medium">ESTABLISHED,RELATED</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">QUARANTINED HOSTS:</span>
                <span className="text-rose-500 font-bold tabular-nums">{blocklist.length}</span>
              </div>
            </div>
          </div>
        </div>

        {/* LAN IoT Subnet Zone */}
        <div className={`lg:col-span-4 border p-4 rounded-xl space-y-3 ${
          isDark ? 'bg-[#121824] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
        }`}>
          <div className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center justify-between border-b border-inherit pb-2">
            <div className="flex items-center gap-2">
              <Cpu className="w-4 h-4 text-emerald-500" />
              <span>Protected LAN IoT Devices</span>
            </div>
            <span className="text-[11px] font-bold text-emerald-500">{devices.length} Nodes</span>
          </div>

          <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
            {devices.map((dev) => {
              const blocked = isQuarantined(dev.ip);
              const alertState = hasAlert(dev.ip);

              return (
                <div
                  key={dev.id}
                  onClick={() => setSelectedIp(dev.ip)}
                  className={`p-2.5 rounded-lg border cursor-pointer transition-all flex items-center justify-between ${
                    blocked
                      ? isDark
                        ? 'bg-rose-500/10 border-rose-500/40 text-rose-300'
                        : 'bg-rose-50 border-rose-200 text-rose-800'
                      : alertState
                        ? isDark
                          ? 'bg-amber-500/10 border-amber-500/40 text-amber-300'
                          : 'bg-amber-50 border-amber-200 text-amber-800'
                        : isDark
                          ? 'bg-[#151D2C] border-[#222E42] hover:border-blue-500/50'
                          : 'bg-white border-slate-200 hover:border-blue-300 shadow-xs'
                  }`}
                >
                  <div>
                    <div className="font-semibold text-xs leading-tight">{dev.name}</div>
                    <div className="text-[10px] text-slate-400 font-mono mt-0.5">{dev.ip} &bull; {dev.deviceType}</div>
                  </div>

                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono tracking-wider uppercase font-semibold border ${
                    blocked
                      ? 'border-rose-500/40 text-rose-400 bg-rose-500/10'
                      : 'border-emerald-500/30 text-emerald-400 bg-emerald-500/10'
                  }`}>
                    {blocked ? 'ISOLATED' : 'ONLINE'}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

      </div>

    </div>
  );
};
