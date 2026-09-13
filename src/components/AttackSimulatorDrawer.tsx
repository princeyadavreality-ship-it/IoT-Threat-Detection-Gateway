import React, { useState } from 'react';
import { X, Crosshair, KeyRound, Radio, Zap, Play, ShieldAlert } from 'lucide-react';
import { AlertCategory, IoTDevice } from '../types';

interface AttackSimulatorDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  devices: IoTDevice[];
  onInject: (category: AlertCategory, targetIp: string) => void;
  isInjecting: boolean;
  theme?: 'dark' | 'light';
}

export const AttackSimulatorDrawer: React.FC<AttackSimulatorDrawerProps> = ({
  isOpen,
  onClose,
  devices,
  onInject,
  isInjecting,
  theme = 'dark',
}) => {
  const [selectedCategory, setSelectedCategory] = useState<AlertCategory>('PORT_SCAN');
  const [targetDeviceIp, setTargetDeviceIp] = useState<string>(devices[0]?.ip || '192.168.1.10');
  const isDark = theme === 'dark';

  if (!isOpen) return null;

  const attacks: {
    category: AlertCategory;
    name: string;
    icon: React.ReactNode;
    desc: string;
    profile: string;
    ruleTrigger: string;
  }[] = [
    {
      category: 'PORT_SCAN',
      name: 'TCP Port Sweep Reconnaissance',
      icon: <Crosshair className="w-4 h-4 text-blue-500" />,
      desc: 'Rapid reconnaissance probing 18 unique TCP ports from external adversary 198.51.100.42 within <1.0s window.',
      profile: '18 SYN pkts, Len: 60B, Ports: 21, 22, 23, 80, 443, 8080...',
      ruleTrigger: 'Unique ports >= 15 in sliding window 5.0s',
    },
    {
      category: 'BRUTE_FORCE',
      name: 'SSH / Admin Credential Attack',
      icon: <KeyRound className="w-4 h-4 text-rose-500" />,
      desc: 'Sustained failed credential authentication bursts targeting IoT management ports (SSH 22 / Telnet 23).',
      profile: '8 Failed attempts with auth_success=false in <2.0s',
      ruleTrigger: 'Failed auth >= 5 in sliding window 10.0s',
    },
    {
      category: 'C2_BEACONING',
      name: 'Command & Control (C2) Low-Jitter Beacon',
      icon: <Radio className="w-4 h-4 text-amber-500" />,
      desc: 'Simulates compromised IoT firmware transmitting periodic check-ins to malicious C2 server 203.0.113.88:8443.',
      profile: '8 Periodic HTTPS heartbeats, ~2.4s intervals (std_dev < 0.05s)',
      ruleTrigger: 'Beacon pulses >= 4, std_dev delta_t < 0.25s',
    },
    {
      category: 'VOLUME_FLOOD',
      name: 'Volume Flood / UDP DDoS Surge',
      icon: <Zap className="w-4 h-4 text-purple-500" />,
      desc: 'Sudden bandwidth inundation targeting port 80/443 to saturate IoT device network stack.',
      profile: '35 UDP datagrams (1400B each) = ~49,000 bytes in 0.7s',
      ruleTrigger: 'Byte sum >= 30,000 in sliding window 3.0s',
    },
  ];

  const currentAttack = attacks.find((a) => a.category === selectedCategory) || attacks[0];

  const handleExecute = () => {
    onInject(selectedCategory, targetDeviceIp);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
      <div className={`border rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl relative transition-colors ${
        isDark ? 'bg-[#0F1522] border-[#1C2538] text-slate-100' : 'bg-white border-slate-200 text-slate-900'
      }`}>
        
        {/* Header */}
        <div className={`px-5 py-4 border-b flex items-center justify-between ${
          isDark ? 'border-[#1C2538] bg-[#121824]' : 'border-slate-200 bg-slate-50'
        }`}>
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-lg bg-rose-500/10 text-rose-500">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <span className="font-display font-bold text-sm">
                Adversary Attack Vector Simulation
              </span>
              <div className="text-xs text-slate-400">
                Inject synthetically generated exploit traffic to test detection latency
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 cursor-pointer p-1.5 rounded-lg hover:bg-slate-700/30 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body Grid */}
        <div className="p-5 grid grid-cols-1 md:grid-cols-12 gap-4">
          
          {/* Left: Attack Pattern Selector */}
          <div className="md:col-span-6 space-y-2">
            <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">
              Select Vector:
            </div>

            {attacks.map((atk) => {
              const isSelected = selectedCategory === atk.category;
              return (
                <div
                  key={atk.category}
                  onClick={() => setSelectedCategory(atk.category)}
                  className={`p-3 rounded-xl border transition-all cursor-pointer text-xs ${
                    isSelected
                      ? isDark
                        ? 'bg-[#151E2E] border-blue-500 text-white shadow-xs'
                        : 'bg-blue-50/50 border-blue-500 text-slate-900 shadow-xs'
                      : isDark
                        ? 'bg-[#121824] border-[#1C2538] text-slate-300 hover:border-slate-700'
                        : 'bg-white border-slate-200 text-slate-700 hover:border-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2.5 font-semibold">
                      {atk.icon}
                      <span className="text-xs">{atk.name}</span>
                    </div>
                    {isSelected && <span className="w-2 h-2 rounded-full bg-blue-500"></span>}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1 font-mono">
                    {atk.ruleTrigger}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Right: Target Specification */}
          <div className={`md:col-span-6 space-y-3.5 p-4 rounded-xl border font-mono text-xs ${
            isDark ? 'bg-[#121824] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
          }`}>
            
            {/* Target Select */}
            <div>
              <label className="text-slate-400 text-xs block mb-1.5 font-sans font-medium">
                Target LAN Subnet Node
              </label>
              <select
                value={targetDeviceIp}
                onChange={(e) => setTargetDeviceIp(e.target.value)}
                className={`w-full px-3 py-2 text-xs font-mono rounded-lg border outline-none focus:ring-1 focus:ring-blue-500 cursor-pointer ${
                  isDark ? 'bg-[#0B0F17] border-[#222E42] text-slate-200' : 'bg-white border-slate-300 text-slate-900'
                }`}
              >
                {devices.map((d) => (
                  <option key={d.id} value={d.ip}>
                    {d.name} ({d.ip})
                  </option>
                ))}
              </select>
            </div>

            {/* Profile Specification */}
            <div>
              <span className="text-slate-400 text-[11px] block uppercase tracking-wider mb-1 font-bold">
                Simulation Signature:
              </span>
              <div className={`p-2.5 rounded-lg border text-[11px] space-y-1 ${
                isDark ? 'bg-[#0B0F17] border-[#222E42] text-slate-300' : 'bg-white border-slate-200 text-slate-700'
              }`}>
                <div><span className="text-slate-400">Frame:</span> {currentAttack.profile}</div>
                <div><span className="text-slate-400">Heuristic:</span> {currentAttack.ruleTrigger}</div>
                <div><span className="text-slate-400">Rule Drop:</span> <span className="text-rose-500 font-bold">iptables -s {targetDeviceIp} -j DROP</span></div>
              </div>
            </div>

            {/* Summary */}
            <div className="text-xs font-sans text-slate-400 leading-relaxed">
              {currentAttack.desc}
            </div>

            {/* Execute Button */}
            <button
              onClick={handleExecute}
              disabled={isInjecting}
              className="w-full py-2.5 px-4 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-sans text-xs font-bold tracking-wide flex items-center justify-center gap-2 cursor-pointer transition-all disabled:opacity-50 shadow-xs"
            >
              {isInjecting ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span>
                  <span>Injecting Vector Telemetry...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Execute Vector Attack</span>
                </>
              )}
            </button>
          </div>

        </div>

      </div>
    </div>
  );
};
