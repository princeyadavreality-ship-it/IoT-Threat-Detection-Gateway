import React, { useState } from 'react';
import { Crosshair, KeyRound, Radio, Zap, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { AlertCategory, IoTDevice } from '../types';

interface AttackInjectorProps {
  devices: IoTDevice[];
  onInject: (type: AlertCategory, targetIp: string) => void;
  isInjecting: boolean;
}

export const AttackInjector: React.FC<AttackInjectorProps> = ({
  devices,
  onInject,
  isInjecting,
}) => {
  const [lastInjected, setLastInjected] = useState<string | null>(null);

  const handleInject = (category: AlertCategory, defaultTarget: string) => {
    onInject(category, defaultTarget);
    setLastInjected(category);
    setTimeout(() => setLastInjected(null), 3000);
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3.5 mb-4 border-b border-slate-800 gap-2">
        <div>
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            <h2 className="text-sm font-bold text-white uppercase tracking-wider">
              Attack Simulator &amp; Threat Injector
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Inject realistic malicious traffic vectors directly into the live packet stream to test detection heuristics and automated isolation.
          </p>
        </div>
        {lastInjected && (
          <div className="flex items-center gap-1.5 px-2.5 py-1 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-300 text-xs font-medium animate-fade-in">
            <CheckCircle2 className="w-3.5 h-3.5 text-amber-400" />
            <span>Injected: {lastInjected}</span>
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3.5">
        
        {/* Attack 1: Port Scan */}
        <div className="bg-slate-800/60 hover:bg-slate-800/90 border border-slate-700/70 hover:border-slate-600 rounded-lg p-3.5 flex flex-col justify-between transition-all">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-purple-500/15 text-purple-300 border border-purple-500/30 uppercase">
                Reconnaissance
              </span>
              <Crosshair className="w-4 h-4 text-purple-400" />
            </div>
            <h3 className="text-xs font-bold text-white">Port Scan Sweep</h3>
            <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
              Attacker <code className="text-slate-300 font-mono">198.51.100.42</code> sweeps 18 unique TCP ports on the Camera (<code className="text-slate-300 font-mono">192.168.1.10</code>) in under 1 second.
            </p>
          </div>
          <button
            id="inject-port-scan-btn"
            disabled={isInjecting}
            onClick={() => handleInject('PORT_SCAN', '192.168.1.10')}
            className="mt-3 w-full py-1.5 px-3 bg-purple-600/90 hover:bg-purple-500 text-white rounded text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
          >
            <Crosshair className="w-3.5 h-3.5" />
            <span>Inject Port Scan (18 Ports)</span>
          </button>
        </div>

        {/* Attack 2: Brute Force */}
        <div className="bg-slate-800/60 hover:bg-slate-800/90 border border-slate-700/70 hover:border-slate-600 rounded-lg p-3.5 flex flex-col justify-between transition-all">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-rose-500/15 text-rose-300 border border-rose-500/30 uppercase">
                Credential Theft
              </span>
              <KeyRound className="w-4 h-4 text-rose-400" />
            </div>
            <h3 className="text-xs font-bold text-white">Brute-Force Auth</h3>
            <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
              Attacker floods the Smart Door Lock (<code className="text-slate-300 font-mono">192.168.1.11:22</code>) with 8 rapid failed password attempts in 2 seconds.
            </p>
          </div>
          <button
            id="inject-brute-force-btn"
            disabled={isInjecting}
            onClick={() => handleInject('BRUTE_FORCE', '192.168.1.11')}
            className="mt-3 w-full py-1.5 px-3 bg-rose-600/90 hover:bg-rose-500 text-white rounded text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
          >
            <KeyRound className="w-3.5 h-3.5" />
            <span>Inject Brute Force (8 Attempts)</span>
          </button>
        </div>

        {/* Attack 3: C2 Beaconing */}
        <div className="bg-slate-800/60 hover:bg-slate-800/90 border border-slate-700/70 hover:border-slate-600 rounded-lg p-3.5 flex flex-col justify-between transition-all">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 uppercase">
                Malware C2
              </span>
              <Radio className="w-4 h-4 text-amber-400" />
            </div>
            <h3 className="text-xs font-bold text-white">C2 Beaconing (Low Jitter)</h3>
            <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
              Compromised Power Plug (<code className="text-slate-300 font-mono">192.168.1.13</code>) makes regular heartbeats to C2 (<code className="text-slate-300 font-mono">203.0.113.88</code>) with jitter variance &lt; 0.05s.
            </p>
          </div>
          <button
            id="inject-c2-beaconing-btn"
            disabled={isInjecting}
            onClick={() => handleInject('C2_BEACONING', '192.168.1.13')}
            className="mt-3 w-full py-1.5 px-3 bg-amber-600/90 hover:bg-amber-500 text-white rounded text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
          >
            <Radio className="w-3.5 h-3.5" />
            <span>Inject C2 Beaconing (8 Pulses)</span>
          </button>
        </div>

        {/* Attack 4: Volume Flood */}
        <div className="bg-slate-800/60 hover:bg-slate-800/90 border border-slate-700/70 hover:border-slate-600 rounded-lg p-3.5 flex flex-col justify-between transition-all">
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="px-2 py-0.5 text-[10px] font-bold rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 uppercase">
                DDoS / Exfiltration
              </span>
              <AlertTriangle className="w-4 h-4 text-cyan-400" />
            </div>
            <h3 className="text-xs font-bold text-white">Volume Flood Surge</h3>
            <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
              Massive UDP burst of 35 packets (~49,000 bytes) hitting Camera (<code className="text-slate-300 font-mono">192.168.1.10:80</code>) within 0.7s to choke gateway capacity.
            </p>
          </div>
          <button
            id="inject-volume-flood-btn"
            disabled={isInjecting}
            onClick={() => handleInject('VOLUME_FLOOD', '192.168.1.10')}
            className="mt-3 w-full py-1.5 px-3 bg-cyan-600/90 hover:bg-cyan-500 text-white rounded text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
          >
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Inject Volume Flood (49 KB)</span>
          </button>
        </div>

      </div>
    </div>
  );
};
