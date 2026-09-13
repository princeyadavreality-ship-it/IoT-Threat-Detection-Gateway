import React from 'react';
import { Shield, ShieldAlert, ShieldCheck, Play, Pause, RefreshCw, Terminal, Sliders, Activity } from 'lucide-react';

interface HeaderProps {
  safetyMode: boolean;
  onToggleSafety: () => void;
  autoTraffic: boolean;
  onToggleAutoTraffic: () => void;
  onRunScan: () => void;
  activeTab: 'dashboard' | 'packets' | 'python' | 'topology';
  setActiveTab: (tab: 'dashboard' | 'packets' | 'python' | 'topology') => void;
  onOpenThresholds: () => void;
  quarantineCount: number;
  alertCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  safetyMode,
  onToggleSafety,
  autoTraffic,
  onToggleAutoTraffic,
  onRunScan,
  activeTab,
  setActiveTab,
  onOpenThresholds,
  quarantineCount,
  alertCount,
}) => {
  return (
    <header className="bg-slate-900 border-b border-slate-800 sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between py-4 gap-4">
          
          {/* Title and Branding */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold text-white tracking-tight">
                  IoT Threat Detection &amp; Hardening Gateway
                </h1>
                <span className="px-2 py-0.5 text-xs font-semibold rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                  GATEWAY ACTIVE
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Local Subnet: <code className="text-slate-300 font-mono">192.168.1.0/24</code> &bull; Gateway IP: <code className="text-slate-300 font-mono">192.168.1.1</code> &bull; Software Simulation
              </p>
            </div>
          </div>

          {/* Quick Actions & Toggles */}
          <div className="flex flex-wrap items-center gap-2.5">
            {/* Run Scan Button */}
            <button
              id="header-run-scan-btn"
              onClick={onRunScan}
              className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-colors shadow-sm shadow-blue-600/20 cursor-pointer"
              title="Run rule-based detection engine over recent packet buffer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Run Detection Scan</span>
            </button>

            {/* Auto Traffic Generator Toggle */}
            <button
              id="header-auto-traffic-btn"
              onClick={onToggleAutoTraffic}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 border transition-all cursor-pointer ${
                autoTraffic
                  ? 'bg-emerald-950/40 text-emerald-300 border-emerald-500/30'
                  : 'bg-slate-800/80 text-slate-400 border-slate-700 hover:text-slate-200'
              }`}
              title="Simulates real-time background IoT traffic"
            >
              {autoTraffic ? <Pause className="w-3.5 h-3.5 text-emerald-400" /> : <Play className="w-3.5 h-3.5" />}
              <span>Auto Traffic: {autoTraffic ? 'ON' : 'PAUSED'}</span>
            </button>

            {/* Safety Mode Toggle */}
            <button
              id="header-safety-mode-btn"
              onClick={onToggleSafety}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 border transition-all cursor-pointer ${
                safetyMode
                  ? 'bg-slate-800 text-slate-300 border-slate-700 hover:border-slate-600'
                  : 'bg-rose-950/50 text-rose-300 border-rose-600/50 hover:bg-rose-900/40'
              }`}
              title={safetyMode ? 'Safety ON: iptables commands are strictly simulated' : 'Safety OFF: Live OS command execution enabled for hardware'}
            >
              {safetyMode ? (
                <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />
              ) : (
                <ShieldAlert className="w-3.5 h-3.5 text-rose-400 animate-bounce" />
              )}
              <span>Safety: {safetyMode ? 'SIMULATED (Safe)' : 'LIVE HARDWARE'}</span>
            </button>

            {/* Thresholds Button */}
            <button
              id="header-thresholds-btn"
              onClick={onOpenThresholds}
              className="p-1.5 rounded-lg bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700 cursor-pointer"
              title="Configure Detection Thresholds"
            >
              <Sliders className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-t border-slate-800 gap-1 overflow-x-auto no-scrollbar">
          <button
            id="tab-dashboard"
            onClick={() => setActiveTab('dashboard')}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 flex items-center gap-2 whitespace-nowrap cursor-pointer transition-colors ${
              activeTab === 'dashboard'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Gateway Monitor &amp; Alerts</span>
            {alertCount > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                {alertCount}
              </span>
            )}
          </button>

          <button
            id="tab-topology"
            onClick={() => setActiveTab('topology')}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 flex items-center gap-2 whitespace-nowrap cursor-pointer transition-colors ${
              activeTab === 'topology'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Network Topology Map</span>
            {quarantineCount > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">
                {quarantineCount} Isolated
              </span>
            )}
          </button>

          <button
            id="tab-packets"
            onClick={() => setActiveTab('packets')}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 flex items-center gap-2 whitespace-nowrap cursor-pointer transition-colors ${
              activeTab === 'packets'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Live Packet Stream</span>
          </button>

          <button
            id="tab-python"
            onClick={() => setActiveTab('python')}
            className={`px-4 py-2.5 text-xs font-semibold border-b-2 flex items-center gap-2 whitespace-nowrap cursor-pointer transition-colors ${
              activeTab === 'python'
                ? 'border-blue-500 text-blue-400 bg-blue-500/5'
                : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Python Source &amp; Windows / Pi Setup</span>
          </button>
        </div>

      </div>
    </header>
  );
};
