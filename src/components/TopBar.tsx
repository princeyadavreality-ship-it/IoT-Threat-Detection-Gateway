import React, { useState, useEffect } from 'react';
import { 
  RefreshCw, 
  Play, 
  Pause, 
  ShieldCheck, 
  ShieldAlert, 
  Wifi, 
  Volume2, 
  VolumeX,
  Sun,
  Moon,
  Crosshair,
  Shield,
  Activity,
  Clock
} from 'lucide-react';

interface TopBarProps {
  monitoringActive: boolean;
  onToggleMonitoring: () => void;
  deviceCount: number;
  lastScanTime: number;
  safetyMode: boolean;
  onToggleSafety: () => void;
  onRunScanNow: () => void;
  isScanning: boolean;
  onOpenThresholds: () => void;
  ttsEnabled: boolean;
  onToggleTts: () => void;
  isSpeakingTts?: boolean;
  onTestTts?: () => void;
  theme?: 'dark' | 'light';
  onToggleTheme?: () => void;
  onOpenAttackDrawer?: () => void;
  adaptiveRegime?: string;
  adaptiveMultiplier?: number;
  onOpenBaseline?: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({
  monitoringActive,
  onToggleMonitoring,
  deviceCount,
  lastScanTime,
  safetyMode,
  onToggleSafety,
  onRunScanNow,
  isScanning,
  onOpenThresholds,
  ttsEnabled,
  onToggleTts,
  isSpeakingTts = false,
  onTestTts,
  theme = 'dark',
  onToggleTheme,
  onOpenAttackDrawer,
  adaptiveRegime,
  adaptiveMultiplier,
  onOpenBaseline,
}) => {
  const [secondsUntilRefresh, setSecondsUntilRefresh] = useState<number>(2);

  // Auto-refresh countdown simulation for live feeling
  useEffect(() => {
    if (!monitoringActive) return;
    const interval = setInterval(() => {
      setSecondsUntilRefresh((prev) => (prev <= 1 ? 2 : prev - 1));
    }, 1000);
    return () => clearInterval(interval);
  }, [monitoringActive]);

  const formatTime = (ts: number) => {
    if (!ts) return '--:--:--';
    const d = new Date(ts);
    return `${d.toISOString().slice(11, 19)} UTC`;
  };

  const isDark = theme === 'dark';

  return (
    <header className={`relative px-4 lg:px-6 py-2.5 flex items-center justify-between gap-4 select-none shrink-0 transition-colors border-b z-20 ${
      isDark 
        ? 'bg-[#0B0F17] border-[#1C2433] text-[#F1F5F9]' 
        : 'bg-white border-slate-200 text-slate-900 shadow-xs'
    }`}>
      
      {/* Left: Brand Identity, Fleet Scope & Operational Status */}
      <div className="flex items-center gap-4">
        {/* Brand Lockup */}
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center text-white shadow-sm ring-1 ring-white/20">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-display font-bold text-sm tracking-tight">
                SENTINEL<span className="text-blue-500 font-semibold">.IOT</span>
              </span>
              <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-medium border ${
                isDark 
                  ? 'bg-[#141B28] text-slate-400 border-[#222E42]' 
                  : 'bg-slate-100 text-slate-600 border-slate-200'
              }`}>
                v2.4
              </span>
            </div>
            <div className={`text-[11px] flex items-center gap-1.5 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
              <span className="font-mono">192.168.1.1</span>
              <span>&bull;</span>
              <span className="hidden sm:inline">Gateway Core</span>
            </div>
          </div>
        </div>

        {/* Live Status Pill */}
        <div className={`hidden md:flex items-center gap-2 px-2.5 py-1 rounded-full text-xs border ${
          monitoringActive 
            ? isDark
              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/25'
              : 'bg-emerald-50 text-emerald-700 border-emerald-200'
            : isDark
              ? 'bg-slate-800 text-slate-400 border-slate-700'
              : 'bg-slate-100 text-slate-600 border-slate-200'
        }`}>
          <span className="relative flex h-2 w-2">
            {monitoringActive ? (
              <>
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-60"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </>
            ) : (
              <span className="relative inline-flex rounded-full h-2 w-2 bg-slate-400"></span>
            )}
          </span>
          <span className="font-medium text-[11px]">
            {monitoringActive ? 'Ingestion Active' : 'Ingestion Paused'}
          </span>
          <span className={`text-[10px] font-mono tabular-nums pl-1 border-l ${
            isDark ? 'border-emerald-500/20 text-emerald-400/80' : 'border-emerald-200 text-emerald-600'
          }`}>
            {monitoringActive ? `${secondsUntilRefresh}s tick` : 'idle'}
          </span>
        </div>

        {/* Subnet Nodes Counter */}
        <div className={`hidden xl:flex items-center gap-1.5 text-xs ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
          <Wifi className="w-3.5 h-3.5 text-blue-500" />
          <span className="font-medium">{deviceCount} Managed IoT Nodes</span>
        </div>

        {/* Adaptive Baseline Regime Status Badge */}
        {adaptiveRegime && (
          <button
            onClick={onOpenBaseline}
            className={`hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-xs font-mono transition-all cursor-pointer ${
              adaptiveRegime === 'MAINTENANCE_WINDOW'
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                : adaptiveRegime === 'OFF_PEAK'
                ? 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30 hover:bg-indigo-500/20'
                : 'bg-blue-500/10 text-blue-400 border-blue-500/30 hover:bg-blue-500/20'
            }`}
            title="Current Diurnal Operational Regime - Click to inspect Adaptive Baseline"
          >
            <Clock className="w-3.5 h-3.5" />
            <span className="font-medium">
              {adaptiveRegime === 'MAINTENANCE_WINDOW' ? 'Maint. Window' : adaptiveRegime === 'OFF_PEAK' ? 'Off-Peak' : 'Peak Hours'}
            </span>
            <span className="font-bold opacity-80">({adaptiveMultiplier?.toFixed(1) || '1.0'}x)</span>
          </button>
        )}
      </div>

      {/* Right: Operational Controls & Tools */}
      <div className="flex items-center gap-2">
        
        {/* Force Scan */}
        <button
          id="topbar-run-scan-btn"
          onClick={onRunScanNow}
          disabled={isScanning}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 border transition-all cursor-pointer disabled:opacity-50 ${
            isDark 
              ? 'bg-[#131926] hover:bg-[#1A2234] text-slate-300 hover:text-white border-[#222E42]' 
              : 'bg-slate-50 hover:bg-slate-100 text-slate-700 border-slate-200'
          }`}
          title="Force immediate heuristic evaluation of buffered telemetry"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-blue-500 ${isScanning ? 'animate-spin' : ''}`} />
          <span className="hidden sm:inline">Scan Now</span>
        </button>

        {/* Telemetry Stream Toggle */}
        <button
          id="topbar-traffic-toggle-btn"
          onClick={onToggleMonitoring}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 border transition-all cursor-pointer ${
            monitoringActive
              ? isDark
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                : 'bg-emerald-50 text-emerald-700 border-emerald-300 hover:bg-emerald-100'
              : isDark
                ? 'bg-[#131926] text-slate-400 border-[#222E42] hover:bg-[#1A2234]'
                : 'bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100'
          }`}
          title="Toggle live telemetry ingestion"
        >
          {monitoringActive ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
          <span className="hidden md:inline">{monitoringActive ? 'Stream On' : 'Paused'}</span>
        </button>

        {/* Voice Alerts Toggle */}
        <button
          id="topbar-tts-toggle-btn"
          onClick={onToggleTts}
          className={`px-3 py-1.5 rounded-lg text-xs font-medium flex items-center gap-1.5 border transition-all cursor-pointer ${
            ttsEnabled
              ? isSpeakingTts
                ? 'bg-amber-500/20 text-amber-400 border-amber-500/50 shadow-xs ring-1 ring-amber-500/30'
                : isDark
                  ? 'bg-[#131926] text-blue-400 border-blue-500/40 hover:bg-[#1A2234]'
                  : 'bg-blue-50 text-blue-700 border-blue-200 hover:bg-blue-100'
              : isDark
                ? 'bg-[#131926] text-slate-500 border-[#222E42] hover:text-slate-400'
                : 'bg-slate-50 text-slate-400 border-slate-200 hover:text-slate-600'
          }`}
          title={ttsEnabled ? 'Voice notifications active (Click to mute)' : 'Voice notifications muted (Click to enable)'}
        >
          {ttsEnabled ? (
            <Volume2 className={`w-3.5 h-3.5 ${isSpeakingTts ? 'animate-pulse text-amber-400' : 'text-blue-500'}`} />
          ) : (
            <VolumeX className="w-3.5 h-3.5" />
          )}
          <span className="hidden lg:inline">
            {isSpeakingTts ? 'Speaking...' : ttsEnabled ? 'Voice On' : 'Muted'}
          </span>
        </button>

        {/* Safety Enforcement Mode Toggle */}
        <button
          id="topbar-safety-toggle-btn"
          onClick={onToggleSafety}
          className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center gap-1.5 border transition-all cursor-pointer ${
            safetyMode
              ? isDark
                ? 'bg-[#131926] text-slate-300 border-[#222E42] hover:bg-[#1A2234]'
                : 'bg-slate-50 text-slate-700 border-slate-200 hover:bg-slate-100'
              : 'bg-red-600 text-white border-red-600 hover:bg-red-700 shadow-sm'
          }`}
          title={safetyMode ? 'Dry-run: iptables quarantine commands are simulated safely' : 'Live mode: System executes active firewall isolation'}
        >
          {safetyMode ? (
            <>
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-500" />
              <span className="text-[11px]">Dry-Run</span>
            </>
          ) : (
            <>
              <ShieldAlert className="w-3.5 h-3.5 text-white animate-pulse" />
              <span className="text-[11px]">Active Kernel</span>
            </>
          )}
        </button>

        {/* Theme Switcher Toggle (Light / Dark) */}
        {onToggleTheme && (
          <button
            id="topbar-theme-toggle-btn"
            onClick={onToggleTheme}
            className={`p-2 rounded-lg border transition-all cursor-pointer ${
              isDark
                ? 'bg-[#131926] text-slate-300 border-[#222E42] hover:text-white hover:bg-[#1A2234]'
                : 'bg-slate-50 text-slate-600 border-slate-200 hover:text-slate-900 hover:bg-slate-100'
            }`}
            title={isDark ? 'Switch to Clean Light Studio theme' : 'Switch to Dark Obsidian theme'}
          >
            {isDark ? <Sun className="w-3.5 h-3.5 text-amber-400" /> : <Moon className="w-3.5 h-3.5 text-slate-700" />}
          </button>
        )}

        {/* Launch Adversary Test Button (Elevated CTA) */}
        {onOpenAttackDrawer && (
          <button
            id="topbar-attack-drawer-btn"
            onClick={onOpenAttackDrawer}
            className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition-all cursor-pointer active:scale-98"
            title="Launch Adversary Red Team Simulation Drawer"
          >
            <Crosshair className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Simulate Attack</span>
          </button>
        )}

      </div>
    </header>
  );
};
