import React, { useState, useMemo } from 'react';
import { 
  Clock, 
  ShieldCheck, 
  ShieldAlert, 
  Sliders, 
  Activity, 
  Zap, 
  Crosshair, 
  TrendingUp, 
  RotateCcw, 
  CheckCircle2, 
  AlertTriangle, 
  Info, 
  Play, 
  Calendar, 
  Sparkles,
  Copy,
  Check,
  Radio,
  Layers
} from 'lucide-react';
import { 
  AdaptiveBaselineConfig, 
  OperationalRegime, 
  DetectionThresholds, 
  SuppressedFalsePositive, 
  AlertCategory 
} from '../types';

interface AdaptiveBaselineHUDProps {
  config: AdaptiveBaselineConfig;
  onUpdateConfig: (newConfig: AdaptiveBaselineConfig) => void;
  thresholds: DetectionThresholds;
  suppressedEvents: SuppressedFalsePositive[];
  onTriggerMaintenanceTest: (routineType: 'firmware_sync' | 'asset_discovery_scan') => void;
  onClearSuppressedEvents: () => void;
  theme?: 'dark' | 'light';
}

export const AdaptiveBaselineHUD: React.FC<AdaptiveBaselineHUDProps> = ({
  config,
  onUpdateConfig,
  thresholds,
  suppressedEvents,
  onTriggerMaintenanceTest,
  onClearSuppressedEvents,
  theme = 'dark',
}) => {
  const isDark = theme === 'dark';
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Compute current hour based on config mode
  const currentHour = useMemo(() => {
    if (config.mode === 'MANUAL_SIMULATED') {
      return config.simulatedHour;
    }
    const d = new Date();
    return d.getHours() + d.getMinutes() / 60;
  }, [config.mode, config.simulatedHour]);

  // Compute regime and multiplier
  const { regime, multiplier, regimeDescription } = useMemo(() => {
    if (!config.enabled) {
      return {
        regime: 'PEAK_HOURS' as OperationalRegime,
        multiplier: 1.0,
        regimeDescription: 'Adaptive Baseline is disabled. Static 1.0x baseline active 24/7.',
      };
    }

    const mStart = config.maintenanceStartHour;
    const mEnd = config.maintenanceEndHour;
    let inMaint = false;
    if (mStart < mEnd) {
      inMaint = currentHour >= mStart && currentHour < mEnd;
    } else {
      inMaint = currentHour >= mStart || currentHour < mEnd;
    }

    if (inMaint) {
      return {
        regime: 'MAINTENANCE_WINDOW' as OperationalRegime,
        multiplier: config.maintenanceFactor,
        regimeDescription: `Scheduled maintenance window (${String(mStart).padStart(2, '0')}:00 - ${String(mEnd).padStart(2, '0')}:00): automated updates and scans tolerated.`,
      };
    }

    const isOffpeak = currentHour >= 18 || currentHour < 2 || (currentHour >= 5 && currentHour < 8);
    if (isOffpeak) {
      return {
        regime: 'OFF_PEAK' as OperationalRegime,
        multiplier: config.offpeakFactor,
        regimeDescription: 'Quiescent evening/night period: moderate baseline tolerance.',
      };
    }

    return {
      regime: 'PEAK_HOURS' as OperationalRegime,
      multiplier: 1.0,
      regimeDescription: 'Active daytime operational window: standard strict thresholds enforced.',
    };
  }, [config, currentHour]);

  // Effective thresholds computed for display
  const effectiveThresholds = useMemo(() => {
    const mult = config.enabled ? multiplier : 1.0;
    return {
      ports: Math.round(thresholds.portScanUniquePorts * mult),
      floodBytes: Math.round(thresholds.volumeFloodBytes * mult),
      bruteForce: Math.round(thresholds.bruteForceFailures * mult),
      beaconJitter: Number((thresholds.beaconingMaxJitterSec * (1 + (mult - 1) * 0.4)).toFixed(3)),
    };
  }, [thresholds, config.enabled, multiplier]);

  // Helper formatting for hours
  const formatHourString = (decimalHour: number) => {
    const hrs = Math.floor(decimalHour);
    const mins = Math.floor((decimalHour % 1) * 60);
    const period = hrs >= 12 ? 'PM' : 'AM';
    const displayHrs = hrs % 12 === 0 ? 12 : hrs % 12;
    return `${String(displayHrs).padStart(2, '0')}:${String(mins).padStart(2, '0')} ${period} (${String(hrs).padStart(2, '0')}:${String(mins).padStart(2, '0')})`;
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Generate 24-point diurnal data points for chart
  const diurnalPoints = useMemo(() => {
    const points: { hour: number; expectedTraffic: number; alertThreshold: number; inMaint: boolean }[] = [];
    for (let h = 0; h < 24; h += 0.5) {
      // Diurnal sinusoidal baseline curve: lower at 03:00, peak at 14:00
      const normTraffic = 20 + 75 * (0.5 + 0.5 * Math.sin(((h - 8) / 24) * 2 * Math.PI));
      
      const mStart = config.maintenanceStartHour;
      const mEnd = config.maintenanceEndHour;
      let inM = false;
      if (mStart < mEnd) {
        inM = h >= mStart && h < mEnd;
      } else {
        inM = h >= mStart || h < mEnd;
      }

      const mult = config.enabled 
        ? inM 
          ? config.maintenanceFactor 
          : (h >= 18 || h < 2 || (h >= 5 && h < 8)) ? config.offpeakFactor : 1.0 
        : 1.0;

      points.push({
        hour: h,
        expectedTraffic: Math.round(normTraffic),
        alertThreshold: Math.round(100 * mult),
        inMaint: inM,
      });
    }
    return points;
  }, [config]);

  return (
    <div className="space-y-6">
      
      {/* 1. Header Banner & Operational Status */}
      <div className={`border rounded-2xl p-5 lg:p-6 transition-all ${
        isDark ? 'bg-[#0E1422] border-[#1C263A]' : 'bg-white border-slate-200 shadow-sm'
      }`}>
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-5">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2.5">
              <div className={`p-2 rounded-xl ${
                regime === 'MAINTENANCE_WINDOW'
                  ? 'bg-emerald-500/20 text-emerald-400 ring-1 ring-emerald-500/40 animate-pulse'
                  : regime === 'OFF_PEAK'
                  ? 'bg-indigo-500/20 text-indigo-400 ring-1 ring-indigo-500/40'
                  : 'bg-blue-500/20 text-blue-400 ring-1 ring-blue-500/40'
              }`}>
                <Clock className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <h2 className={`font-display text-lg font-bold tracking-tight ${isDark ? 'text-white' : 'text-slate-900'}`}>
                    Adaptive Baseline Heuristic Engine
                  </h2>
                  <span className={`text-[11px] font-mono font-bold px-2.5 py-0.5 rounded-full border ${
                    !config.enabled
                      ? 'bg-slate-500/10 text-slate-400 border-slate-500/30'
                      : regime === 'MAINTENANCE_WINDOW'
                      ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40 shadow-xs'
                      : regime === 'OFF_PEAK'
                      ? 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30'
                      : 'bg-blue-500/15 text-blue-400 border-blue-500/30'
                  }`}>
                    {!config.enabled ? 'HEURISTIC DISABLED' : `${regime.replace('_', ' ')} (${multiplier.toFixed(1)}x SENSITIVITY)`}
                  </span>
                </div>
                <p className={`text-xs mt-0.5 ${isDark ? 'text-slate-400' : 'text-slate-600'}`}>
                  {regimeDescription}
                </p>
              </div>
            </div>
          </div>

          {/* Quick Controls */}
          <div className="flex items-center gap-3 self-start lg:self-auto flex-wrap">
            <div className={`px-3 py-1.5 rounded-xl border flex items-center gap-2 text-xs ${
              isDark ? 'bg-[#141C2E] border-[#222E46] text-slate-300' : 'bg-slate-50 border-slate-200 text-slate-700'
            }`}>
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span className="font-medium">Mitigated False Positives:</span>
              <span className="font-mono font-bold text-emerald-400">{suppressedEvents.length}</span>
            </div>

            <button
              onClick={() => onUpdateConfig({ ...config, enabled: !config.enabled })}
              className={`px-4 py-2 rounded-xl text-xs font-bold font-mono border transition-all cursor-pointer flex items-center gap-2 ${
                config.enabled
                  ? isDark
                    ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 hover:bg-emerald-500/30'
                    : 'bg-emerald-50 text-emerald-700 border-emerald-300 hover:bg-emerald-100'
                  : isDark
                    ? 'bg-slate-800 text-slate-400 border-slate-700 hover:text-white'
                    : 'bg-slate-100 text-slate-600 border-slate-300 hover:bg-slate-200'
              }`}
            >
              <Zap className="w-3.5 h-3.5" />
              {config.enabled ? 'ADAPTIVE: ACTIVE' : 'ADAPTIVE: DISABLED'}
            </button>
          </div>
        </div>

        {/* Dynamic Metric Comparison Row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-5 pt-4 border-t border-slate-800/80">
          <div className={`p-3 rounded-xl border ${isDark ? 'bg-[#121929] border-[#1E293F]' : 'bg-slate-50 border-slate-200'}`}>
            <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400 block mb-1">
              Port Sweep Limit
            </span>
            <div className="flex items-baseline gap-2">
              <span className={`text-lg font-bold font-mono ${multiplier > 1.0 ? 'text-emerald-400' : isDark ? 'text-white' : 'text-slate-900'}`}>
                {effectiveThresholds.ports} ports
              </span>
              <span className="text-[10px] text-slate-500 font-mono">
                (base: {thresholds.portScanUniquePorts})
              </span>
            </div>
            <span className="text-[10px] text-slate-400 block mt-1">
              Discovery scan allowance
            </span>
          </div>

          <div className={`p-3 rounded-xl border ${isDark ? 'bg-[#121929] border-[#1E293F]' : 'bg-slate-50 border-slate-200'}`}>
            <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400 block mb-1">
              Volume Flood Limit
            </span>
            <div className="flex items-baseline gap-2">
              <span className={`text-lg font-bold font-mono ${multiplier > 1.0 ? 'text-emerald-400' : isDark ? 'text-white' : 'text-slate-900'}`}>
                {(effectiveThresholds.floodBytes / 1024).toFixed(1)} KB
              </span>
              <span className="text-[10px] text-slate-500 font-mono">
                (base: {(thresholds.volumeFloodBytes / 1024).toFixed(1)}K)
              </span>
            </div>
            <span className="text-[10px] text-slate-400 block mt-1">
              Firmware update bandwidth
            </span>
          </div>

          <div className={`p-3 rounded-xl border ${isDark ? 'bg-[#121929] border-[#1E293F]' : 'bg-slate-50 border-slate-200'}`}>
            <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400 block mb-1">
              Auth Retry Tolerance
            </span>
            <div className="flex items-baseline gap-2">
              <span className={`text-lg font-bold font-mono ${multiplier > 1.0 ? 'text-emerald-400' : isDark ? 'text-white' : 'text-slate-900'}`}>
                {effectiveThresholds.bruteForce} fails
              </span>
              <span className="text-[10px] text-slate-500 font-mono">
                (base: {thresholds.bruteForceFailures})
              </span>
            </div>
            <span className="text-[10px] text-slate-400 block mt-1">
              Batch script key rotations
            </span>
          </div>

          <div className={`p-3 rounded-xl border ${isDark ? 'bg-[#121929] border-[#1E293F]' : 'bg-slate-50 border-slate-200'}`}>
            <span className="text-[10px] uppercase font-mono tracking-wider text-slate-400 block mb-1">
              Beacon Jitter Max
            </span>
            <div className="flex items-baseline gap-2">
              <span className={`text-lg font-bold font-mono ${multiplier > 1.0 ? 'text-emerald-400' : isDark ? 'text-white' : 'text-slate-900'}`}>
                {effectiveThresholds.beaconJitter}s
              </span>
              <span className="text-[10px] text-slate-500 font-mono">
                (base: {thresholds.beaconingMaxJitterSec}s)
              </span>
            </div>
            <span className="text-[10px] text-slate-400 block mt-1">
              Synchronized sync pulses
            </span>
          </div>
        </div>
      </div>

      {/* 2. Interactive Time Scrubber & Diurnal Cycle */}
      <div className={`border rounded-2xl p-5 lg:p-6 ${
        isDark ? 'bg-[#0E1422] border-[#1C263A]' : 'bg-white border-slate-200 shadow-sm'
      }`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h3 className={`text-sm font-display font-bold flex items-center gap-2 ${isDark ? 'text-white' : 'text-slate-900'}`}>
              <Calendar className="w-4 h-4 text-blue-400" />
              <span>24-Hour Diurnal Timeline &amp; Time-of-Day Scrubber</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Drag the timeline to simulate network traffic across diurnal cycles or lock to system real-time clock.
            </p>
          </div>

          {/* Mode Switcher */}
          <div className="flex items-center gap-1.5 p-1 rounded-xl bg-slate-900 border border-slate-800">
            <button
              onClick={() => onUpdateConfig({ ...config, mode: 'MANUAL_SIMULATED' })}
              className={`px-3 py-1 rounded-lg text-xs font-medium cursor-pointer transition-colors ${
                config.mode === 'MANUAL_SIMULATED'
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Simulated Scrubber
            </button>
            <button
              onClick={() => onUpdateConfig({ ...config, mode: 'AUTO_CLOCK' })}
              className={`px-3 py-1 rounded-lg text-xs font-medium cursor-pointer transition-colors ${
                config.mode === 'AUTO_CLOCK'
                  ? 'bg-blue-600 text-white shadow-xs'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Live Clock
            </button>
          </div>
        </div>

        {/* Current Time Readout */}
        <div className="flex items-center justify-between text-xs mb-3 font-mono">
          <span className="text-slate-400">Selected Time of Day:</span>
          <span className={`text-sm font-bold px-3 py-1 rounded-lg border ${
            regime === 'MAINTENANCE_WINDOW'
              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
              : regime === 'OFF_PEAK'
              ? 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30'
              : 'bg-blue-500/10 text-blue-400 border-blue-500/30'
          }`}>
            🕒 {formatHourString(currentHour)}
          </span>
        </div>

        {/* Scrubber Range Slider with Visual Bands */}
        <div className="relative py-4">
          {/* Visual Band Backdrop */}
          <div className="h-4 w-full rounded-full overflow-hidden flex relative border border-slate-800">
            {/* 00:00 - 02:00 (Off-peak, 2h / 24h = 8.33%) */}
            <div style={{ width: '8.33%' }} className="bg-indigo-950/70 relative border-r border-slate-800" title="Off-Peak (00:00 - 02:00)" />
            {/* 02:00 - 05:00 (Maintenance Window, 3h / 24h = 12.5%) */}
            <div 
              style={{ width: `${((config.maintenanceEndHour - config.maintenanceStartHour) / 24) * 100}%` }} 
              className="bg-emerald-500/25 relative border-r border-emerald-500/40 flex items-center justify-center"
              title="Maintenance Window (02:00 - 05:00)"
            >
              <span className="text-[9px] font-mono text-emerald-300 font-bold tracking-tighter truncate px-1">
                MAINTENANCE WINDOW
              </span>
            </div>
            {/* 05:00 - 08:00 (Off-peak, 3h / 24h = 12.5%) */}
            <div style={{ width: '12.5%' }} className="bg-indigo-950/70 relative border-r border-slate-800" title="Morning Off-Peak (05:00 - 08:00)" />
            {/* 08:00 - 18:00 (Daytime Peak, 10h / 24h = 41.66%) */}
            <div style={{ width: '41.67%' }} className="bg-blue-950/60 relative border-r border-slate-800 flex items-center justify-center" title="Peak Daytime Hours (08:00 - 18:00)">
              <span className="text-[9px] font-mono text-blue-300 font-bold tracking-tighter">
                PEAK DAYTIME (1.0x STRICT)
              </span>
            </div>
            {/* 18:00 - 24:00 (Evening Off-peak, 6h / 24h = 25%) */}
            <div style={{ width: '25%' }} className="bg-indigo-950/70 relative" title="Evening Off-Peak (18:00 - 24:00)" />
          </div>

          {/* The Slider Input */}
          <input
            type="range"
            min={0}
            max={23.9}
            step={0.1}
            disabled={config.mode === 'AUTO_CLOCK'}
            value={currentHour}
            onChange={(e) => onUpdateConfig({ ...config, mode: 'MANUAL_SIMULATED', simulatedHour: parseFloat(e.target.value) })}
            className="w-full mt-2 cursor-pointer accent-blue-500 disabled:opacity-50"
          />

          <div className="flex justify-between text-[10px] text-slate-500 font-mono mt-1">
            <span>00:00 (Midnight)</span>
            <span className="text-emerald-400 font-bold">03:00 (Maint Window)</span>
            <span>08:00 (Peak Start)</span>
            <span>14:00 (Afternoon Peak)</span>
            <span>18:00 (Off-Peak)</span>
            <span>23:59 (End)</span>
          </div>
        </div>

        {/* Quick Presets Bar */}
        <div className="flex items-center gap-2 flex-wrap mt-3 pt-3 border-t border-slate-800/60">
          <span className="text-xs text-slate-400 font-mono mr-1">Quick Scrubber Presets:</span>
          
          <button
            onClick={() => onUpdateConfig({ ...config, mode: 'MANUAL_SIMULATED', simulatedHour: 3.25 })}
            className={`px-2.5 py-1 rounded-lg text-xs font-mono font-medium border transition-colors cursor-pointer flex items-center gap-1.5 ${
              regime === 'MAINTENANCE_WINDOW'
                ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border-slate-800'
            }`}
          >
            <span>🌙 03:15 AM Maint. Window</span>
          </button>

          <button
            onClick={() => onUpdateConfig({ ...config, mode: 'MANUAL_SIMULATED', simulatedHour: 14.0 })}
            className={`px-2.5 py-1 rounded-lg text-xs font-mono font-medium border transition-colors cursor-pointer flex items-center gap-1.5 ${
              currentHour >= 13.5 && currentHour <= 14.5
                ? 'bg-blue-500/20 text-blue-300 border-blue-500/40'
                : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border-slate-800'
            }`}
          >
            <span>☀️ 14:00 PM Daytime Peak</span>
          </button>

          <button
            onClick={() => onUpdateConfig({ ...config, mode: 'MANUAL_SIMULATED', simulatedHour: 21.0 })}
            className={`px-2.5 py-1 rounded-lg text-xs font-mono font-medium border transition-colors cursor-pointer flex items-center gap-1.5 ${
              currentHour >= 20.5 && currentHour <= 21.5
                ? 'bg-indigo-500/20 text-indigo-300 border-indigo-500/40'
                : 'bg-slate-900 hover:bg-slate-800 text-slate-300 border-slate-800'
            }`}
          >
            <span>🌆 21:00 PM Evening Off-Peak</span>
          </button>

          <button
            onClick={() => {
              const d = new Date();
              onUpdateConfig({ ...config, mode: 'AUTO_CLOCK', simulatedHour: d.getHours() + d.getMinutes() / 60 });
            }}
            className="px-2.5 py-1 rounded-lg text-xs font-mono font-medium bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 cursor-pointer flex items-center gap-1.5"
          >
            <span>⏱️ Sync Real System Time</span>
          </button>
        </div>
      </div>

      {/* 3. SVG Diurnal Traffic & Sensitivity Threshold Curve */}
      <div className={`border rounded-2xl p-5 lg:p-6 ${
        isDark ? 'bg-[#0E1422] border-[#1C263A]' : 'bg-white border-slate-200 shadow-sm'
      }`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
          <div>
            <h3 className={`text-sm font-display font-bold flex items-center gap-2 ${isDark ? 'text-white' : 'text-slate-900'}`}>
              <TrendingUp className="w-4 h-4 text-emerald-400" />
              <span>Diurnal Profile: Traffic Volume vs Adaptive Alert Threshold</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Notice how the threshold envelope (emerald) expands during the low-traffic maintenance window (02:00-05:00) to safely absorb scheduled bursts.
            </p>
          </div>

          {/* Legend */}
          <div className="flex items-center gap-4 text-xs font-mono">
            <div className="flex items-center gap-1.5">
              <span className="w-3 h-0.5 bg-blue-500 inline-block"></span>
              <span className="text-slate-400">Expected IoT Traffic</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-3 h-0.5 bg-emerald-400 inline-block"></span>
              <span className="text-slate-400">Adaptive Alert Limit ({multiplier}x)</span>
            </div>
          </div>
        </div>

        {/* SVG Curve Canvas */}
        <div className="w-full h-44 relative bg-slate-950/70 rounded-xl border border-slate-800/80 p-2 overflow-hidden">
          <svg viewBox="0 0 1000 200" preserveAspectRatio="none" className="w-full h-full">
            <defs>
              <linearGradient id="maintZoneGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#10b981" stopOpacity="0.25" />
                <stop offset="100%" stopColor="#10b981" stopOpacity="0.02" />
              </linearGradient>
              <linearGradient id="trafficGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.3" />
                <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.0" />
              </linearGradient>
            </defs>

            {/* Grid lines */}
            <line x1="0" y1="50" x2="1000" y2="50" stroke="#1e293b" strokeDasharray="4 4" strokeWidth="1" />
            <line x1="0" y1="100" x2="1000" y2="100" stroke="#1e293b" strokeDasharray="4 4" strokeWidth="1" />
            <line x1="0" y1="150" x2="1000" y2="150" stroke="#1e293b" strokeDasharray="4 4" strokeWidth="1" />

            {/* Shaded Maintenance Window Zone (02:00 to 05:00 -> 2/24*1000 = 83.3 to 5/24*1000 = 208.3) */}
            <rect 
              x={((config.maintenanceStartHour) / 24) * 1000} 
              y="0" 
              width={((config.maintenanceEndHour - config.maintenanceStartHour) / 24) * 1000} 
              height="200" 
              fill="url(#maintZoneGrad)" 
            />

            {/* Traffic Baseline Area & Line */}
            {(() => {
              const dTraffic = diurnalPoints.map((p, idx) => {
                const x = (p.hour / 24) * 1000;
                // invert y: 0 is top, 200 is bottom
                const y = 180 - (p.expectedTraffic / 100) * 140;
                return `${idx === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
              }).join(' ');
              return (
                <>
                  <path d={`${dTraffic} L 1000 200 L 0 200 Z`} fill="url(#trafficGrad)" />
                  <path d={dTraffic} fill="none" stroke="#3b82f6" strokeWidth="2.5" />
                </>
              );
            })()}

            {/* Adaptive Threshold Line */}
            {(() => {
              const dThresh = diurnalPoints.map((p, idx) => {
                const x = (p.hour / 24) * 1000;
                const y = 180 - (p.alertThreshold / (100 * config.maintenanceFactor * 1.2)) * 160;
                return `${idx === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`;
              }).join(' ');
              return <path d={dThresh} fill="none" stroke="#10b981" strokeWidth="2" strokeDasharray="3 3" />;
            })()}

            {/* Current Time Cursor Line */}
            {(() => {
              const cursorX = (currentHour / 24) * 1000;
              return (
                <g>
                  <line x1={cursorX} y1="0" x2={cursorX} y2="200" stroke="#f59e0b" strokeWidth="2" />
                  <circle cx={cursorX} cy="15" r="4" fill="#f59e0b" />
                </g>
              );
            })()}
          </svg>

          {/* Time cursor badge on top of chart */}
          <div 
            className="absolute top-2 -translate-x-1/2 pointer-events-none px-2 py-0.5 rounded bg-amber-500/90 text-slate-950 font-mono text-[9px] font-bold shadow-md"
            style={{ left: `${Math.min(92, Math.max(8, (currentHour / 24) * 100))}%` }}
          >
            {formatHourString(currentHour).split(' ')[0]} {regime.slice(0, 5)}
          </div>
        </div>
      </div>

      {/* 4. Live Maintenance Simulation Test Bench */}
      <div className={`border rounded-2xl p-5 lg:p-6 ${
        isDark ? 'bg-[#0E1422] border-[#1C263A]' : 'bg-white border-slate-200 shadow-sm'
      }`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
          <div>
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-amber-400" />
              <h3 className={`text-sm font-display font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                Maintenance Window Live Test Bench
              </h3>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Simulate scheduled maintenance routines right now to test false-positive mitigation under the current regime.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          
          {/* Test Case A: OTA Firmware Update */}
          <div className={`p-4 rounded-xl border space-y-3 ${
            isDark ? 'bg-[#121929] border-[#1E2A40]' : 'bg-slate-50 border-slate-200'
          }`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-purple-400" />
                <span className="text-xs font-bold font-display text-white">Routine A: OTA Firmware Binary Chunk</span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20">
                37.5 KB Burst
              </span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Target: <code className="font-mono text-blue-400">192.168.1.10</code> (Smart Security Camera).
              Exceeds static limit (<code className="font-mono text-rose-400">25,000 B</code>) but is under the adaptive maintenance threshold (<code className="font-mono text-emerald-400">{effectiveThresholds.floodBytes.toLocaleString()} B</code>).
            </p>

            <div className="flex items-center justify-between pt-2 border-t border-slate-800">
              <div className="text-[11px] font-mono">
                {regime === 'MAINTENANCE_WINDOW' && config.enabled ? (
                  <span className="text-emerald-400 font-semibold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Will be absorbed (0 alerts)
                  </span>
                ) : (
                  <span className="text-rose-400 font-semibold flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5" /> Will trigger FALSE POSITIVE
                  </span>
                )}
              </div>

              <button
                onClick={() => onTriggerMaintenanceTest('firmware_sync')}
                className="px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-purple-600 hover:bg-purple-500 text-white cursor-pointer transition-colors flex items-center gap-1.5 shadow-sm"
              >
                <Play className="w-3 h-3 fill-white" />
                <span>Inject 37.5 KB Sync</span>
              </button>
            </div>
          </div>

          {/* Test Case B: LAN Asset Discovery Sweep */}
          <div className={`p-4 rounded-xl border space-y-3 ${
            isDark ? 'bg-[#121929] border-[#1E2A40]' : 'bg-slate-50 border-slate-200'
          }`}>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Crosshair className="w-4 h-4 text-blue-400" />
                <span className="text-xs font-bold font-display text-white">Routine B: LAN Inventory Asset Scan</span>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20">
                17 Ports Probed
              </span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Target: <code className="font-mono text-blue-400">192.168.1.10</code> from Gateway <code className="font-mono">192.168.1.1</code>.
              Exceeds static limit (<code className="font-mono text-rose-400">15 ports</code>) but is under adaptive maintenance threshold (<code className="font-mono text-emerald-400">{effectiveThresholds.ports} ports</code>).
            </p>

            <div className="flex items-center justify-between pt-2 border-t border-slate-800">
              <div className="text-[11px] font-mono">
                {regime === 'MAINTENANCE_WINDOW' && config.enabled ? (
                  <span className="text-emerald-400 font-semibold flex items-center gap-1">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Will be absorbed (0 alerts)
                  </span>
                ) : (
                  <span className="text-rose-400 font-semibold flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5" /> Will trigger FALSE POSITIVE
                  </span>
                )}
              </div>

              <button
                onClick={() => onTriggerMaintenanceTest('asset_discovery_scan')}
                className="px-3 py-1.5 rounded-lg text-xs font-mono font-bold bg-blue-600 hover:bg-blue-500 text-white cursor-pointer transition-colors flex items-center gap-1.5 shadow-sm"
              >
                <Play className="w-3 h-3 fill-white" />
                <span>Inject 17-Port Sweep</span>
              </button>
            </div>
          </div>

        </div>
      </div>

      {/* 5. False Positive Mitigation Ledger (Audit Log) */}
      <div className={`border rounded-2xl p-5 lg:p-6 ${
        isDark ? 'bg-[#0E1422] border-[#1C263A]' : 'bg-white border-slate-200 shadow-sm'
      }`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <h3 className={`text-sm font-display font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
                Adaptive False-Positive Mitigation Ledger
              </h3>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Audit log of benign network anomalies absorbed by the Adaptive Baseline, preserving IoT device uptime.
            </p>
          </div>

          {suppressedEvents.length > 0 && (
            <button
              onClick={onClearSuppressedEvents}
              className="text-xs font-mono text-slate-400 hover:text-white px-2.5 py-1 rounded bg-slate-900 border border-slate-800 cursor-pointer"
            >
              Clear Log
            </button>
          )}
        </div>

        {suppressedEvents.length === 0 ? (
          <div className="p-8 text-center border border-dashed border-slate-800 rounded-xl">
            <CheckCircle2 className="w-8 h-8 text-slate-600 mx-auto mb-2" />
            <p className="text-xs text-slate-400">
              No benign maintenance anomalies recorded yet. Use the Test Bench above to simulate maintenance routines!
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-sans">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] font-mono uppercase text-slate-400">
                  <th className="py-2.5 px-3">Event ID</th>
                  <th className="py-2.5 px-3">Category</th>
                  <th className="py-2.5 px-3">Source &rarr; Target</th>
                  <th className="py-2.5 px-3">Raw Metric vs Static Limit</th>
                  <th className="py-2.5 px-3">Adaptive Limit</th>
                  <th className="py-2.5 px-3">Regime</th>
                  <th className="py-2.5 px-3">Prevented Quarantine Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                {suppressedEvents.map((evt) => (
                  <tr key={evt.id} className="hover:bg-slate-900/50 transition-colors">
                    <td className="py-3 px-3 text-slate-400 font-semibold">{evt.id}</td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold">
                        {evt.category}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-slate-300">
                      <span>{evt.sourceIp}</span>
                      <span className="text-slate-500 mx-1">&rarr;</span>
                      <span className="text-blue-400">{evt.targetIp}</span>
                    </td>
                    <td className="py-3 px-3">
                      <span className="text-amber-400 font-bold">{evt.rawMetric.toLocaleString()} {evt.metricUnit}</span>
                      <span className="text-slate-500 text-[10px] ml-1">(base: {evt.staticThreshold.toLocaleString()})</span>
                    </td>
                    <td className="py-3 px-3 text-emerald-400 font-bold">
                      {evt.adaptiveThreshold.toLocaleString()} {evt.metricUnit}
                    </td>
                    <td className="py-3 px-3">
                      <span className="text-slate-300 text-[10px]">
                        {evt.regime} (+{evt.multiplier}x)
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1.5">
                        <code className="text-[10px] px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-rose-300 line-through truncate max-w-xs">
                          {evt.preventedAction}
                        </code>
                        <button
                          onClick={() => handleCopy(evt.preventedAction, evt.id)}
                          className="p-1 text-slate-400 hover:text-white cursor-pointer"
                          title="Copy prevented iptables command"
                        >
                          {copiedId === evt.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* 6. Configuration & Tuning Controls */}
      <div className={`border rounded-2xl p-5 lg:p-6 ${
        isDark ? 'bg-[#0E1422] border-[#1C263A]' : 'bg-white border-slate-200 shadow-sm'
      }`}>
        <div className="flex items-center gap-2 mb-4">
          <Sliders className="w-4 h-4 text-blue-400" />
          <h3 className={`text-sm font-display font-bold ${isDark ? 'text-white' : 'text-slate-900'}`}>
            Adaptive Baseline Configuration &amp; Window Hours
          </h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div>
            <label className="text-xs text-slate-400 block mb-1 font-mono">Maintenance Start Hour</label>
            <select
              value={config.maintenanceStartHour}
              onChange={(e) => onUpdateConfig({ ...config, maintenanceStartHour: Number(e.target.value) })}
              className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-white font-mono text-xs"
            >
              {Array.from({ length: 24 }).map((_, i) => (
                <option key={i} value={i}>
                  {String(i).padStart(2, '0')}:00 {i >= 12 ? 'PM' : 'AM'}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="text-xs text-slate-400 block mb-1 font-mono">Maintenance End Hour</label>
            <select
              value={config.maintenanceEndHour}
              onChange={(e) => onUpdateConfig({ ...config, maintenanceEndHour: Number(e.target.value) })}
              className="w-full px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 text-white font-mono text-xs"
            >
              {Array.from({ length: 24 }).map((_, i) => (
                <option key={i} value={i}>
                  {String(i).padStart(2, '0')}:00 {i >= 12 ? 'PM' : 'AM'}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="text-xs text-slate-400 block mb-1 font-mono">
              Maintenance Multiplier ({config.maintenanceFactor}x)
            </label>
            <input
              type="range"
              min={1.2}
              max={4.0}
              step={0.1}
              value={config.maintenanceFactor}
              onChange={(e) => onUpdateConfig({ ...config, maintenanceFactor: parseFloat(e.target.value) })}
              className="w-full mt-2 accent-emerald-500"
            />
            <span className="text-[10px] text-slate-500 font-mono">1.2x (Tight) to 4.0x (Permissive)</span>
          </div>

          <div>
            <label className="text-xs text-slate-400 block mb-1 font-mono">
              Off-Peak Multiplier ({config.offpeakFactor}x)
            </label>
            <input
              type="range"
              min={1.0}
              max={2.5}
              step={0.1}
              value={config.offpeakFactor}
              onChange={(e) => onUpdateConfig({ ...config, offpeakFactor: parseFloat(e.target.value) })}
              className="w-full mt-2 accent-indigo-500"
            />
            <span className="text-[10px] text-slate-500 font-mono">1.0x (Standard) to 2.5x (Relaxed)</span>
          </div>
        </div>

        <div className="flex items-center justify-between pt-4 mt-4 border-t border-slate-800/80">
          <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300">
            <input
              type="checkbox"
              checked={config.autoSuppressMaintenanceSpikes}
              onChange={(e) => onUpdateConfig({ ...config, autoSuppressMaintenanceSpikes: e.target.checked })}
              className="rounded accent-emerald-500 cursor-pointer"
            />
            <span>Auto-suppress benign surges under adaptive threshold (prevents false iptables drop rules)</span>
          </label>

          <button
            onClick={() => onUpdateConfig({
              enabled: true,
              maintenanceStartHour: 2,
              maintenanceEndHour: 5,
              maintenanceFactor: 2.2,
              offpeakFactor: 1.3,
              mode: 'MANUAL_SIMULATED',
              simulatedHour: 3.25,
              autoSuppressMaintenanceSpikes: true,
            })}
            className="text-xs font-mono text-slate-400 hover:text-white flex items-center gap-1.5 cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Defaults</span>
          </button>
        </div>
      </div>

    </div>
  );
};
