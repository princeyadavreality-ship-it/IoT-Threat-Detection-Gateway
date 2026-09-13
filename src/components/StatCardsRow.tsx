import React, { useMemo } from 'react';
import { Activity, ShieldAlert, Ban, Clock, CheckCircle2, TrendingUp } from 'lucide-react';
import { ThreatAlert } from '../types';

interface StatCardsRowProps {
  totalEvents: number;
  alertsCount: number;
  highSeverityCount: number;
  quarantinedCount: number;
  totalDevices: number;
  uptimeSeconds: number;
  packetRate: number;
  alerts?: ThreatAlert[];
  mtbiMinutes?: number;
  theme?: 'dark' | 'light';
}

export const StatCardsRow: React.FC<StatCardsRowProps> = ({
  totalEvents,
  alertsCount,
  highSeverityCount,
  quarantinedCount,
  totalDevices,
  uptimeSeconds,
  packetRate,
  alerts,
  mtbiMinutes,
  theme = 'dark',
}) => {
  const isDark = theme === 'dark';

  const calculatedMtbi = useMemo(() => {
    if (mtbiMinutes !== undefined) return mtbiMinutes;
    if (alerts && alerts.length > 0) {
      return Number((60 / alerts.length).toFixed(1));
    }
    return 24.8;
  }, [mtbiMinutes, alerts]);

  const formatUptime = (seconds: number) => {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${String(hrs).padStart(2, '0')}:${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
  };

  const cardBaseStyle = isDark
    ? 'bg-[#101622] border-[#1C2538] hover:border-[#27354E]'
    : 'bg-white border-slate-200 hover:border-slate-300 shadow-xs';

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
      
      {/* 1. Events Analyzed */}
      <div className={`border rounded-xl p-4 transition-all ${cardBaseStyle}`}>
        <div className="flex items-center justify-between mb-2">
          <span className={`text-xs font-medium ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
            Ingested Events
          </span>
          <div className={`p-1.5 rounded-lg ${isDark ? 'bg-blue-500/10 text-blue-400' : 'bg-blue-50 text-blue-600'}`}>
            <Activity className="w-4 h-4" />
          </div>
        </div>

        <div className="flex items-baseline gap-2.5">
          <span className={`font-display text-2xl lg:text-3xl font-bold tracking-tight tabular-nums ${
            isDark ? 'text-white' : 'text-slate-900'
          }`}>
            {totalEvents.toLocaleString()}
          </span>
          <span className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded-md border ${
            isDark 
              ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' 
              : 'bg-blue-50 text-blue-700 border-blue-200'
          }`}>
            {packetRate.toFixed(1)}/s
          </span>
        </div>

        <div className={`mt-2.5 pt-2 flex items-center justify-between text-[11px] border-t ${
          isDark ? 'border-slate-800/60 text-slate-400' : 'border-slate-100 text-slate-500'
        }`}>
          <span className="flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            <span>Zero Dropped</span>
          </span>
          <span className="font-mono text-[10px]">L4/L7 Stateful</span>
        </div>
      </div>

      {/* 2. Threat Alerts */}
      <div className={`border rounded-xl p-4 transition-all ${
        alertsCount > 0 
          ? isDark 
            ? 'bg-[#141219] border-rose-500/30 ring-1 ring-rose-500/20' 
            : 'bg-rose-50/50 border-rose-200 shadow-xs'
          : cardBaseStyle
      }`}>
        <div className="flex items-center justify-between mb-2">
          <span className={`text-xs font-medium ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
            Threat Alerts
          </span>
          <div className={`p-1.5 rounded-lg ${
            alertsCount > 0 
              ? 'bg-rose-500/15 text-rose-500' 
              : isDark ? 'bg-slate-800 text-slate-400' : 'bg-slate-100 text-slate-500'
          }`}>
            <ShieldAlert className="w-4 h-4" />
          </div>
        </div>

        <div className="flex items-baseline gap-2.5">
          <span className={`font-display text-2xl lg:text-3xl font-bold tracking-tight tabular-nums ${
            alertsCount > 0 
              ? 'text-rose-500' 
              : isDark ? 'text-white' : 'text-slate-900'
          }`}>
            {alertsCount}
          </span>
          {alertsCount > 0 && (
            <span className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded-md bg-rose-500/15 text-rose-400 border border-rose-500/30">
              {highSeverityCount} Critical
            </span>
          )}
        </div>

        <div className={`mt-2.5 pt-2 flex items-center justify-between text-[11px] border-t ${
          isDark ? 'border-slate-800/60 text-slate-400' : 'border-slate-100 text-slate-500'
        }`}>
          <span>ATT&amp;CK Rules</span>
          <span className={`font-medium ${alertsCount > 0 ? 'text-rose-400' : 'text-emerald-500'}`}>
            {alertsCount > 0 ? 'Mitigation Active' : 'Subnet Clean'}
          </span>
        </div>
      </div>

      {/* 3. KEY METRIC: Mean Time Between Incidents (MTBI) */}
      <div className={`border rounded-xl p-4 transition-all relative overflow-hidden ${
        isDark 
          ? 'bg-[#101926] border-blue-500/30 ring-1 ring-blue-500/20' 
          : 'bg-blue-50/50 border-blue-200 shadow-xs'
      }`}>
        <div className="flex items-center justify-between mb-2">
          <span className={`text-xs font-semibold ${isDark ? 'text-blue-300' : 'text-blue-900'}`}>
            MTBI (Key Metric)
          </span>
          <div className={`p-1.5 rounded-lg ${isDark ? 'bg-blue-500/20 text-blue-400' : 'bg-blue-100 text-blue-700'}`}>
            <TrendingUp className="w-4 h-4" />
          </div>
        </div>

        <div className="flex items-baseline gap-2">
          <span className={`font-display text-2xl lg:text-3xl font-bold tracking-tight tabular-nums ${
            isDark ? 'text-white' : 'text-slate-900'
          }`}>
            {calculatedMtbi} <span className="text-xs font-normal text-slate-400">min</span>
          </span>
          <span className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded-md bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            ↑ Improving
          </span>
        </div>

        <div className={`mt-2.5 pt-2 flex items-center justify-between text-[11px] border-t ${
          isDark ? 'border-slate-800/60 text-slate-400' : 'border-blue-100 text-slate-500'
        }`}>
          <span>Posture Trend</span>
          <span className="font-semibold text-emerald-500">
            Widening Intervals
          </span>
        </div>
      </div>

      {/* 4. Containment / Isolation */}
      <div className={`border rounded-xl p-4 transition-all ${
        quarantinedCount > 0
          ? isDark 
            ? 'bg-[#16151B] border-amber-500/30 ring-1 ring-amber-500/20' 
            : 'bg-amber-50/50 border-amber-200 shadow-xs'
          : cardBaseStyle
      }`}>
        <div className="flex items-center justify-between mb-2">
          <span className={`text-xs font-medium ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
            Quarantined Nodes
          </span>
          <div className={`p-1.5 rounded-lg ${
            quarantinedCount > 0 
              ? 'bg-amber-500/15 text-amber-500' 
              : isDark ? 'bg-slate-800 text-slate-400' : 'bg-slate-100 text-slate-500'
          }`}>
            <Ban className="w-4 h-4" />
          </div>
        </div>

        <div className="flex items-baseline gap-2.5">
          <span className={`font-display text-2xl lg:text-3xl font-bold tracking-tight tabular-nums ${
            isDark ? 'text-white' : 'text-slate-900'
          }`}>
            {quarantinedCount}
          </span>
          <span className={`text-xs ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
            / {totalDevices} Fleet
          </span>
        </div>

        <div className={`mt-2.5 pt-2 flex items-center justify-between text-[11px] border-t ${
          isDark ? 'border-slate-800/60 text-slate-400' : 'border-slate-100 text-slate-500'
        }`}>
          <span>Firewall Status</span>
          <span className={`font-medium ${quarantinedCount > 0 ? 'text-amber-500' : 'text-slate-400'}`}>
            {quarantinedCount === 0 ? 'All Nodes Open' : `${quarantinedCount} Isolated`}
          </span>
        </div>
      </div>

      {/* 5. Engine Health & Uptime */}
      <div className={`border rounded-xl p-4 transition-all ${cardBaseStyle}`}>
        <div className="flex items-center justify-between mb-2">
          <span className={`text-xs font-medium ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
            Gateway Uptime
          </span>
          <div className={`p-1.5 rounded-lg ${isDark ? 'bg-emerald-500/10 text-emerald-400' : 'bg-emerald-50 text-emerald-600'}`}>
            <Clock className="w-4 h-4" />
          </div>
        </div>

        <div className="flex items-baseline gap-2.5">
          <span className={`font-display text-2xl lg:text-3xl font-bold tracking-tight tabular-nums ${
            isDark ? 'text-white' : 'text-slate-900'
          }`}>
            {formatUptime(uptimeSeconds)}
          </span>
        </div>

        <div className={`mt-2.5 pt-2 flex items-center justify-between text-[11px] border-t ${
          isDark ? 'border-slate-800/60 text-slate-400' : 'border-slate-100 text-slate-500'
        }`}>
          <span className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
            <span>99.98% Healthy</span>
          </span>
          <span className="font-mono text-[10px]">Suricata 7.0</span>
        </div>
      </div>

    </div>
  );
};
