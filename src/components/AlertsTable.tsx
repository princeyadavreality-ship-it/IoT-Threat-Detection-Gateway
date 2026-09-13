import React, { useState } from 'react';
import { AlertTriangle, ChevronDown, ChevronRight, ShieldAlert, Crosshair, KeyRound, Radio, Zap } from 'lucide-react';
import { ThreatAlert } from '../types';

interface AlertsTableProps {
  alerts: ThreatAlert[];
  onClearAlerts: () => void;
}

export const AlertsTable: React.FC<AlertsTableProps> = ({ alerts, onClearAlerts }) => {
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'PORT_SCAN':
        return <Crosshair className="w-3.5 h-3.5 text-purple-400" />;
      case 'BRUTE_FORCE':
        return <KeyRound className="w-3.5 h-3.5 text-rose-400" />;
      case 'C2_BEACONING':
        return <Radio className="w-3.5 h-3.5 text-amber-400" />;
      case 'VOLUME_FLOOD':
      default:
        return <Zap className="w-3.5 h-3.5 text-cyan-400" />;
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'HIGH':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30 uppercase">
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30 uppercase">
            MEDIUM
          </span>
        );
      case 'LOW':
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30 uppercase">
            LOW
          </span>
        );
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <div className="flex items-center justify-between pb-3.5 mb-4 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-rose-400" />
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">
            Detection Engine Alerts ({alerts.length})
          </h2>
        </div>
        {alerts.length > 0 && (
          <button
            id="clear-alerts-btn"
            onClick={onClearAlerts}
            className="text-xs text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
          >
            Clear Alert History
          </button>
        )}
      </div>

      {alerts.length === 0 ? (
        <div className="py-10 text-center text-slate-500 text-xs">
          <AlertTriangle className="w-8 h-8 text-slate-600 mx-auto mb-2 opacity-50" />
          <p className="text-slate-400 font-medium">No active threat alerts detected.</p>
          <p className="text-slate-500 text-[11px] mt-1">
            Subnet traffic is conforming to benign IoT baseline profiles. Inject an attack above to test detection rules.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-semibold">
                <th className="pb-3 pr-2 w-8"></th>
                <th className="pb-3 px-2">Alert ID</th>
                <th className="pb-3 px-2">Category</th>
                <th className="pb-3 px-2">Severity</th>
                <th className="pb-3 px-2">Source Host</th>
                <th className="pb-3 px-2">Target Host</th>
                <th className="pb-3 px-2">Forensic Detail</th>
                <th className="pb-3 pl-2 text-right">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {alerts.slice().reverse().map((alert) => {
                const isExpanded = expandedAlertId === alert.id;
                return (
                  <React.Fragment key={alert.id}>
                    <tr
                      onClick={() => setExpandedAlertId(isExpanded ? null : alert.id)}
                      className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                    >
                      {/* Expand Chevron */}
                      <td className="py-3 pr-2 text-slate-500">
                        {isExpanded ? (
                          <ChevronDown className="w-3.5 h-3.5 text-slate-300" />
                        ) : (
                          <ChevronRight className="w-3.5 h-3.5" />
                        )}
                      </td>

                      {/* ID */}
                      <td className="py-3 px-2 font-mono font-semibold text-slate-300">
                        {alert.id}
                      </td>

                      {/* Category */}
                      <td className="py-3 px-2">
                        <div className="flex items-center gap-1.5 font-medium text-slate-200">
                          {getCategoryIcon(alert.category)}
                          <span>{alert.category.replace('_', ' ')}</span>
                        </div>
                      </td>

                      {/* Severity */}
                      <td className="py-3 px-2">
                        {getSeverityBadge(alert.severity)}
                      </td>

                      {/* Source */}
                      <td className="py-3 px-2 font-mono text-rose-300 font-medium">
                        {alert.sourceIp}
                      </td>

                      {/* Target */}
                      <td className="py-3 px-2 font-mono text-slate-300">
                        {alert.targetIp}
                      </td>

                      {/* Detail */}
                      <td className="py-3 px-2 text-slate-300 max-w-xs truncate">
                        {alert.detail}
                      </td>

                      {/* Time */}
                      <td className="py-3 pl-2 text-right font-mono text-slate-400 text-[11px]">
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </td>
                    </tr>

                    {/* Expandable Forensic Evidence Row */}
                    {isExpanded && (
                      <tr className="bg-slate-800/50">
                        <td colSpan={8} className="p-3.5 text-xs">
                          <div className="bg-slate-950/80 border border-slate-700/80 rounded-lg p-3">
                            <div className="text-slate-300 font-semibold mb-1.5 flex items-center justify-between">
                              <span>Forensic Evidence &amp; Detection Heuristics</span>
                              <span className="text-[11px] font-mono text-slate-400">Rule Trigger: {alert.category}</span>
                            </div>
                            <p className="text-slate-400 text-[11px] mb-2">{alert.detail}</p>
                            <pre className="text-[11px] font-mono bg-slate-900 p-2 rounded text-emerald-400 overflow-x-auto border border-slate-800">
                              {JSON.stringify(alert.evidence, null, 2)}
                            </pre>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
