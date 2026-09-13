import React, { useState } from 'react';
import { ShieldCheck, ShieldAlert, Copy, Check, Terminal, ExternalLink, RefreshCw } from 'lucide-react';
import { ResponseAction } from '../types';

interface ResponseLedgerProps {
  actions: ResponseAction[];
  blocklist: string[];
  safetyMode: boolean;
  onUnblock: (ip: string) => void;
}

export const ResponseLedger: React.FC<ResponseLedgerProps> = ({
  actions,
  blocklist,
  safetyMode,
  onUnblock,
}) => {
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const handleCopy = (text: string, index: number) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3.5 mb-4 border-b border-slate-800 gap-2">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">
            Hardening &amp; Firewall Enforcement Ledger
          </h2>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">
            Active Blocklist: <strong className="text-rose-400 font-mono">{blocklist.length} IPs</strong>
          </span>
          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
            safetyMode 
              ? 'bg-blue-500/10 text-blue-400 border-blue-500/30' 
              : 'bg-rose-500/15 text-rose-300 border-rose-500/30 animate-pulse'
          }`}>
            {safetyMode ? 'Dry-Run Simulation' : 'Live Kernel Enforcement'}
          </span>
        </div>
      </div>

      {/* Active Quarantined IPs Chips */}
      {blocklist.length > 0 && (
        <div className="mb-4 p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex flex-wrap items-center gap-2">
          <span className="text-xs font-semibold text-slate-300">Quarantined IPs:</span>
          {blocklist.map((ip) => (
            <div
              key={ip}
              className="px-2.5 py-1 rounded bg-rose-950/60 text-rose-300 border border-rose-700/50 text-xs font-mono flex items-center gap-2"
            >
              <span>{ip}</span>
              <button
                id={`unblock-chip-${ip.replace(/\./g, '-')}`}
                onClick={() => onUnblock(ip)}
                className="hover:text-white cursor-pointer text-slate-400 transition-colors"
                title="Lift quarantine"
              >
                &times;
              </button>
            </div>
          ))}
        </div>
      )}

      {actions.length === 0 ? (
        <div className="py-8 text-center text-slate-500 text-xs">
          <Terminal className="w-8 h-8 text-slate-600 mx-auto mb-2 opacity-50" />
          <p className="text-slate-400 font-medium">No response actions recorded yet.</p>
          <p className="text-slate-500 text-[11px] mt-1">
            When threats are detected, the response engine evaluates security policies and synthesizes kernel iptables rules.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-semibold">
                <th className="pb-3 px-2">Target IP</th>
                <th className="pb-3 px-2">Policy Action</th>
                <th className="pb-3 px-2">Trigger Reason</th>
                <th className="pb-3 px-2">Generated iptables Rule</th>
                <th className="pb-3 px-2">Execution Mode</th>
                <th className="pb-3 pl-2 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {actions.slice().reverse().map((action, idx) => {
                const isBlocked = blocklist.includes(action.targetIp);
                return (
                  <tr key={action.id} className="hover:bg-slate-800/40 transition-colors">
                    
                    {/* Target IP */}
                    <td className="py-3 px-2 font-mono font-bold text-slate-200">
                      {action.targetIp}
                    </td>

                    {/* Action Badge */}
                    <td className="py-3 px-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                        action.action === 'ISOLATE'
                          ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
                          : 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                      }`}>
                        {action.action}
                      </span>
                    </td>

                    {/* Reason */}
                    <td className="py-3 px-2 text-slate-300 max-w-xs text-[11px]">
                      {action.reason}
                    </td>

                    {/* iptables Command */}
                    <td className="py-3 px-2 font-mono">
                      <div className="flex items-center gap-1.5 bg-slate-950/80 px-2.5 py-1.5 rounded border border-slate-800 text-blue-300 text-[11px] max-w-md overflow-x-auto">
                        <span className="text-slate-500 select-none">$</span>
                        <span className="truncate">{action.iptablesCommand}</span>
                        <button
                          id={`copy-iptables-btn-${idx}`}
                          onClick={() => handleCopy(action.iptablesCommand, idx)}
                          className="ml-auto text-slate-400 hover:text-white shrink-0 cursor-pointer"
                          title="Copy iptables command"
                        >
                          {copiedIndex === idx ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </td>

                    {/* Execution Mode */}
                    <td className="py-3 px-2">
                      <span className={`text-[11px] font-medium ${
                        action.executedLive ? 'text-amber-400 font-semibold' : 'text-slate-400'
                      }`}>
                        {action.executedLive ? 'Live OS Applied' : 'Simulated (Safe)'}
                      </span>
                    </td>

                    {/* Control / Unblock */}
                    <td className="py-3 pl-2 text-right">
                      {isBlocked ? (
                        <button
                          id={`unblock-action-btn-${action.targetIp.replace(/\./g, '-')}`}
                          onClick={() => onUnblock(action.targetIp)}
                          className="px-2.5 py-1 text-xs rounded bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 font-semibold transition-colors cursor-pointer"
                        >
                          Lift Block
                        </button>
                      ) : (
                        <span className="text-slate-500 text-[11px]">Reverted / Inactive</span>
                      )}
                    </td>

                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
