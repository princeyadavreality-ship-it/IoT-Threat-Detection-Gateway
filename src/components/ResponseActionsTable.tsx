import React, { useState } from 'react';
import { ShieldCheck, Copy, Check, Terminal, Shield } from 'lucide-react';
import { ResponseAction } from '../types';

interface ResponseActionsTableProps {
  actions: ResponseAction[];
  blocklist: string[];
  safetyMode: boolean;
  onUnblock: (ip: string) => void;
  theme?: 'dark' | 'light';
}

export const ResponseActionsTable: React.FC<ResponseActionsTableProps> = ({
  actions,
  blocklist,
  safetyMode,
  onUnblock,
  theme = 'dark',
}) => {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const isDark = theme === 'dark';

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  return (
    <div className={`border rounded-xl overflow-hidden transition-colors ${
      isDark ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
    }`}>
      
      {/* Header Toolbar */}
      <div className={`p-3.5 lg:p-4 border-b flex items-center justify-between ${
        isDark ? 'border-[#1C2538] bg-[#121824]' : 'border-slate-200 bg-slate-50'
      }`}>
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-emerald-500/10 text-emerald-500">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div className="flex items-center gap-2">
            <span className="font-display font-bold text-sm">Response &amp; Containment Ledger</span>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold border ${
              isDark ? 'bg-slate-800 text-emerald-400 border-slate-700' : 'bg-white text-emerald-700 border-slate-200'
            }`}>
              {actions.length} Dispatched
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-slate-400 hidden sm:inline">Execution Mode:</span>
          <span className={`px-2 py-0.5 rounded-md font-semibold text-[11px] border ${
            safetyMode 
              ? isDark
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : 'bg-emerald-50 text-emerald-700 border-emerald-200'
              : isDark
                ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                : 'bg-amber-50 text-amber-800 border-amber-200'
          }`}>
            {safetyMode ? 'Dry-Run Simulation' : 'Live Kernel Active'}
          </span>
        </div>
      </div>

      {/* Table Content */}
      {actions.length === 0 ? (
        <div className="py-10 text-center text-slate-500">
          <div className={`w-9 h-9 mx-auto mb-2 rounded-lg flex items-center justify-center border ${
            isDark ? 'bg-[#141B28] border-[#222E42] text-slate-400' : 'bg-slate-100 border-slate-200 text-slate-500'
          }`}>
            <Terminal className="w-4 h-4" />
          </div>
          <div className="font-semibold text-sm">No Active Mitigations Dispatched</div>
          <div className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
            Deterministic host quarantine rules and iptables drop syntheses will be logged here in real-time.
          </div>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className={`border-b text-[11px] font-mono tracking-wider uppercase ${
                isDark ? 'border-[#1C2538] bg-[#0C111C] text-slate-400' : 'border-slate-200 bg-slate-50 text-slate-500'
              }`}>
                <th className="py-2.5 px-3.5 whitespace-nowrap">Action ID</th>
                <th className="py-2.5 px-2.5 whitespace-nowrap">Policy</th>
                <th className="py-2.5 px-3 whitespace-nowrap">Target Host</th>
                <th className="py-2.5 px-3">Trigger Reason</th>
                <th className="py-2.5 px-3">Kernel Directive</th>
                <th className="py-2.5 px-2.5 whitespace-nowrap">Status</th>
                <th className="py-2.5 pr-4 text-right whitespace-nowrap">Action</th>
              </tr>
            </thead>
            <tbody className={`divide-y ${isDark ? 'divide-[#1C2538]' : 'divide-slate-200'}`}>
              {actions.slice().reverse().map((act) => {
                const isBlocked = blocklist.includes(act.targetIp);
                return (
                  <tr key={act.id} className={`transition-colors ${
                    isDark ? 'hover:bg-[#121824]' : 'hover:bg-slate-50'
                  }`}>
                    {/* Action ID */}
                    <td className="py-2.5 px-3.5 font-mono text-[11px] text-slate-400 whitespace-nowrap tabular-nums">
                      {act.id}
                    </td>

                    {/* Policy Badge */}
                    <td className="py-2.5 px-2.5 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold uppercase border ${
                        act.action === 'ISOLATE'
                          ? isDark
                            ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                            : 'bg-rose-50 text-rose-700 border-rose-200'
                          : isDark
                            ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                            : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      }`}>
                        {act.action}
                      </span>
                    </td>

                    {/* Target IP */}
                    <td className="py-2.5 px-3 font-mono font-semibold text-rose-400 whitespace-nowrap tabular-nums">
                      {act.targetIp}
                    </td>

                    {/* Reason */}
                    <td className="py-2.5 px-3 text-slate-300 max-w-xs truncate">
                      {act.reason}
                    </td>

                    {/* Monospace Code Block */}
                    <td className="py-2.5 px-3 font-mono text-[11px]">
                      <div className={`flex items-center gap-1.5 px-2 py-1 rounded border max-w-xs sm:max-w-sm overflow-x-auto ${
                        isDark ? 'bg-[#0B0F17] border-[#222E42] text-slate-200' : 'bg-slate-100 border-slate-200 text-slate-800'
                      }`}>
                        <span className="text-emerald-500 select-none font-bold">$</span>
                        <span className="truncate">{act.iptablesCommand}</span>
                        <button
                          onClick={() => handleCopy(act.iptablesCommand, act.id)}
                          className="ml-auto text-slate-400 hover:text-blue-500 shrink-0 cursor-pointer pl-1.5 transition-colors"
                          title="Copy command to clipboard"
                        >
                          {copiedId === act.id ? (
                            <Check className="w-3 h-3 text-emerald-500" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </td>

                    {/* Mode */}
                    <td className="py-2.5 px-2.5 font-mono text-[11px] whitespace-nowrap">
                      <span className={`font-semibold ${act.executedLive ? 'text-amber-500' : 'text-emerald-500'}`}>
                        {act.executedLive ? 'LIVE' : 'SIM'}
                      </span>
                    </td>

                    {/* Revoke Control */}
                    <td className="py-2.5 pr-4 text-right whitespace-nowrap">
                      {isBlocked ? (
                        <button
                          onClick={() => onUnblock(act.targetIp)}
                          className={`px-2.5 py-1 rounded-md text-[11px] font-semibold border transition-all cursor-pointer ${
                            isDark
                              ? 'bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700'
                              : 'bg-slate-100 hover:bg-slate-200 text-slate-700 border-slate-200'
                          }`}
                        >
                          Revoke Drop
                        </button>
                      ) : (
                        <span className="font-mono text-[11px] text-slate-400">Released</span>
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
