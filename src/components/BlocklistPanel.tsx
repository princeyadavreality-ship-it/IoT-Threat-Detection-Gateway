import React, { useState } from 'react';
import { Ban, ShieldCheck, Check, Copy, Plus } from 'lucide-react';

interface BlocklistPanelProps {
  blocklist: string[];
  onUnblock: (ip: string) => void;
  onManualBlock: (ip: string) => void;
  safetyMode: boolean;
  theme?: 'dark' | 'light';
}

export const BlocklistPanel: React.FC<BlocklistPanelProps> = ({
  blocklist,
  onUnblock,
  onManualBlock,
  safetyMode,
  theme = 'dark',
}) => {
  const [customIp, setCustomIp] = useState('');
  const [copiedIp, setCopiedIp] = useState<string | null>(null);
  const isDark = theme === 'dark';

  const handleAdd = (e: React.FormEvent) => {
    e.preventDefault();
    if (customIp.trim()) {
      onManualBlock(customIp.trim());
      setCustomIp('');
    }
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIp(id);
    setTimeout(() => setCopiedIp(null), 1500);
  };

  return (
    <div className={`border rounded-xl overflow-hidden transition-colors ${
      isDark ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
    }`}>
      
      {/* Header */}
      <div className={`p-3.5 lg:p-4 border-b flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
        isDark ? 'border-[#1C2538] bg-[#121824]' : 'border-slate-200 bg-slate-50'
      }`}>
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-rose-500/10 text-rose-500">
            <Ban className="w-4 h-4" />
          </div>
          <div className="flex items-center gap-2">
            <span className="font-display font-bold text-sm">Active Quarantine Blocklist</span>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold border ${
              isDark ? 'bg-slate-800 text-rose-400 border-slate-700' : 'bg-white text-rose-700 border-slate-200'
            }`}>
              {blocklist.length} Blocked
            </span>
          </div>
        </div>

        {/* Manual IP Addition */}
        <form onSubmit={handleAdd} className="flex items-center gap-2">
          <input
            type="text"
            placeholder="e.g. 192.168.1.15"
            value={customIp}
            onChange={(e) => setCustomIp(e.target.value)}
            className={`px-3 py-1.5 text-xs font-mono rounded-lg border outline-none focus:ring-1 focus:ring-rose-500 w-36 sm:w-44 transition-colors ${
              isDark 
                ? 'bg-[#0B0F17] border-[#222E42] text-slate-200 placeholder-slate-500' 
                : 'bg-white border-slate-300 text-slate-900 placeholder-slate-400'
            }`}
          />
          <button
            type="submit"
            className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-rose-600 hover:bg-rose-700 text-white flex items-center gap-1.5 cursor-pointer transition-colors shadow-xs"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Drop Host</span>
          </button>
        </form>
      </div>

      {/* Blocklist Table or Empty State */}
      {blocklist.length === 0 ? (
        <div className="py-12 text-center text-slate-500">
          <div className={`w-9 h-9 mx-auto mb-2 rounded-lg flex items-center justify-center border ${
            isDark ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' : 'bg-emerald-50 border-emerald-200 text-emerald-600'
          }`}>
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div className="font-semibold text-sm">No Quarantine Drops Enforced</div>
          <div className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
            Gateway firewall policy: all registered IoT nodes currently permitted through the Linux FORWARD chain.
          </div>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className={`border-b text-[11px] font-mono tracking-wider uppercase ${
                isDark ? 'border-[#1C2538] bg-[#0C111C] text-slate-400' : 'border-slate-200 bg-slate-50 text-slate-500'
              }`}>
                <th className="py-2.5 px-3.5 whitespace-nowrap">Isolated IPv4</th>
                <th className="py-2.5 px-3 whitespace-nowrap">iptables Rule Specification</th>
                <th className="py-2.5 px-2.5 whitespace-nowrap">Enforcement</th>
                <th className="py-2.5 pr-4 text-right whitespace-nowrap">Action</th>
              </tr>
            </thead>
            <tbody className={`divide-y ${isDark ? 'divide-[#1C2538]' : 'divide-slate-200'}`}>
              {blocklist.map((ip) => {
                const iptablesCmd = `iptables -A FORWARD -s ${ip} -j DROP && iptables -A INPUT -s ${ip} -j DROP`;
                return (
                  <tr key={ip} className={`transition-colors ${
                    isDark ? 'hover:bg-[#121824]' : 'hover:bg-slate-50'
                  }`}>
                    {/* IP */}
                    <td className="py-3 px-3.5 font-mono text-[11px] font-bold text-rose-400 whitespace-nowrap tabular-nums">
                      {ip}
                    </td>

                    {/* iptables command */}
                    <td className="py-3 px-3 font-mono text-[11px]">
                      <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded border max-w-md overflow-x-auto ${
                        isDark ? 'bg-[#0B0F17] border-[#222E42] text-slate-300' : 'bg-slate-100 border-slate-200 text-slate-800'
                      }`}>
                        <span className="text-rose-500 font-bold select-none">$</span>
                        <span className="truncate">{iptablesCmd}</span>
                        <button
                          onClick={() => handleCopy(iptablesCmd, ip)}
                          className="ml-auto text-slate-400 hover:text-blue-500 shrink-0 cursor-pointer pl-1.5 transition-colors"
                          title="Copy command"
                        >
                          {copiedIp === ip ? (
                            <Check className="w-3 h-3 text-emerald-500" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </td>

                    {/* Kernel Status */}
                    <td className="py-3 px-2.5 font-mono text-[11px] whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded font-bold uppercase text-[10px] border ${
                        safetyMode
                          ? isDark
                            ? 'bg-amber-500/15 text-amber-400 border-amber-500/30'
                            : 'bg-amber-50 text-amber-800 border-amber-200'
                          : isDark
                            ? 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                            : 'bg-rose-50 text-rose-700 border-rose-200'
                      }`}>
                        {safetyMode ? 'DRY-RUN' : 'LIVE KERNEL'}
                      </span>
                    </td>

                    {/* Action */}
                    <td className="py-3 pr-4 text-right whitespace-nowrap">
                      <button
                        onClick={() => onUnblock(ip)}
                        className={`px-2.5 py-1 rounded-md text-[11px] font-semibold border transition-all cursor-pointer ${
                          isDark
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-600 hover:text-white'
                            : 'bg-emerald-50 text-emerald-700 border-emerald-200 hover:bg-emerald-600 hover:text-white'
                        }`}
                      >
                        Lift Quarantine Drop
                      </button>
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
