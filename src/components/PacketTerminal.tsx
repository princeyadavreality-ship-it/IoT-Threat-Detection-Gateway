import React, { useState } from 'react';
import { Terminal, Search, Pause, Play, Trash2 } from 'lucide-react';
import { Packet } from '../types';

interface PacketTerminalProps {
  packets: Packet[];
  onClear: () => void;
  isPaused: boolean;
  onTogglePause: () => void;
  theme?: 'dark' | 'light';
}

export const PacketTerminal: React.FC<PacketTerminalProps> = ({
  packets,
  onClear,
  isPaused,
  onTogglePause,
  theme = 'dark',
}) => {
  const [filterText, setFilterText] = useState('');
  const [threatOnly, setThreatOnly] = useState(false);
  const isDark = theme === 'dark';

  const filtered = packets.filter((p) => {
    if (threatOnly && !p.isAttack) return false;
    if (!filterText) return true;
    const q = filterText.toLowerCase();
    return (
      p.srcIp.toLowerCase().includes(q) ||
      p.dstIp.toLowerCase().includes(q) ||
      p.protocol.toLowerCase().includes(q) ||
      p.payloadInfo.toLowerCase().includes(q) ||
      (p.attackType && p.attackType.toLowerCase().includes(q))
    );
  });

  return (
    <div className={`border rounded-xl overflow-hidden flex flex-col h-[650px] transition-colors ${
      isDark ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
    }`}>
      
      {/* Terminal Toolbar */}
      <div className={`p-3.5 lg:p-4 border-b flex flex-wrap items-center justify-between gap-3 shrink-0 ${
        isDark ? 'border-[#1C2538] bg-[#121824]' : 'border-slate-200 bg-slate-50'
      }`}>
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-blue-500/10 text-blue-500">
            <Terminal className="w-4 h-4" />
          </div>
          <div className="flex items-center gap-2">
            <span className="font-display font-bold text-sm">Stateful Packet Inspection Tail</span>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold border ${
              isDark ? 'bg-slate-800 text-blue-400 border-slate-700' : 'bg-white text-blue-700 border-slate-200'
            }`}>
              {packets.length} Frames
            </span>
          </div>
        </div>

        {/* Filters and Controls */}
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Filter port or IP..."
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
              className={`pl-8 pr-3 py-1.5 text-xs font-mono rounded-lg border outline-none focus:ring-1 focus:ring-blue-500 w-44 transition-colors ${
                isDark 
                  ? 'bg-[#0B0F17] border-[#222E42] text-slate-200 placeholder-slate-500' 
                  : 'bg-white border-slate-300 text-slate-900 placeholder-slate-400'
              }`}
            />
          </div>

          <label className={`flex items-center gap-1.5 text-xs cursor-pointer select-none px-2.5 py-1.5 rounded-lg border transition-colors ${
            isDark 
              ? 'bg-[#0B0F17] border-[#222E42] text-slate-300 hover:border-blue-500/40' 
              : 'bg-white border-slate-200 text-slate-700 hover:border-blue-300'
          }`}>
            <input
              type="checkbox"
              checked={threatOnly}
              onChange={(e) => setThreatOnly(e.target.checked)}
              className="rounded accent-blue-600 cursor-pointer"
            />
            <span className={threatOnly ? 'text-rose-500 font-bold' : ''}>
              Threats Only
            </span>
          </label>

          <button
            onClick={onTogglePause}
            className={`px-3 py-1.5 rounded-lg border flex items-center gap-1.5 text-xs font-semibold cursor-pointer transition-colors ${
              isPaused
                ? isDark
                  ? 'bg-amber-500/15 text-amber-400 border-amber-500/40'
                  : 'bg-amber-50 text-amber-800 border-amber-200'
                : isDark
                  ? 'bg-[#0B0F17] text-slate-300 border-[#222E42] hover:text-white'
                  : 'bg-white text-slate-700 border-slate-200 hover:text-slate-900'
            }`}
          >
            {isPaused ? <Play className="w-3.5 h-3.5 text-amber-500" /> : <Pause className="w-3.5 h-3.5" />}
            <span>{isPaused ? 'Resume' : 'Pause'}</span>
          </button>

          <button
            onClick={onClear}
            className={`p-2 rounded-lg border transition-all cursor-pointer ${
              isDark
                ? 'bg-[#0B0F17] border-[#222E42] text-slate-400 hover:text-rose-400'
                : 'bg-white border-slate-200 text-slate-500 hover:text-rose-600'
            }`}
            title="Clear buffer"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Scrolling Stream Window */}
      <div className={`flex-1 overflow-y-auto font-mono text-[11px] select-text ${
        isDark ? 'bg-[#0B0F17] text-slate-300' : 'bg-white text-slate-800'
      }`}>
        <table className="w-full text-left border-collapse">
          <thead className={`sticky top-0 border-b text-[10px] uppercase font-semibold ${
            isDark ? 'bg-[#101622] border-[#1C2538] text-slate-400' : 'bg-slate-50 border-slate-200 text-slate-500'
          }`}>
            <tr>
              <th className="py-2.5 px-3.5 whitespace-nowrap">Timestamp</th>
              <th className="py-2.5 px-2 whitespace-nowrap">Proto</th>
              <th className="py-2.5 px-3 whitespace-nowrap">Source Host : Port</th>
              <th className="py-2.5 px-3 whitespace-nowrap">Target Node : Port</th>
              <th className="py-2.5 px-2 whitespace-nowrap">Len</th>
              <th className="py-2.5 px-2 whitespace-nowrap">Flags</th>
              <th className="py-2.5 px-3">Payload Telemetry</th>
              <th className="py-2.5 pr-4 text-right whitespace-nowrap">Verdict</th>
            </tr>
          </thead>
          <tbody className={`divide-y ${isDark ? 'divide-[#1C2538]/60' : 'divide-slate-200'}`}>
            {filtered.slice(-150).reverse().map((pkt) => {
              const d = new Date(pkt.timestamp);
              const timeStr = `${d.toISOString().slice(11, 19)}.${String(d.getMilliseconds()).padStart(3, '0')}`;

              return (
                <tr
                  key={pkt.id}
                  className={`transition-colors ${
                    pkt.isAttack 
                      ? isDark
                        ? 'bg-rose-500/10 text-rose-300 font-semibold hover:bg-rose-500/15'
                        : 'bg-rose-50 text-rose-800 font-semibold hover:bg-rose-100'
                      : isDark
                        ? 'hover:bg-[#121824] text-slate-300'
                        : 'hover:bg-slate-50 text-slate-700'
                  }`}
                >
                  <td className="py-1.5 px-3.5 text-slate-400 whitespace-nowrap tabular-nums">
                    {timeStr}
                  </td>

                  <td className="py-1.5 px-2 whitespace-nowrap">
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono border font-semibold ${
                      isDark 
                        ? 'border-[#222E42] bg-[#141B28] text-blue-400' 
                        : 'border-blue-200 bg-blue-50 text-blue-700'
                    }`}>
                      {pkt.protocol}
                    </span>
                  </td>

                  <td className="py-1.5 px-3 whitespace-nowrap tabular-nums font-semibold text-blue-400">
                    {pkt.srcIp}:{pkt.srcPort}
                  </td>

                  <td className="py-1.5 px-3 whitespace-nowrap tabular-nums">
                    {pkt.dstIp}:{pkt.dstPort}
                  </td>

                  <td className="py-1.5 px-2 whitespace-nowrap tabular-nums text-slate-400">
                    {pkt.length}B
                  </td>

                  <td className="py-1.5 px-2 whitespace-nowrap text-slate-400 text-[10px]">
                    {pkt.flags}
                  </td>

                  <td className="py-1.5 px-3 truncate max-w-xs text-slate-400">
                    {pkt.payloadInfo}
                  </td>

                  <td className="py-1.5 pr-4 text-right whitespace-nowrap">
                    {pkt.isAttack ? (
                      <span className={`px-2 py-0.5 rounded font-mono text-[9px] font-bold tracking-wider uppercase border ${
                        isDark 
                          ? 'bg-rose-500/20 text-rose-400 border-rose-500/40' 
                          : 'bg-rose-100 text-rose-800 border-rose-300'
                      }`}>
                        {pkt.attackType || 'ATTACK'}
                      </span>
                    ) : (
                      <span className={`px-2 py-0.5 rounded font-mono text-[9px] font-medium tracking-wider uppercase border ${
                        isDark 
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' 
                          : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      }`}>
                        PASS
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

    </div>
  );
};
