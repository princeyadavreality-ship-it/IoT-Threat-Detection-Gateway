import React, { useState } from 'react';
import { Terminal, Filter, ShieldAlert, CheckCircle2, Pause, Play, Trash2 } from 'lucide-react';
import { Packet } from '../types';

interface PacketStreamProps {
  packets: Packet[];
  onClearPackets: () => void;
  isPaused: boolean;
  onTogglePause: () => void;
}

export const PacketStream: React.FC<PacketStreamProps> = ({
  packets,
  onClearPackets,
  isPaused,
  onTogglePause,
}) => {
  const [filterText, setFilterText] = useState('');
  const [onlyAttacks, setOnlyAttacks] = useState(false);

  const filteredPackets = packets.filter((pkt) => {
    if (onlyAttacks && !pkt.isAttack) return false;
    if (filterText) {
      const q = filterText.toLowerCase();
      return (
        pkt.srcIp.toLowerCase().includes(q) ||
        pkt.dstIp.toLowerCase().includes(q) ||
        pkt.protocol.toLowerCase().includes(q) ||
        pkt.payloadInfo.toLowerCase().includes(q) ||
        (pkt.attackType && pkt.attackType.toLowerCase().includes(q))
      );
    }
    return true;
  });

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3.5 mb-4 border-b border-slate-800 gap-3">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-emerald-400" />
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">
            Live Packet Inspection Feed ({packets.length} Total Captured)
          </h2>
        </div>

        {/* Controls and Search */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <input
            type="text"
            placeholder="Filter by IP, protocol, payload..."
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            className="px-2.5 py-1 rounded bg-slate-950 border border-slate-700 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500 text-xs font-mono"
          />

          <label className="flex items-center gap-1.5 text-slate-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={onlyAttacks}
              onChange={(e) => setOnlyAttacks(e.target.checked)}
              className="rounded bg-slate-800 border-slate-700 text-rose-500 focus:ring-0"
            />
            <span>Threats Only</span>
          </label>

          <button
            onClick={onTogglePause}
            className={`px-2.5 py-1 rounded border flex items-center gap-1 font-semibold transition-colors cursor-pointer ${
              isPaused
                ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                : 'bg-slate-800 text-slate-300 border-slate-700 hover:border-slate-600'
            }`}
          >
            {isPaused ? <Play className="w-3 h-3 text-amber-400" /> : <Pause className="w-3 h-3" />}
            <span>{isPaused ? 'Resume' : 'Pause'}</span>
          </button>

          <button
            onClick={onClearPackets}
            className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 cursor-pointer"
            title="Clear buffer"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div className="overflow-x-auto max-h-[500px] overflow-y-auto font-mono text-xs border border-slate-800/80 rounded-lg bg-slate-950/90">
        <table className="w-full text-left border-collapse">
          <thead className="bg-slate-900 sticky top-0 border-b border-slate-800 text-slate-400">
            <tr>
              <th className="py-2 px-3">Time</th>
              <th className="py-2 px-2">Proto</th>
              <th className="py-2 px-3">Source IP : Port</th>
              <th className="py-2 px-3">Destination IP : Port</th>
              <th className="py-2 px-2">Len</th>
              <th className="py-2 px-2">Flags</th>
              <th className="py-2 px-3">Payload Summary</th>
              <th className="py-2 px-3 text-right">Class</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/40 text-[11px]">
            {filteredPackets.slice(-100).reverse().map((pkt) => {
              return (
                <tr
                  key={pkt.id}
                  className={`hover:bg-slate-800/30 transition-colors ${
                    pkt.isAttack ? 'bg-rose-950/20 text-rose-200' : 'text-slate-300'
                  }`}
                >
                  <td className="py-2 px-3 text-slate-500 whitespace-nowrap">
                    {new Date(pkt.timestamp).toLocaleTimeString()}.{Math.floor(pkt.timestamp % 1000)}
                  </td>
                  <td className="py-2 px-2">
                    <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                      pkt.protocol === 'MQTT' ? 'bg-purple-900/60 text-purple-300' :
                      pkt.protocol === 'HTTPS' ? 'bg-emerald-900/60 text-emerald-300' :
                      pkt.protocol === 'HTTP' ? 'bg-blue-900/60 text-blue-300' :
                      'bg-slate-800 text-slate-300'
                    }`}>
                      {pkt.protocol}
                    </span>
                  </td>
                  <td className="py-2 px-3 text-slate-300 whitespace-nowrap">
                    {pkt.srcIp}:{pkt.srcPort}
                  </td>
                  <td className="py-2 px-3 text-slate-300 whitespace-nowrap">
                    {pkt.dstIp}:{pkt.dstPort}
                  </td>
                  <td className="py-2 px-2 text-slate-400">
                    {pkt.length}B
                  </td>
                  <td className="py-2 px-2 text-slate-500">
                    {pkt.flags || '-'}
                  </td>
                  <td className="py-2 px-3 truncate max-w-xs text-slate-300">
                    {pkt.payloadInfo}
                    {pkt.authSuccess === false && (
                      <span className="ml-1 text-rose-400 font-bold">[AUTH_FAIL]</span>
                    )}
                  </td>
                  <td className="py-2 px-3 text-right whitespace-nowrap">
                    {pkt.isAttack ? (
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                        {pkt.attackType || 'ATTACK'}
                      </span>
                    ) : (
                      <span className="text-[10px] text-emerald-400 font-medium">
                        BENIGN
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
