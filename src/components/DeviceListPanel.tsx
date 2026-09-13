import React, { useState } from 'react';
import { Cpu, Lock, Camera, Plug, Thermometer, Search, ShieldCheck, Ban } from 'lucide-react';
import { IoTDevice } from '../types';

interface DeviceListPanelProps {
  devices: IoTDevice[];
  onToggleIsolate: (ip: string) => void;
  blocklist: string[];
  theme?: 'dark' | 'light';
}

export const DeviceListPanel: React.FC<DeviceListPanelProps> = ({
  devices,
  onToggleIsolate,
  blocklist,
  theme = 'dark',
}) => {
  const [filterText, setFilterText] = useState('');
  const isDark = theme === 'dark';

  const getDeviceIcon = (type: string) => {
    switch (type) {
      case 'Security Camera':
        return <Camera className="w-4 h-4 text-blue-500" />;
      case 'Access Control':
        return <Lock className="w-4 h-4 text-emerald-500" />;
      case 'Environment Sensor':
        return <Thermometer className="w-4 h-4 text-emerald-500" />;
      case 'Power Controller':
        return <Plug className="w-4 h-4 text-amber-500" />;
      case 'Climate Control':
      default:
        return <Cpu className="w-4 h-4 text-purple-500" />;
    }
  };

  const filtered = devices.filter((d) => {
    if (!filterText) return true;
    const q = filterText.toLowerCase();
    return (
      d.name.toLowerCase().includes(q) ||
      d.ip.toLowerCase().includes(q) ||
      d.mac.toLowerCase().includes(q) ||
      d.deviceType.toLowerCase().includes(q)
    );
  });

  return (
    <div className={`border rounded-xl overflow-hidden transition-colors ${
      isDark ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
    }`}>
      
      {/* Panel Header */}
      <div className={`p-3.5 lg:p-4 border-b flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
        isDark ? 'border-[#1C2538] bg-[#121824]' : 'border-slate-200 bg-slate-50'
      }`}>
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-blue-500/10 text-blue-500">
            <Cpu className="w-4 h-4" />
          </div>
          <div className="flex items-center gap-2">
            <span className="font-display font-bold text-sm">Subnet Device Inventory</span>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold border ${
              isDark ? 'bg-slate-800 text-blue-400 border-slate-700' : 'bg-white text-blue-700 border-slate-200'
            }`}>
              {devices.length} Nodes
            </span>
          </div>
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Filter hostname, IP, MAC..."
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            className={`pl-8 pr-3 py-1.5 text-xs font-mono rounded-lg border outline-none focus:ring-1 focus:ring-blue-500 w-52 transition-colors ${
              isDark 
                ? 'bg-[#0B0F17] border-[#222E42] text-slate-200 placeholder-slate-500' 
                : 'bg-white border-slate-300 text-slate-900 placeholder-slate-400'
            }`}
          />
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className={`border-b text-[11px] font-mono tracking-wider uppercase ${
              isDark ? 'border-[#1C2538] bg-[#0C111C] text-slate-400' : 'border-slate-200 bg-slate-50 text-slate-500'
            }`}>
              <th className="py-2.5 px-3.5 whitespace-nowrap">Device Hostname</th>
              <th className="py-2.5 px-3 whitespace-nowrap">IPv4 Address</th>
              <th className="py-2.5 px-3 whitespace-nowrap">Hardware MAC</th>
              <th className="py-2.5 px-3 whitespace-nowrap">Standard Protocols</th>
              <th className="py-2.5 px-3 whitespace-nowrap">Open Ports</th>
              <th className="py-2.5 px-3 whitespace-nowrap">Telemetry</th>
              <th className="py-2.5 px-2.5 whitespace-nowrap">Policy Status</th>
              <th className="py-2.5 pr-4 text-right whitespace-nowrap">Firewall Action</th>
            </tr>
          </thead>
          <tbody className={`divide-y ${isDark ? 'divide-[#1C2538]' : 'divide-slate-200'}`}>
            {filtered.map((dev) => {
              const isBlocked = blocklist.includes(dev.ip);

              return (
                <tr key={dev.id} className={`transition-colors ${
                  isDark ? 'hover:bg-[#121824]' : 'hover:bg-slate-50'
                }`}>
                  
                  {/* Device Name */}
                  <td className="py-3 px-3.5">
                    <div className="flex items-center gap-2.5">
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center border shrink-0 ${
                        isDark ? 'bg-[#141B28] border-[#222E42]' : 'bg-slate-100 border-slate-200'
                      }`}>
                        {getDeviceIcon(dev.deviceType)}
                      </div>
                      <div>
                        <div className="font-semibold text-xs leading-tight">{dev.name}</div>
                        <div className="text-[11px] text-slate-400">{dev.deviceType}</div>
                      </div>
                    </div>
                  </td>

                  {/* IP */}
                  <td className="py-3 px-3 font-mono text-[11px] font-bold text-blue-500 whitespace-nowrap tabular-nums">
                    {dev.ip}
                  </td>

                  {/* MAC */}
                  <td className="py-3 px-3 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                    {dev.mac}
                  </td>

                  {/* Baseline Protocols */}
                  <td className="py-3 px-3">
                    <div className="flex flex-wrap gap-1">
                      {dev.normalProtocols.map((p) => (
                        <span 
                          key={p} 
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-medium uppercase border ${
                            isDark 
                              ? 'bg-[#141B28] border-[#222E42] text-slate-300' 
                              : 'bg-slate-100 border-slate-200 text-slate-700'
                          }`}
                        >
                          {p}
                        </span>
                      ))}
                    </div>
                  </td>

                  {/* Normal Ports */}
                  <td className="py-3 px-3 font-mono text-[11px] text-slate-400 tabular-nums">
                    {dev.normalPorts.join(', ')}
                  </td>

                  {/* Telemetry Volume */}
                  <td className="py-3 px-3 font-mono text-[11px] whitespace-nowrap tabular-nums">
                    <div className="font-medium">{dev.packetsSent} pkts</div>
                    <div className="text-slate-400 text-[10px]">{(dev.bytesTotal / 1024).toFixed(1)} KB</div>
                  </td>

                  {/* Policy State */}
                  <td className="py-3 px-2.5 whitespace-nowrap">
                    {isBlocked ? (
                      <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold uppercase border ${
                        isDark 
                          ? 'bg-rose-500/15 text-rose-400 border-rose-500/30' 
                          : 'bg-rose-50 text-rose-700 border-rose-200'
                      }`}>
                        Quarantined
                      </span>
                    ) : (
                      <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-medium uppercase border ${
                        isDark 
                          ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' 
                          : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      }`}>
                        Monitored
                      </span>
                    )}
                  </td>

                  {/* Firewall Action */}
                  <td className="py-3 pr-4 text-right whitespace-nowrap">
                    <button
                      onClick={() => onToggleIsolate(dev.ip)}
                      className={`px-2.5 py-1 rounded-md text-[11px] font-semibold border transition-all cursor-pointer ${
                        isBlocked
                          ? isDark
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-600 hover:text-white'
                            : 'bg-emerald-50 text-emerald-700 border-emerald-200 hover:bg-emerald-600 hover:text-white'
                          : isDark
                            ? 'bg-rose-500/10 text-rose-300 border-rose-500/30 hover:bg-rose-600 hover:text-white'
                            : 'bg-rose-50 text-rose-700 border-rose-200 hover:bg-rose-600 hover:text-white'
                      }`}
                    >
                      {isBlocked ? 'Lift Drop' : 'Isolate Node'}
                    </button>
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
