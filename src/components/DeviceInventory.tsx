import React from 'react';
import { Camera, Lock, Cpu, Plug, Thermometer, ShieldAlert, CheckCircle, Ban } from 'lucide-react';
import { IoTDevice } from '../types';

interface DeviceInventoryProps {
  devices: IoTDevice[];
  onToggleIsolate: (ip: string) => void;
  blocklist: string[];
}

export const DeviceInventory: React.FC<DeviceInventoryProps> = ({
  devices,
  onToggleIsolate,
  blocklist,
}) => {
  const getDeviceIcon = (type: string) => {
    switch (type) {
      case 'Security Camera':
        return <Camera className="w-4 h-4 text-blue-400" />;
      case 'Access Control':
        return <Lock className="w-4 h-4 text-amber-400" />;
      case 'Environment Sensor':
        return <Thermometer className="w-4 h-4 text-emerald-400" />;
      case 'Power Controller':
        return <Plug className="w-4 h-4 text-purple-400" />;
      case 'Climate Control':
      default:
        return <Cpu className="w-4 h-4 text-cyan-400" />;
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <div className="flex items-center justify-between pb-3.5 mb-4 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Cpu className="w-4 h-4 text-blue-400" />
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">
            Monitored IoT Devices (5 Nodes Active)
          </h2>
        </div>
        <span className="text-xs text-slate-400 font-mono">
          Subnet: 192.168.1.10 - 192.168.1.14
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400 font-semibold">
              <th className="pb-3 pr-4">Device Identity</th>
              <th className="pb-3 px-3">IP Address</th>
              <th className="pb-3 px-3">MAC Address</th>
              <th className="pb-3 px-3">Allowed Protocols</th>
              <th className="pb-3 px-3">Traffic Vol</th>
              <th className="pb-3 px-3">Hardening Status</th>
              <th className="pb-3 pl-3 text-right">Manual Control</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {devices.map((device) => {
              const isBlocked = blocklist.includes(device.ip);
              return (
                <tr key={device.id} className="hover:bg-slate-800/30 transition-colors">
                  
                  {/* Name and Icon */}
                  <td className="py-3.5 pr-4">
                    <div className="flex items-center gap-2.5">
                      <div className="w-8 h-8 rounded-lg bg-slate-800 border border-slate-700/80 flex items-center justify-center shrink-0">
                        {getDeviceIcon(device.deviceType)}
                      </div>
                      <div>
                        <div className="font-semibold text-white">{device.name}</div>
                        <div className="text-[11px] text-slate-400">{device.deviceType}</div>
                      </div>
                    </div>
                  </td>

                  {/* IP */}
                  <td className="py-3.5 px-3 font-mono font-medium text-slate-200">
                    {device.ip}
                  </td>

                  {/* MAC */}
                  <td className="py-3.5 px-3 font-mono text-slate-400">
                    {device.mac}
                  </td>

                  {/* Protocols and Ports */}
                  <td className="py-3.5 px-3">
                    <div className="flex flex-wrap gap-1">
                      {device.normalProtocols.map((p) => (
                        <span key={p} className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px] border border-slate-700">
                          {p}
                        </span>
                      ))}
                      <span className="text-[10px] text-slate-500 font-mono py-0.5">
                        :{device.normalPorts.join(',')}
                      </span>
                    </div>
                  </td>

                  {/* Traffic Stats */}
                  <td className="py-3.5 px-3 font-mono text-slate-300">
                    <div>{device.packetsSent + device.packetsReceived} pkts</div>
                    <div className="text-[10px] text-slate-500">
                      {Math.round(device.bytesTotal / 1024)} KB
                    </div>
                  </td>

                  {/* Status Badge */}
                  <td className="py-3.5 px-3">
                    {isBlocked ? (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-bold bg-rose-500/15 text-rose-300 border border-rose-500/30">
                        <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                        <span>ISOLATED (DROPPED)</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                        <span>MONITORED (ONLINE)</span>
                      </span>
                    )}
                  </td>

                  {/* Action Toggle */}
                  <td className="py-3.5 pl-3 text-right">
                    <button
                      id={`toggle-device-isolate-${device.id}`}
                      onClick={() => onToggleIsolate(device.ip)}
                      className={`px-3 py-1 rounded-lg text-xs font-semibold border transition-all cursor-pointer inline-flex items-center gap-1.5 ${
                        isBlocked
                          ? 'bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border-blue-500/30'
                          : 'bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border-rose-500/20'
                      }`}
                    >
                      {isBlocked ? (
                        <>
                          <CheckCircle className="w-3 h-3 text-blue-400" />
                          <span>Lift Quarantine</span>
                        </>
                      ) : (
                        <>
                          <Ban className="w-3 h-3 text-rose-400" />
                          <span>Manual Isolate</span>
                        </>
                      )}
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
