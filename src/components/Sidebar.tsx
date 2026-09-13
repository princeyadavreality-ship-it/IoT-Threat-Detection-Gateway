import React from 'react';
import { 
  Activity, 
  ShieldAlert, 
  Cpu, 
  Ban, 
  Sliders, 
  Terminal, 
  Layers, 
  Radio, 
  Crosshair,
  Server,
  Network,
  Lock,
  CpuIcon
} from 'lucide-react';

export type NavTab = 'radar' | 'overview' | 'alerts' | 'devices' | 'blocklist' | 'traffic' | 'topology' | 'settings' | 'python';

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  alertCount: number;
  blocklistCount: number;
  deviceCount: number;
  isSimulating: boolean;
  onOpenAttackDrawer: () => void;
  theme?: 'dark' | 'light';
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  alertCount,
  blocklistCount,
  deviceCount,
  isSimulating,
  onOpenAttackDrawer,
  theme = 'dark',
}) => {
  const isDark = theme === 'dark';

  const navSections: {
    title: string;
    items: {
      id: NavTab;
      label: string;
      icon: React.ComponentType<{ className?: string }>;
      badge?: number | string;
      badgeVariant?: 'danger' | 'warning' | 'neutral' | 'success';
    }[];
  }[] = [
    {
      title: 'OPERATIONS & DEFENSE',
      items: [
        { 
          id: 'radar', 
          label: 'Tactical Radar', 
          icon: Radio,
          badge: 'HUD',
          badgeVariant: 'neutral'
        },
        { 
          id: 'overview', 
          label: 'Security Overview', 
          icon: Layers 
        },
        { 
          id: 'alerts', 
          label: 'Incident Alerts', 
          icon: ShieldAlert,
          badge: alertCount > 0 ? alertCount : undefined,
          badgeVariant: alertCount > 0 ? 'danger' : 'neutral'
        },
        { 
          id: 'blocklist', 
          label: 'Quarantine Ledger', 
          icon: Ban,
          badge: blocklistCount > 0 ? blocklistCount : undefined,
          badgeVariant: blocklistCount > 0 ? 'warning' : 'neutral'
        },
      ],
    },
    {
      title: 'FLEET & TELEMETRY',
      items: [
        { 
          id: 'devices', 
          label: 'IoT Inventory', 
          icon: Cpu,
          badge: deviceCount,
          badgeVariant: 'success'
        },
        { 
          id: 'traffic', 
          label: 'Live Packet Terminal', 
          icon: Activity 
        },
        { 
          id: 'topology', 
          label: 'Network Topology', 
          icon: Network 
        },
      ],
    },
    {
      title: 'CONFIGURATION',
      items: [
        { 
          id: 'settings', 
          label: 'Defense Policies', 
          icon: Sliders 
        },
        { 
          id: 'python', 
          label: 'FastAPI Daemon', 
          icon: Terminal 
        },
      ],
    },
  ];

  const getBadgeStyle = (variant?: 'danger' | 'warning' | 'neutral' | 'success') => {
    switch (variant) {
      case 'danger':
        return isDark
          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
          : 'bg-rose-100 text-rose-700 border border-rose-200';
      case 'warning':
        return isDark
          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
          : 'bg-amber-100 text-amber-800 border border-amber-200';
      case 'success':
        return isDark
          ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
          : 'bg-emerald-100 text-emerald-800 border border-emerald-200';
      case 'neutral':
      default:
        return isDark
          ? 'bg-slate-800 text-slate-300 border border-slate-700'
          : 'bg-slate-100 text-slate-600 border border-slate-200';
    }
  };

  return (
    <aside className={`w-64 shrink-0 flex flex-col justify-between select-none z-10 transition-colors border-r ${
      isDark 
        ? 'bg-[#0E131E] border-[#1C2433] text-[#F1F5F9]' 
        : 'bg-[#FBFCFD] border-slate-200 text-slate-800'
    }`}>
      
      {/* Top Nav Sections */}
      <div className="p-3.5 space-y-5 overflow-y-auto">
        {navSections.map((section) => (
          <div key={section.title} className="space-y-1">
            <div className={`px-3 text-[10px] font-semibold tracking-wider font-mono uppercase ${
              isDark ? 'text-slate-500' : 'text-slate-400'
            }`}>
              {section.title}
            </div>

            <div className="space-y-0.5">
              {section.items.map((item) => {
                const isActive = currentTab === item.id;
                const IconComponent = item.icon;
                return (
                  <button
                    key={item.id}
                    id={`sidebar-nav-${item.id}`}
                    onClick={() => onSelectTab(item.id)}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all cursor-pointer ${
                      isActive
                        ? isDark
                          ? 'bg-[#1C2538] text-blue-400 font-semibold shadow-xs ring-1 ring-white/10'
                          : 'bg-blue-50 text-blue-700 font-semibold shadow-xs ring-1 ring-blue-500/20'
                        : isDark
                          ? 'text-slate-400 hover:text-slate-200 hover:bg-[#151C2A]'
                          : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 truncate">
                      <IconComponent className={`w-4 h-4 shrink-0 ${
                        isActive 
                          ? isDark ? 'text-blue-400' : 'text-blue-600'
                          : isDark ? 'text-slate-400' : 'text-slate-500'
                      }`} />
                      <span className="truncate">{item.label}</span>
                    </div>

                    {item.badge !== undefined && (
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-medium tracking-tight ${getBadgeStyle(item.badgeVariant)}`}>
                        {item.badge}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Gateway Hardware Telemetry Footer */}
      <div className={`p-3.5 border-t transition-colors ${
        isDark ? 'border-[#1C2433] bg-[#0A0D15]' : 'border-slate-200 bg-slate-50'
      }`}>
        {/* Node Health Metrics */}
        <div className="space-y-2 mb-3">
          <div className="flex items-center justify-between text-[11px]">
            <span className={`flex items-center gap-1.5 ${isDark ? 'text-slate-400' : 'text-slate-500'}`}>
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>Kernel Filtering</span>
            </span>
            <span className="font-mono text-[10px] font-semibold text-blue-500">
              eBPF / IPTABLES
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2 text-[10px] font-mono">
            <div className={`p-1.5 rounded border ${
              isDark ? 'bg-[#111724] border-[#1C2433] text-slate-300' : 'bg-white border-slate-200 text-slate-700'
            }`}>
              <div className="text-slate-500 text-[9px]">CPU LOAD</div>
              <div className="font-bold text-emerald-500">14.2%</div>
            </div>
            <div className={`p-1.5 rounded border ${
              isDark ? 'bg-[#111724] border-[#1C2433] text-slate-300' : 'bg-white border-slate-200 text-slate-700'
            }`}>
              <div className="text-slate-500 text-[9px]">MEM USAGE</div>
              <div className="font-bold text-blue-400">388 MB</div>
            </div>
          </div>
        </div>

        {/* Quick Simulator Launcher Button */}
        <button
          id="sidebar-attack-drawer-btn"
          onClick={onOpenAttackDrawer}
          className={`w-full py-2 px-3 rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-all cursor-pointer border shadow-xs ${
            isDark
              ? 'bg-[#141B29] hover:bg-blue-600 hover:text-white text-slate-300 border-[#222E42] hover:border-blue-500'
              : 'bg-white hover:bg-blue-600 hover:text-white text-slate-700 border-slate-200 hover:border-blue-500'
          }`}
        >
          <Crosshair className="w-3.5 h-3.5 text-blue-500" />
          <span>Red Team Testing</span>
        </button>
      </div>

    </aside>
  );
};
