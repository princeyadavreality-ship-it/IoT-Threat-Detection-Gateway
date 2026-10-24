import React, { useState, useRef, useEffect, useCallback, useMemo } from 'react';
import {
  Radio,
  Server,
  Laptop,
  Lock,
  Camera,
  Plug,
  Thermometer,
  Cpu,
  Globe,
  Ban,
  ShieldCheck,
  Shield,
  Network,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Minimize2,
  RotateCcw,
  Crosshair,
  Search,
  Layers,
  AlertTriangle,
  Activity,
  HardDrive,
  Eye,
  Sliders,
  CheckCircle2,
  X,
  Compass,
  Move,
  Info,
  ShieldAlert
} from 'lucide-react';
import { IoTDevice, ThreatAlert, ProtocolType } from '../types';

interface TopologyPanelProps {
  devices: IoTDevice[];
  blocklist: string[];
  recentAlerts: ThreatAlert[];
  onToggleIsolate: (ip: string) => void;
  theme?: 'dark' | 'light';
}

// Enterprise extension nodes to test large IoT network deployments
const ENTERPRISE_EXTRA_DEVICES: IoTDevice[] = [
  {
    id: 'cam-east-02',
    name: 'Perimeter Dome Cam #2',
    ip: '192.168.1.51',
    mac: '00:1E:67:B1:00:51',
    deviceType: 'Security Camera',
    normalDestinations: ['192.168.1.1', '52.14.99.102'],
    normalPorts: [554, 443],
    normalProtocols: ['TCP', 'HTTPS'],
    status: 'ONLINE',
    packetsSent: 680,
    packetsReceived: 620,
    bytesTotal: 840000,
    lastSeen: Date.now(),
  },
  {
    id: 'cam-dock-03',
    name: 'Loading Dock Camera #3',
    ip: '192.168.1.52',
    mac: '00:1E:67:B1:00:52',
    deviceType: 'Security Camera',
    normalDestinations: ['192.168.1.1', '52.14.99.102'],
    normalPorts: [554, 443],
    normalProtocols: ['TCP', 'HTTPS'],
    status: 'ONLINE',
    packetsSent: 540,
    packetsReceived: 490,
    bytesTotal: 720000,
    lastSeen: Date.now(),
  },
  {
    id: 'badge-server-02',
    name: 'Server Room Turnstile RFID',
    ip: '192.168.1.55',
    mac: '00:1E:67:C2:00:55',
    deviceType: 'Access Control',
    normalDestinations: ['192.168.1.1', '34.210.45.88'],
    normalPorts: [8883, 22],
    normalProtocols: ['MQTT', 'TCP'],
    status: 'ONLINE',
    packetsSent: 210,
    packetsReceived: 195,
    bytesTotal: 48000,
    lastSeen: Date.now(),
  },
  {
    id: 'temp-cold-02',
    name: 'Cold Storage Freezer Probe',
    ip: '192.168.1.61',
    mac: '00:1E:67:D3:00:61',
    deviceType: 'Environment Sensor',
    normalDestinations: ['192.168.1.1', '172.67.180.12'],
    normalPorts: [1883],
    normalProtocols: ['MQTT'],
    status: 'ONLINE',
    packetsSent: 420,
    packetsReceived: 410,
    bytesTotal: 39000,
    lastSeen: Date.now(),
  },
  {
    id: 'temp-cleanroom-03',
    name: 'Cleanroom Particulate Sensor',
    ip: '192.168.1.62',
    mac: '00:1E:67:D3:00:62',
    deviceType: 'Environment Sensor',
    normalDestinations: ['192.168.1.1', '172.67.180.12'],
    normalPorts: [1883],
    normalProtocols: ['MQTT'],
    status: 'ONLINE',
    packetsSent: 380,
    packetsReceived: 370,
    bytesTotal: 34000,
    lastSeen: Date.now(),
  },
  {
    id: 'hvac-chiller-02',
    name: 'Roof Chiller Controller B',
    ip: '192.168.1.71',
    mac: '00:1E:67:E4:00:71',
    deviceType: 'Climate Control',
    normalDestinations: ['192.168.1.1', '18.232.11.90'],
    normalPorts: [443],
    normalProtocols: ['HTTPS', 'TCP'],
    status: 'ONLINE',
    packetsSent: 290,
    packetsReceived: 275,
    bytesTotal: 62000,
    lastSeen: Date.now(),
  },
  {
    id: 'plug-lab-02',
    name: 'R&D Power Meter Rack 4',
    ip: '192.168.1.81',
    mac: '00:1E:67:F5:00:81',
    deviceType: 'Power Controller',
    normalDestinations: ['192.168.1.1', '172.67.180.12'],
    normalPorts: [80],
    normalProtocols: ['HTTP'],
    status: 'ONLINE',
    packetsSent: 190,
    packetsReceived: 180,
    bytesTotal: 28000,
    lastSeen: Date.now(),
  },
  {
    id: 'plug-ups-03',
    name: 'Primary UPS Smart PDU',
    ip: '192.168.1.82',
    mac: '00:1E:67:F5:00:82',
    deviceType: 'Power Controller',
    normalDestinations: ['192.168.1.1', '172.67.180.12'],
    normalPorts: [80, 443],
    normalProtocols: ['HTTP', 'HTTPS'],
    status: 'ONLINE',
    packetsSent: 340,
    packetsReceived: 330,
    bytesTotal: 55000,
    lastSeen: Date.now(),
  },
];

interface WanNode {
  id: string;
  name: string;
  ip: string;
  port?: number;
  type: 'ADVERSARY' | 'C2' | 'CLOUD' | 'NTP';
  desc: string;
  statusText: string;
}

const WAN_NODES: WanNode[] = [
  {
    id: 'wan-attacker',
    name: 'Adversary Recon Scanner',
    ip: '198.51.100.42',
    type: 'ADVERSARY',
    desc: 'SYN port sweep / credential dictionary source',
    statusText: 'UNTRUSTED WAN',
  },
  {
    id: 'wan-c2',
    name: 'C2 Command & Control Endpoint',
    ip: '203.0.113.88',
    port: 8443,
    type: 'C2',
    desc: 'Low-jitter beacon listener & payload staging',
    statusText: 'MALICIOUS C2',
  },
  {
    id: 'wan-cloud',
    name: 'Authorized Cloud Broker (AWS IoT)',
    ip: '52.14.99.102',
    port: 8883,
    type: 'CLOUD',
    desc: 'TLS MQTT telemetry ingestion service',
    statusText: 'PERMITTED CLOUD',
  },
  {
    id: 'wan-ntp',
    name: 'Firmware & NTP Sync Service',
    ip: '18.232.11.90',
    port: 443,
    type: 'NTP',
    desc: 'Timekeeping & signed OTA update server',
    statusText: 'AUTHORIZED WAN',
  },
];

export const TopologyPanel: React.FC<TopologyPanelProps> = ({
  devices,
  blocklist,
  recentAlerts,
  onToggleIsolate,
  theme = 'dark',
}) => {
  const isDark = theme === 'dark';

  // State: Large fleet toggle
  const [useLargeFleet, setUseLargeFleet] = useState<boolean>(false);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedClusterFilter, setSelectedClusterFilter] = useState<'ALL' | 'THREATS' | 'CAMERAS' | 'SENSORS' | 'POWER' | 'ENDPOINTS'>('ALL');
  const [isExpanded, setIsExpanded] = useState<boolean>(false);
  const [showMinimap, setShowMinimap] = useState<boolean>(true);

  // Transformation state: Zoom and Pan
  const [zoom, setZoom] = useState<number>(1.0);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  // Container refs
  const containerRef = useRef<HTMLDivElement | null>(null);
  const contentRef = useRef<HTMLDivElement | null>(null);

  // Active devices combined
  const activeDevices = useMemo(() => {
    return useLargeFleet ? [...devices, ...ENTERPRISE_EXTRA_DEVICES] : devices;
  }, [devices, useLargeFleet]);

  const isQuarantined = useCallback((ip: string) => blocklist.includes(ip), [blocklist]);
  
  const getDeviceAlert = useCallback((ip: string) => {
    return recentAlerts.find((a) => a.sourceIp === ip || a.targetIp.includes(ip));
  }, [recentAlerts]);

  // Zoom bounds
  const MIN_ZOOM = 0.4;
  const MAX_ZOOM = 2.4;

  // Zoom actions
  const handleZoom = useCallback((delta: number, clientCenterX?: number, clientCenterY?: number) => {
    setZoom((prevZoom) => {
      const newZoom = Math.min(Math.max(prevZoom + delta, MIN_ZOOM), MAX_ZOOM);
      if (newZoom === prevZoom) return prevZoom;

      if (containerRef.current && clientCenterX !== undefined && clientCenterY !== undefined) {
        const rect = containerRef.current.getBoundingClientRect();
        const cursorX = clientCenterX - rect.left;
        const cursorY = clientCenterY - rect.top;

        // Anchor pan to mouse position
        setPan((prevPan) => {
          const factor = newZoom / prevZoom;
          return {
            x: cursorX - (cursorX - prevPan.x) * factor,
            y: cursorY - (cursorY - prevPan.y) * factor,
          };
        });
      }

      return newZoom;
    });
  }, []);

  const handleResetView = useCallback(() => {
    setZoom(1.0);
    setPan({ x: 0, y: 0 });
  }, []);

  const handleFitToScreen = useCallback(() => {
    if (!containerRef.current) return;
    const container = containerRef.current;
    const cw = container.clientWidth;
    const ch = container.clientHeight;
    
    // Virtual content bounding box estimated: 1280px wide by 760px tall
    const contentW = 1320;
    const contentH = useLargeFleet ? 980 : 760;

    const scaleX = (cw - 60) / contentW;
    const scaleY = (ch - 60) / contentH;
    const fitZoom = Math.min(Math.max(Math.min(scaleX, scaleY), MIN_ZOOM), 1.2);

    const fitPanX = (cw - contentW * fitZoom) / 2;
    const fitPanY = (ch - contentH * fitZoom) / 2;

    setZoom(Number(fitZoom.toFixed(2)));
    setPan({ x: Math.round(fitPanX), y: Math.max(10, Math.round(fitPanY)) });
  }, [useLargeFleet]);

  // Center on specific coordinate or node
  const handleCenterOnGateway = useCallback(() => {
    if (!containerRef.current) return;
    const cw = containerRef.current.clientWidth;
    const ch = containerRef.current.clientHeight;
    // Gateway center roughly at X: 520, Y: 320 in content space
    const targetX = 520;
    const targetY = 320;
    const targetZoom = 1.1;

    setZoom(targetZoom);
    setPan({
      x: cw / 2 - targetX * targetZoom,
      y: ch / 2 - targetY * targetZoom,
    });
  }, []);

  const handleFocusThreats = useCallback(() => {
    if (!containerRef.current) return;
    // Find first quarantined IP or attacker
    const threatIp = blocklist[0] || '198.51.100.42';
    setSelectedIp(threatIp);

    const cw = containerRef.current.clientWidth;
    const ch = containerRef.current.clientHeight;

    // If threat is WAN attacker: X ~ 160, Y ~ 180
    // If threat is local device: X ~ 880, Y ~ 260
    const isWan = threatIp.startsWith('198.') || threatIp.startsWith('203.');
    const targetX = isWan ? 180 : 880;
    const targetY = 240;
    const targetZoom = 1.15;

    setZoom(targetZoom);
    setPan({
      x: cw / 2 - targetX * targetZoom,
      y: ch / 2 - targetY * targetZoom,
    });
  }, [blocklist]);

  // Mouse wheel zoom with cursor anchoring
  const onWheel = useCallback((e: React.WheelEvent<HTMLDivElement>) => {
    e.preventDefault();
    const delta = e.deltaY < 0 ? 0.12 : -0.12;
    handleZoom(delta, e.clientX, e.clientY);
  }, [handleZoom]);

  // Pointer drag panning
  const onPointerDown = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    // Only pan on left click or middle click
    if (e.button !== 0 && e.button !== 1) return;
    // If clicking directly on an interactive button or input, ignore pan
    const target = e.target as HTMLElement;
    if (target.closest('button') || target.closest('input') || target.closest('a')) {
      return;
    }

    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
  }, [pan]);

  const onPointerMove = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    if (!isDragging) return;
    setPan({
      x: e.clientX - dragStart.x,
      y: e.clientY - dragStart.y,
    });
  }, [isDragging, dragStart]);

  const onPointerUp = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    if (!isDragging) return;
    setIsDragging(false);
    try {
      (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId);
    } catch {
      // Ignore if pointer capture was lost
    }
  }, [isDragging]);

  // Double click canvas background to zoom in on cursor
  const onDoubleClick = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    const target = e.target as HTMLElement;
    if (target.closest('.device-node-card') || target.closest('button')) return;
    handleZoom(0.3, e.clientX, e.clientY);
  }, [handleZoom]);

  // Key navigation
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      // Only react if canvas is in view and no input is focused
      if (document.activeElement?.tagName === 'INPUT' || document.activeElement?.tagName === 'TEXTAREA') return;

      if (e.key === '+' || e.key === '=') {
        e.preventDefault();
        handleZoom(0.15);
      } else if (e.key === '-' || e.key === '_') {
        e.preventDefault();
        handleZoom(-0.15);
      } else if (e.key.toLowerCase() === 'r' || e.key === '0') {
        e.preventDefault();
        handleResetView();
      } else if (e.key === 'ArrowLeft') {
        setPan((p) => ({ ...p, x: p.x + 50 }));
      } else if (e.key === 'ArrowRight') {
        setPan((p) => ({ ...p, x: p.x - 50 }));
      } else if (e.key === 'ArrowUp') {
        setPan((p) => ({ ...p, y: p.y + 50 }));
      } else if (e.key === 'ArrowDown') {
        setPan((p) => ({ ...p, y: p.y - 50 }));
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [handleZoom, handleResetView]);

  // Filtered devices based on cluster and search
  const filteredDevices = useMemo(() => {
    return activeDevices.filter((dev) => {
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch = !q || 
        dev.name.toLowerCase().includes(q) || 
        dev.ip.includes(q) || 
        dev.deviceType.toLowerCase().includes(q) ||
        dev.mac.toLowerCase().includes(q);

      if (!matchesSearch) return false;

      if (selectedClusterFilter === 'ALL') return true;
      if (selectedClusterFilter === 'THREATS') return isQuarantined(dev.ip) || !!getDeviceAlert(dev.ip);
      if (selectedClusterFilter === 'CAMERAS') return dev.deviceType === 'Security Camera';
      if (selectedClusterFilter === 'SENSORS') return dev.deviceType === 'Environment Sensor' || dev.deviceType === 'Climate Control';
      if (selectedClusterFilter === 'POWER') return dev.deviceType === 'Power Controller';
      if (selectedClusterFilter === 'ENDPOINTS') return dev.deviceType.includes('Workstation') || dev.deviceType === 'Access Control';
      return true;
    });
  }, [activeDevices, searchQuery, selectedClusterFilter, isQuarantined, getDeviceAlert]);

  // Selected device entity details
  const selectedEntity = useMemo(() => {
    if (!selectedIp) return null;
    const wan = WAN_NODES.find((w) => w.ip === selectedIp);
    if (wan) return { type: 'WAN', data: wan };
    const dev = activeDevices.find((d) => d.ip === selectedIp);
    if (dev) return { type: 'DEVICE', data: dev };
    if (selectedIp === '192.168.1.1') return { type: 'GATEWAY', data: null };
    return null;
  }, [selectedIp, activeDevices]);

  // Helper to render device icons
  const getDeviceIcon = (deviceType: string) => {
    switch (deviceType) {
      case 'Security Camera':
        return <Camera className="w-4 h-4 text-sky-400" />;
      case 'Access Control':
        return <Lock className="w-4 h-4 text-emerald-400" />;
      case 'Environment Sensor':
        return <Thermometer className="w-4 h-4 text-teal-400" />;
      case 'Power Controller':
        return <Plug className="w-4 h-4 text-amber-400" />;
      case 'Climate Control':
        return <Cpu className="w-4 h-4 text-purple-400" />;
      case 'Workstation / Endpoint':
        return <Laptop className="w-4 h-4 text-cyan-400" />;
      default:
        return <Radio className="w-4 h-4 text-blue-400" />;
    }
  };

  // Minimap calculations
  const minimapTotalW = 1400;
  const minimapTotalH = useLargeFleet ? 1050 : 800;
  const minimapBoxW = 160;
  const minimapBoxH = 100;
  const minimapScale = minimapBoxW / minimapTotalW;

  const currentViewportW = containerRef.current?.clientWidth || 1000;
  const currentViewportH = containerRef.current?.clientHeight || 650;
  const visibleWorldW = currentViewportW / zoom;
  const visibleWorldH = currentViewportH / zoom;
  const visibleWorldX = -pan.x / zoom;
  const visibleWorldY = -pan.y / zoom;

  const minimapRectX = Math.max(0, Math.min(minimapBoxW - 20, visibleWorldX * minimapScale));
  const minimapRectY = Math.max(0, Math.min(minimapBoxH - 15, visibleWorldY * minimapScale));
  const minimapRectW = Math.max(16, Math.min(minimapBoxW, visibleWorldW * minimapScale));
  const minimapRectH = Math.max(14, Math.min(minimapBoxH, visibleWorldH * minimapScale));

  return (
    <div
      className={`border rounded-xl transition-all relative overflow-hidden flex flex-col ${
        isDark ? 'bg-[#0B0F17] border-[#1C2538]' : 'bg-white border-slate-200 shadow-sm'
      }`}
    >
      {/* TOP HEADER CONTROLS */}
      <div
        className={`px-4 py-3.5 border-b flex flex-col xl:flex-row xl:items-center justify-between gap-3 shrink-0 ${
          isDark ? 'bg-[#0E1422] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
        }`}
      >
        {/* Left: Title & Subnet Scope */}
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-blue-500/10 text-blue-500 border border-blue-500/20">
            <Network className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-display font-bold text-sm tracking-tight">
                Interactive IoT Network Topology
              </span>
              <span
                className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold border ${
                  isDark ? 'bg-slate-800 text-blue-400 border-slate-700' : 'bg-blue-50 text-blue-700 border-blue-200'
                }`}
              >
                192.168.1.0/24 &bull; VLAN 10/20
              </span>
              <span className="px-2 py-0.5 text-[10px] font-bold rounded-full bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                {activeDevices.length} Active Endpoints
              </span>
            </div>
            <div className="text-xs text-slate-400 mt-0.5 flex items-center gap-2">
              <span>Zoom &amp; Pan Navigation Enabled</span>
              <span>&bull;</span>
              <span>Mouse Wheel to Zoom &bull; Click &amp; Drag to Pan</span>
            </div>
          </div>
        </div>

        {/* Right: Quick Toolbar */}
        <div className="flex items-center gap-2 flex-wrap justify-between xl:justify-end">
          
          {/* Search Device */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              placeholder="Search IP, node, MAC..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className={`pl-8 pr-2.5 py-1.5 rounded-lg text-xs font-mono border outline-none w-44 transition-all ${
                isDark
                  ? 'bg-[#141B28] border-[#222E42] text-slate-200 focus:border-blue-500 focus:ring-1 focus:ring-blue-500'
                  : 'bg-white border-slate-300 text-slate-800 focus:border-blue-500'
              }`}
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 cursor-pointer"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          {/* Cluster Filter Buttons */}
          <div className="flex items-center gap-1 bg-slate-900/60 p-0.5 rounded-lg border border-slate-800 text-[11px] font-medium">
            <button
              onClick={() => setSelectedClusterFilter('ALL')}
              className={`px-2 py-1 rounded cursor-pointer transition-all ${
                selectedClusterFilter === 'ALL'
                  ? 'bg-blue-600 text-white font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All
            </button>
            <button
              onClick={() => setSelectedClusterFilter('THREATS')}
              className={`px-2 py-1 rounded cursor-pointer transition-all flex items-center gap-1 ${
                selectedClusterFilter === 'THREATS'
                  ? 'bg-rose-600 text-white font-bold'
                  : 'text-slate-400 hover:text-rose-400'
              }`}
            >
              <AlertTriangle className="w-3 h-3" />
              <span>Threats</span>
              {blocklist.length > 0 && (
                <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-ping"></span>
              )}
            </button>
            <button
              onClick={() => setSelectedClusterFilter('CAMERAS')}
              className={`px-2 py-1 rounded cursor-pointer transition-all ${
                selectedClusterFilter === 'CAMERAS'
                  ? 'bg-blue-600 text-white font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Cameras
            </button>
            <button
              onClick={() => setSelectedClusterFilter('SENSORS')}
              className={`px-2 py-1 rounded cursor-pointer transition-all ${
                selectedClusterFilter === 'SENSORS'
                  ? 'bg-blue-600 text-white font-bold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Sensors
            </button>
          </div>

          {/* Enterprise Fleet Scale Simulator Toggle */}
          <button
            onClick={() => {
              setUseLargeFleet(!useLargeFleet);
              setTimeout(() => handleFitToScreen(), 80);
            }}
            className={`px-2.5 py-1.5 rounded-lg border text-xs font-semibold flex items-center gap-1.5 cursor-pointer transition-all ${
              useLargeFleet
                ? 'bg-purple-600/20 text-purple-300 border-purple-500/50 shadow-xs'
                : isDark
                  ? 'bg-[#141B28] text-slate-300 hover:text-white border-[#222E42]'
                  : 'bg-slate-100 text-slate-700 hover:text-slate-900 border-slate-300'
            }`}
            title="Toggle between standard 6-device fleet and large 14-device enterprise deployment to test zoom/pan navigation"
          >
            <Layers className="w-3.5 h-3.5 text-purple-400" />
            <span>{useLargeFleet ? 'Enterprise Deployment (14)' : 'Standard Fleet (6)'}</span>
          </button>

          {/* Fullscreen / Expand Height Toggle */}
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className={`p-1.5 rounded-lg border text-slate-400 hover:text-white cursor-pointer transition-colors ${
              isDark ? 'bg-[#141B28] border-[#222E42]' : 'bg-white border-slate-300'
            }`}
            title={isExpanded ? 'Collapse Canvas Height' : 'Expand Canvas Height'}
          >
            {isExpanded ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      {/* INTERACTIVE CANVAS VIEWPORT */}
      <div
        ref={containerRef}
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
        onDoubleClick={onDoubleClick}
        style={{ height: isExpanded ? '840px' : '640px' }}
        className={`relative w-full overflow-hidden select-none transition-[height] duration-200 ${
          isDragging ? 'cursor-grabbing' : 'cursor-grab'
        } ${isDark ? 'bg-[#070A11]' : 'bg-slate-100'}`}
      >
        {/* Dynamic Background SVG Dot Grid (moves and scales with pan & zoom) */}
        <svg
          className="absolute inset-0 w-full h-full pointer-events-none opacity-40"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <pattern
              id="topology-dot-grid"
              x={pan.x % (32 * zoom)}
              y={pan.y % (32 * zoom)}
              width={32 * zoom}
              height={32 * zoom}
              patternUnits="userSpaceOnUse"
            >
              <circle
                cx={2 * zoom}
                cy={2 * zoom}
                r={1.2 * zoom}
                fill={isDark ? '#384B66' : '#94A3B8'}
              />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill="url(#topology-dot-grid)" />
        </svg>

        {/* FLOATING ZOOM / NAVIGATION PILL (Top-Left overlay) */}
        <div className="absolute top-4 left-4 z-20 flex items-center gap-1.5 bg-[#0F1522]/90 backdrop-blur-md border border-[#222E42] p-1.5 rounded-xl shadow-xl text-xs font-mono text-slate-200">
          <button
            onClick={() => handleZoom(0.2)}
            disabled={zoom >= MAX_ZOOM}
            className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-300 hover:text-white disabled:opacity-30 cursor-pointer transition-colors"
            title="Zoom In (+)"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          
          <span className="w-12 text-center font-bold font-mono text-[11px] text-blue-400">
            {Math.round(zoom * 100)}%
          </span>

          <button
            onClick={() => handleZoom(-0.2)}
            disabled={zoom <= MIN_ZOOM}
            className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-300 hover:text-white disabled:opacity-30 cursor-pointer transition-colors"
            title="Zoom Out (-)"
          >
            <ZoomOut className="w-4 h-4" />
          </button>

          <div className="h-4 w-px bg-slate-700 mx-1"></div>

          <button
            onClick={handleFitToScreen}
            className="px-2 py-1 rounded-lg hover:bg-slate-800 text-slate-300 hover:text-white text-[11px] font-medium cursor-pointer transition-colors"
            title="Fit entire topology to screen"
          >
            Fit View
          </button>

          <button
            onClick={handleResetView}
            className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-300 hover:text-white cursor-pointer transition-colors"
            title="Reset Zoom (1:1)"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>

          <div className="h-4 w-px bg-slate-700 mx-1"></div>

          <button
            onClick={handleCenterOnGateway}
            className="px-2 py-1 rounded-lg hover:bg-blue-600/20 text-blue-400 hover:text-blue-300 text-[11px] font-semibold flex items-center gap-1 cursor-pointer transition-colors"
            title="Center view on Security Gateway"
          >
            <Shield className="w-3 h-3" />
            <span>Gateway</span>
          </button>

          <button
            onClick={handleFocusThreats}
            className="px-2 py-1 rounded-lg hover:bg-rose-600/20 text-rose-400 hover:text-rose-300 text-[11px] font-semibold flex items-center gap-1 cursor-pointer transition-colors"
            title="Jump to flagged threat actor / isolated device"
          >
            <Crosshair className="w-3 h-3" />
            <span>Threats</span>
          </button>
        </div>

        {/* CANVAS WORLD CONTENT TRANSFORM WRAPPER */}
        <div
          ref={contentRef}
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: '0 0',
            width: '1380px',
            minHeight: useLargeFleet ? '980px' : '740px',
          }}
          className="absolute top-0 left-0 p-8 transition-transform duration-75 ease-out will-change-transform"
        >
          {/* SVG CABLING & DATA FLOW TRUNKS */}
          <svg
            className="absolute inset-0 w-full h-full pointer-events-none"
            style={{ zIndex: 0 }}
          >
            <defs>
              <linearGradient id="grad-healthy" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#10B981" stopOpacity="0.8" />
                <stop offset="100%" stopColor="#06B6D4" stopOpacity="0.8" />
              </linearGradient>
              <linearGradient id="grad-threat" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#EF4444" stopOpacity="0.9" />
                <stop offset="100%" stopColor="#B91C1C" stopOpacity="0.6" />
              </linearGradient>
              <linearGradient id="grad-c2" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="#F59E0B" stopOpacity="0.9" />
                <stop offset="100%" stopColor="#EF4444" stopOpacity="0.9" />
              </linearGradient>
            </defs>

            {/* WAN Ingress Trunk lines to Gateway eth0 (X: 520, Y: 280) */}
            {/* 1. Attacker (198.51.100.42) -> Gateway */}
            <path
              d="M 330 110 C 420 110, 440 250, 520 280"
              fill="none"
              stroke={isQuarantined('198.51.100.42') ? '#EF4444' : '#F59E0B'}
              strokeWidth="2.5"
              strokeDasharray={isQuarantined('198.51.100.42') ? '6,6' : 'none'}
              className={isQuarantined('198.51.100.42') ? '' : 'animate-pulse'}
            />

            {/* 2. C2 Server (203.0.113.88) -> Gateway */}
            <path
              d="M 330 220 C 410 220, 440 270, 520 280"
              fill="none"
              stroke={isQuarantined('203.0.113.88') ? '#EF4444' : '#F59E0B'}
              strokeWidth="2"
              strokeDasharray="4,4"
            />

            {/* 3. Authorized Cloud Broker -> Gateway */}
            <path
              d="M 330 330 C 410 330, 440 290, 520 290"
              fill="none"
              stroke="#10B981"
              strokeWidth="2"
              strokeOpacity="0.7"
            />

            {/* 4. Firmware Server -> Gateway */}
            <path
              d="M 330 440 C 420 440, 450 310, 520 300"
              fill="none"
              stroke="#06B6D4"
              strokeWidth="1.5"
              strokeOpacity="0.5"
            />

            {/* Gateway eth1 Distribution Trunks (X: 800, Y: 280) to LAN clusters */}
            {/* Trunk to Cluster 1: Security & Cameras (Y: 100) */}
            <path
              d="M 800 270 C 860 270, 860 110, 920 110"
              fill="none"
              stroke="#38BDF8"
              strokeWidth="2.5"
              strokeOpacity="0.8"
            />
            {/* Trunk to Cluster 2: Environmental & Sensors (Y: 260) */}
            <path
              d="M 800 280 C 860 280, 860 260, 920 260"
              fill="none"
              stroke="#10B981"
              strokeWidth="2.5"
              strokeOpacity="0.8"
            />
            {/* Trunk to Cluster 3: Power & Utilities (Y: 420) */}
            <path
              d="M 800 290 C 860 290, 860 420, 920 420"
              fill="none"
              stroke="#F59E0B"
              strokeWidth="2.5"
              strokeOpacity="0.8"
            />
            {/* Trunk to Cluster 4: Executive DLP Workstations (Y: 580) */}
            <path
              d="M 800 300 C 860 300, 860 580, 920 580"
              fill="none"
              stroke={isQuarantined('192.168.1.15') ? '#EF4444' : '#A855F7'}
              strokeWidth="2.5"
              strokeDasharray={isQuarantined('192.168.1.15') ? '6,6' : 'none'}
              strokeOpacity="0.8"
            />
          </svg>

          {/* SPATIAL THREE-TIER ARCHITECTURE GRID */}
          <div className="grid grid-cols-12 gap-8 items-start relative z-10 font-mono">
            
            {/* ========================================================
                ZONE 1: EXTERNAL WAN & INGRESS BOUNDARY (Col 1-3)
               ======================================================== */}
            <div className="col-span-3 space-y-4">
              <div className="flex items-center justify-between pb-2 border-b border-slate-700/60">
                <div className="flex items-center gap-2 text-xs font-bold text-slate-300 uppercase tracking-wider">
                  <Globe className="w-4 h-4 text-blue-400" />
                  <span>External WAN Ingress</span>
                </div>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30">
                  Untrusted Zone
                </span>
              </div>

              {/* WAN Nodes */}
              <div className="space-y-3">
                {WAN_NODES.map((wn) => {
                  const blocked = isQuarantined(wn.ip);
                  const isSelected = selectedIp === wn.ip;

                  return (
                    <div
                      key={wn.id}
                      onClick={() => setSelectedIp(wn.ip)}
                      className={`device-node-card p-3.5 rounded-xl border transition-all cursor-pointer relative ${
                        blocked
                          ? 'bg-rose-950/40 border-rose-500/60 text-rose-200 shadow-lg shadow-rose-950/30'
                          : wn.type === 'ADVERSARY'
                            ? 'bg-slate-900/90 border-amber-500/40 hover:border-amber-400 text-slate-200'
                            : wn.type === 'C2'
                              ? 'bg-slate-900/90 border-rose-500/40 hover:border-rose-400 text-slate-200'
                              : 'bg-slate-900/80 border-slate-800 hover:border-slate-600 text-slate-200'
                      } ${isSelected ? 'ring-2 ring-blue-500 scale-[1.02]' : ''}`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-center gap-2.5">
                          <div className={`p-2 rounded-lg ${
                            blocked 
                              ? 'bg-rose-500/20 text-rose-400' 
                              : wn.type === 'ADVERSARY'
                                ? 'bg-amber-500/20 text-amber-400'
                                : wn.type === 'C2'
                                  ? 'bg-rose-500/20 text-rose-400'
                                  : 'bg-emerald-500/20 text-emerald-400'
                          }`}>
                            {wn.type === 'ADVERSARY' && <Laptop className="w-4 h-4" />}
                            {wn.type === 'C2' && <Server className="w-4 h-4" />}
                            {wn.type === 'CLOUD' && <Globe className="w-4 h-4" />}
                            {wn.type === 'NTP' && <Activity className="w-4 h-4" />}
                          </div>
                          <div>
                            <div className="text-xs font-bold font-display tracking-tight text-white">
                              {wn.name}
                            </div>
                            <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                              {wn.ip}{wn.port ? `:${wn.port}` : ''}
                            </div>
                          </div>
                        </div>

                        <span
                          className={`px-2 py-0.5 rounded text-[9px] font-bold tracking-wider uppercase border ${
                            blocked
                              ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
                              : wn.type === 'ADVERSARY' || wn.type === 'C2'
                                ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                                : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                          }`}
                        >
                          {blocked ? 'ISOLATED' : wn.statusText}
                        </span>
                      </div>

                      <p className="text-[10px] text-slate-400 mt-2 line-clamp-2 leading-relaxed">
                        {wn.desc}
                      </p>

                      <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px]">
                        <span className="text-slate-400 font-mono">WAN Interface eth0</span>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onToggleIsolate(wn.ip);
                          }}
                          className={`px-2 py-0.5 rounded text-[9px] font-semibold cursor-pointer transition-colors ${
                            blocked
                              ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                              : 'bg-rose-600 hover:bg-rose-500 text-white'
                          }`}
                        >
                          {blocked ? 'Unblock' : 'Isolate'}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* ========================================================
                ZONE 2: SECURITY GATEWAY CORE (Col 4-6)
               ======================================================== */}
            <div className="col-span-3 space-y-4">
              <div className="flex items-center justify-between pb-2 border-b border-blue-500/40">
                <div className="flex items-center gap-2 text-xs font-bold text-blue-400 uppercase tracking-wider">
                  <ShieldCheck className="w-4 h-4 text-blue-400" />
                  <span>Hardening Gateway</span>
                </div>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-500/20 text-blue-300 border border-blue-500/30">
                  192.168.1.1
                </span>
              </div>

              {/* Central Security Core Card */}
              <div
                onClick={() => setSelectedIp('192.168.1.1')}
                className={`device-node-card p-5 rounded-2xl border transition-all cursor-pointer relative overflow-hidden ${
                  selectedIp === '192.168.1.1'
                    ? 'ring-2 ring-blue-500 bg-[#121927] border-blue-500/60'
                    : 'bg-[#101726] border-[#222E42] hover:border-blue-500/50 shadow-xl'
                }`}
              >
                {/* Visual Gateway Emblem */}
                <div className="text-center pb-4">
                  <div className="w-16 h-16 mx-auto rounded-2xl bg-gradient-to-b from-blue-600/20 to-blue-500/10 border border-blue-500/30 flex items-center justify-center mb-3 shadow-inner relative group">
                    <ShieldCheck className="w-9 h-9 text-blue-400" />
                    <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-emerald-500 border-2 border-[#101726]"></span>
                  </div>
                  <h3 className="text-sm font-bold text-white font-display">
                    Linux Kernel Intercept Engine
                  </h3>
                  <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                    Suricata L4/L7 &bull; Netfilter iptables &bull; USB DLP
                  </div>
                </div>

                {/* Live Core Metrics */}
                <div className="space-y-2.5 pt-4 border-t border-slate-800 text-xs font-mono">
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">WAN INGRESS (eth0):</span>
                    <span className="text-emerald-400 font-semibold">1000 Mbps Full-Duplex</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">FORWARD CHAIN:</span>
                    <span className="text-blue-400 font-bold">STATEFUL INSPECT</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">ISOLATED HOSTS:</span>
                    <span className="text-rose-400 font-bold tabular-nums">
                      {blocklist.length} Quarantined
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate-400">TOTAL MONITORED:</span>
                    <span className="text-white font-bold tabular-nums">
                      {activeDevices.length} Nodes
                    </span>
                  </div>
                </div>

                {/* Subnet Distribution Ports */}
                <div className="mt-4 pt-3 border-t border-slate-800/80 grid grid-cols-2 gap-2 text-[10px]">
                  <div className="p-2 rounded bg-slate-900/80 border border-slate-800 text-center">
                    <div className="text-slate-400">VLAN 10</div>
                    <div className="font-bold text-blue-400">IoT Perimeter</div>
                  </div>
                  <div className="p-2 rounded bg-slate-900/80 border border-slate-800 text-center">
                    <div className="text-slate-400">VLAN 20</div>
                    <div className="font-bold text-purple-400">Endpoints/DLP</div>
                  </div>
                </div>
              </div>

              {/* Physical Security & USB Hardware Notice */}
              <div className="p-3.5 rounded-xl border border-amber-500/30 bg-amber-500/10 text-amber-200 text-xs">
                <div className="flex items-center gap-2 font-bold mb-1">
                  <HardDrive className="w-4 h-4 text-amber-400" />
                  <span>Physical DLP &amp; USB Guard</span>
                </div>
                <p className="text-[11px] text-amber-300/80 leading-relaxed">
                  Endpoint telemetry agent stream enforces Windows Registry <code>USBSTOR</code> lockdown and Linux <code>modprobe</code> module drops upon air-gapped storage exfiltration.
                </p>
              </div>
            </div>

            {/* ========================================================
                ZONE 3: PROTECTED LAN IOT CLUSTERS (Col 7-12)
               ======================================================== */}
            <div className="col-span-6 space-y-4">
              <div className="flex items-center justify-between pb-2 border-b border-emerald-500/40">
                <div className="flex items-center gap-2 text-xs font-bold text-emerald-400 uppercase tracking-wider">
                  <Cpu className="w-4 h-4 text-emerald-400" />
                  <span>Protected LAN Fleet (Subnet 192.168.1.0/24)</span>
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-slate-400 font-mono">Showing {filteredDevices.length} of {activeDevices.length}</span>
                </div>
              </div>

              {/* Devices Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                {filteredDevices.map((dev) => {
                  const blocked = isQuarantined(dev.ip);
                  const alert = getDeviceAlert(dev.ip);
                  const isSelected = selectedIp === dev.ip;

                  return (
                    <div
                      key={dev.id}
                      onClick={() => setSelectedIp(dev.ip)}
                      className={`device-node-card p-3 rounded-xl border transition-all cursor-pointer relative ${
                        blocked
                          ? 'bg-rose-950/30 border-rose-500/60 text-rose-200 shadow-md shadow-rose-950/20'
                          : alert
                            ? 'bg-amber-950/25 border-amber-500/50 text-amber-200'
                            : 'bg-[#121824] border-[#1C2538] hover:border-blue-500/50 text-slate-200 shadow-sm'
                      } ${isSelected ? 'ring-2 ring-blue-500 scale-[1.02]' : ''}`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex items-center gap-2.5">
                          <div className={`p-2 rounded-lg ${
                            blocked
                              ? 'bg-rose-500/20 text-rose-400'
                              : alert
                                ? 'bg-amber-500/20 text-amber-400'
                                : 'bg-slate-800 text-slate-300'
                          }`}>
                            {getDeviceIcon(dev.deviceType)}
                          </div>
                          <div>
                            <div className="text-xs font-bold font-display text-white truncate max-w-[150px]">
                              {dev.name}
                            </div>
                            <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                              {dev.ip}
                            </div>
                          </div>
                        </div>

                        <span
                          className={`px-1.5 py-0.5 rounded text-[9px] font-bold tracking-wider uppercase border shrink-0 ${
                            blocked
                              ? 'bg-rose-500/20 text-rose-400 border-rose-500/30'
                              : alert
                                ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                                : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                          }`}
                        >
                          {blocked ? 'ISOLATED' : alert ? 'ALERT' : 'ONLINE'}
                        </span>
                      </div>

                      {/* Device meta */}
                      <div className="mt-2.5 pt-2 border-t border-slate-800 text-[10px] space-y-1 text-slate-400">
                        <div className="flex justify-between">
                          <span>TYPE:</span>
                          <span className="text-slate-300 font-medium">{dev.deviceType}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>MAC:</span>
                          <span className="font-mono text-slate-400">{dev.mac}</span>
                        </div>
                        <div className="flex justify-between">
                          <span>PROTOCOLS:</span>
                          <span className="font-mono text-blue-400">{dev.normalProtocols.join(', ')}</span>
                        </div>
                      </div>

                      {/* Action buttons on card */}
                      <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between">
                        <span className="text-[10px] font-mono text-slate-500">
                          {dev.packetsSent + dev.packetsReceived} pkts
                        </span>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onToggleIsolate(dev.ip);
                          }}
                          className={`px-2.5 py-1 rounded text-[10px] font-bold cursor-pointer transition-colors ${
                            blocked
                              ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                              : 'bg-rose-600 hover:bg-rose-500 text-white'
                          }`}
                        >
                          {blocked ? 'Lift Isolation' : 'Isolate Device'}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>

              {filteredDevices.length === 0 && (
                <div className="p-8 rounded-xl border border-dashed border-slate-800 text-center text-slate-400 text-xs">
                  No devices match current filter or search term.
                </div>
              )}
            </div>

          </div>
        </div>

        {/* MINIMAP RADAR NAVIGATOR (Bottom-Right overlay) */}
        {showMinimap && (
          <div className="absolute bottom-4 right-4 z-20 bg-[#0E1422]/95 backdrop-blur-md border border-[#222E42] rounded-xl p-2.5 shadow-2xl text-[10px] font-mono">
            <div className="flex items-center justify-between pb-1.5 mb-1.5 border-b border-slate-800 text-slate-400">
              <span className="flex items-center gap-1 font-bold">
                <Compass className="w-3 h-3 text-blue-400" />
                <span>Minimap Navigator</span>
              </span>
              <button
                onClick={() => setShowMinimap(false)}
                className="hover:text-white cursor-pointer"
                title="Hide minimap"
              >
                <X className="w-3 h-3" />
              </button>
            </div>

            {/* Minimap preview canvas */}
            <div
              onClick={(e) => {
                const rect = e.currentTarget.getBoundingClientRect();
                const clickX = e.clientX - rect.left;
                const clickY = e.clientY - rect.top;
                const targetWorldX = clickX / minimapScale;
                const targetWorldY = clickY / minimapScale;
                const cw = containerRef.current?.clientWidth || 1000;
                const ch = containerRef.current?.clientHeight || 650;
                setPan({
                  x: cw / 2 - targetWorldX * zoom,
                  y: ch / 2 - targetWorldY * zoom,
                });
              }}
              style={{ width: `${minimapBoxW}px`, height: `${minimapBoxH}px` }}
              className="relative bg-[#070A11] border border-slate-800 rounded-lg overflow-hidden cursor-crosshair"
            >
              {/* WAN dots */}
              <div className="absolute top-4 left-4 w-2 h-2 rounded-full bg-amber-500"></div>
              <div className="absolute top-10 left-4 w-2 h-2 rounded-full bg-rose-500"></div>
              <div className="absolute top-16 left-4 w-2 h-2 rounded-full bg-emerald-500"></div>

              {/* Gateway central dot */}
              <div className="absolute top-1/2 left-[38%] -translate-y-1/2 w-4 h-4 rounded-full bg-blue-500/40 border border-blue-400 flex items-center justify-center">
                <div className="w-1.5 h-1.5 rounded-full bg-blue-400"></div>
              </div>

              {/* LAN device dots */}
              <div className="absolute top-4 right-4 w-2 h-2 rounded-full bg-sky-400"></div>
              <div className="absolute top-10 right-4 w-2 h-2 rounded-full bg-teal-400"></div>
              <div className="absolute top-16 right-4 w-2 h-2 rounded-full bg-amber-400"></div>
              <div className="absolute bottom-3 right-4 w-2 h-2 rounded-full bg-purple-400"></div>

              {/* Viewport rectangle indicator */}
              <div
                style={{
                  left: `${minimapRectX}px`,
                  top: `${minimapRectY}px`,
                  width: `${minimapRectW}px`,
                  height: `${minimapRectH}px`,
                }}
                className="absolute border-2 border-blue-400 bg-blue-500/20 rounded pointer-events-none transition-all duration-75"
              />
            </div>
            
            <div className="text-[9px] text-slate-400 text-center mt-1">
              Click anywhere on radar to pan
            </div>
          </div>
        )}

        {/* Restore Minimap toggle if hidden */}
        {!showMinimap && (
          <button
            onClick={() => setShowMinimap(true)}
            className="absolute bottom-4 right-4 z-20 p-2 rounded-lg bg-[#0E1422] border border-slate-700 text-slate-300 hover:text-white cursor-pointer shadow-lg"
            title="Show Minimap Radar"
          >
            <Compass className="w-4 h-4 text-blue-400" />
          </button>
        )}

        {/* BOTTOM LEFT HINT BADGE */}
        <div className="absolute bottom-4 left-4 z-20 pointer-events-none hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#0E1422]/80 backdrop-blur-md border border-slate-800 text-[11px] text-slate-400">
          <Move className="w-3.5 h-3.5 text-blue-400" />
          <span>Pan: Click &amp; Drag &bull; Zoom: Wheel &bull; Center: Double-Click</span>
        </div>

      </div>

      {/* SELECTED NODE INSPECTOR MODAL / DRAWER */}
      {selectedEntity && (
        <div className={`p-4 border-t flex flex-col md:flex-row md:items-center justify-between gap-4 ${
          isDark ? 'bg-[#0E1422] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
        }`}>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
              <Info className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm text-white">
                  {selectedEntity.type === 'GATEWAY'
                    ? 'Linux Kernel Intercept Gateway (192.168.1.1)'
                    : selectedEntity.type === 'WAN'
                      ? (selectedEntity.data as WanNode).name
                      : (selectedEntity.data as IoTDevice).name}
                </span>
                <span className="text-xs font-mono text-blue-400">
                  {selectedIp}
                </span>
                {selectedIp && isQuarantined(selectedIp) && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400 border border-rose-500/30">
                    QUARANTINED
                  </span>
                )}
              </div>
              <div className="text-xs text-slate-400 mt-0.5">
                {selectedEntity.type === 'GATEWAY' && 'Physical Ingress Node &bull; Netfilter Stateful Firewall &bull; eth0/eth1'}
                {selectedEntity.type === 'WAN' && (selectedEntity.data as WanNode).desc}
                {selectedEntity.type === 'DEVICE' && `${(selectedEntity.data as IoTDevice).deviceType} \u2022 MAC: ${(selectedEntity.data as IoTDevice).mac}`}
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {selectedIp && selectedIp !== '192.168.1.1' && (
              <button
                onClick={() => onToggleIsolate(selectedIp)}
                className={`px-3.5 py-1.5 rounded-lg text-xs font-bold cursor-pointer transition-colors ${
                  isQuarantined(selectedIp)
                    ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                    : 'bg-rose-600 hover:bg-rose-500 text-white'
                }`}
              >
                {isQuarantined(selectedIp) ? 'Lift Quarantine & Unblock' : 'Isolate with iptables / USBSTOR'}
              </button>
            )}
            <button
              onClick={() => setSelectedIp(null)}
              className="p-1.5 rounded-lg border border-slate-700 hover:bg-slate-800 text-slate-400 hover:text-white cursor-pointer"
              title="Close inspector"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

    </div>
  );
};
