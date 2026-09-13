import React, { useState, useEffect, useRef, useMemo } from 'react';
import { 
  Radio, 
  ShieldAlert, 
  ShieldCheck, 
  Crosshair, 
  Zap, 
  Cpu, 
  Activity, 
  Volume2, 
  VolumeX, 
  Lock, 
  Camera, 
  Thermometer, 
  Plug, 
  Flame, 
  KeyRound, 
  Sparkles,
  AlertTriangle,
  RotateCw,
  Eye,
  Server
} from 'lucide-react';
import { IoTDevice, Packet, ThreatAlert, AlertCategory } from '../types';
import { soundEngine } from '../utils/audioSynth';
import { speechEngine } from '../utils/speechNotification';

interface TacticalRadarViewProps {
  devices: IoTDevice[];
  packets: Packet[];
  alerts: ThreatAlert[];
  blocklist: string[];
  onToggleIsolate: (ip: string) => void;
  onInjectAttack: (category: AlertCategory, targetIp: string) => void;
  safetyMode: boolean;
  packetRate: number;
  theme?: 'dark' | 'light';
}

interface RadarNode {
  id: string;
  name: string;
  ip: string;
  mac: string;
  type: string;
  angle: number; // in radians
  distance: number; // 0 to 1 relative to radar radius
  isExternal: boolean;
}

export const TacticalRadarView: React.FC<TacticalRadarViewProps> = ({
  devices,
  packets,
  alerts,
  blocklist,
  onToggleIsolate,
  onInjectAttack,
  safetyMode,
  packetRate,
  theme = 'dark',
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [selectedNodeIp, setSelectedNodeIp] = useState<string>(devices[0]?.ip || '192.168.1.10');
  const [audioEnabled, setAudioEnabled] = useState<boolean>(soundEngine.isEnabled());
  const [ttsEnabled, setTtsEnabled] = useState<boolean>(speechEngine.isEnabled());
  const [isSpeakingTts, setIsSpeakingTts] = useState<boolean>(false);
  const [particlesEnabled, setParticlesEnabled] = useState<boolean>(true);
  const [sweepSpeed, setSweepSpeed] = useState<number>(1); // 1x or 2x
  const [recentPacketBursts, setRecentPacketBursts] = useState<{ id: string; from: string; to: string; isAttack: boolean }[]>([]);

  const radarAngleRef = useRef<number>(0);
  const animFrameIdRef = useRef<number | null>(null);
  const isDark = theme === 'dark';

  // Sound toggle handler
  const handleToggleAudio = () => {
    const next = !audioEnabled;
    soundEngine.setEnabled(next);
    setAudioEnabled(next);
  };

  // TTS Voice notification toggle handler
  const handleToggleTts = () => {
    const next = !ttsEnabled;
    speechEngine.setEnabled(next);
    setTtsEnabled(next);
  };

  useEffect(() => {
    return speechEngine.subscribe((speaking) => {
      setIsSpeakingTts(speaking);
      setTtsEnabled(speechEngine.isEnabled());
    });
  }, []);

  // Build list of all radar tracked nodes (Gateway center, internal devices, external WAN adversaries)
  const radarNodes: RadarNode[] = useMemo(() => [
    // External adversaries in outer orbit
    {
      id: 'adv-scanner',
      name: 'Adversary Port Scanner',
      ip: '198.51.100.42',
      mac: '52:54:00:12:34:56',
      type: 'adversary',
      angle: (35 * Math.PI) / 180,
      distance: 0.88,
      isExternal: true,
    },
    {
      id: 'adv-c2',
      name: 'External C2 Server',
      ip: '203.0.113.88',
      mac: '52:54:00:99:88:77',
      type: 'adversary',
      angle: (210 * Math.PI) / 180,
      distance: 0.92,
      isExternal: true,
    },
    // LAN IoT Nodes (dispersed in concentric orbits)
    {
      id: 'dev-1',
      name: 'Smart Thermostat',
      ip: '192.168.1.10',
      mac: 'b8:27:eb:aa:11:01',
      type: 'thermostat',
      angle: (85 * Math.PI) / 180,
      distance: 0.38,
      isExternal: false,
    },
    {
      id: 'dev-2',
      name: 'Security Camera North',
      ip: '192.168.1.11',
      mac: 'b8:27:eb:aa:11:02',
      type: 'camera',
      angle: (140 * Math.PI) / 180,
      distance: 0.55,
      isExternal: false,
    },
    {
      id: 'dev-3',
      name: 'Smart Doorlock Main',
      ip: '192.168.1.12',
      mac: 'b8:27:eb:aa:11:03',
      type: 'doorlock',
      angle: (290 * Math.PI) / 180,
      distance: 0.45,
      isExternal: false,
    },
    {
      id: 'dev-4',
      name: 'Power Plug Relay',
      ip: '192.168.1.13',
      mac: 'b8:27:eb:aa:11:04',
      type: 'smart_plug',
      angle: (15 * Math.PI) / 180,
      distance: 0.65,
      isExternal: false,
    },
    {
      id: 'dev-5',
      name: 'Environmental Sensor',
      ip: '192.168.1.14',
      mac: 'b8:27:eb:aa:11:05',
      type: 'sensor',
      angle: (245 * Math.PI) / 180,
      distance: 0.70,
      isExternal: false,
    },
    {
      id: 'dev-6',
      name: 'Smoke / Gas Detector',
      ip: '192.168.1.15',
      mac: 'b8:27:eb:aa:11:06',
      type: 'smoke_detector',
      angle: (330 * Math.PI) / 180,
      distance: 0.52,
      isExternal: false,
    },
  ], []);

  // Track latest packets for packet burst animations
  useEffect(() => {
    if (packets.length === 0) return;
    const latest = packets.slice(-5);
    const bursts = latest.map((p) => ({
      id: p.id,
      from: p.srcIp,
      to: p.dstIp,
      isAttack: p.isAttack,
    }));
    setRecentPacketBursts(bursts);
  }, [packets]);

  // Audio chirp feedback on new threat alert
  useEffect(() => {
    if (alerts.length > 0 && alerts[0].severity === 'HIGH') {
      soundEngine.playAlert();
    }
  }, [alerts.length]);

  // -------------------------------------------------------------
  // HTML5 Canvas Radar Animation Loop
  // -------------------------------------------------------------
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let lastTime = performance.now();

    const render = (time: number) => {
      const delta = (time - lastTime) / 1000;
      lastTime = time;

      // Update sweep angle
      radarAngleRef.current = (radarAngleRef.current + delta * (1.2 * sweepSpeed)) % (2 * Math.PI);

      const width = canvas.width;
      const height = canvas.height;
      const centerX = width / 2;
      const centerY = height / 2;
      const radius = Math.min(centerX, centerY) - 24;

      // 1. Clear background
      ctx.fillStyle = isDark ? '#0B0F17' : '#F8FAFC';
      ctx.fillRect(0, 0, width, height);

      // 2. Draw subtle tactical grid
      ctx.strokeStyle = isDark ? '#151D2C' : '#E2E8F0';
      ctx.lineWidth = 1;
      const gridSize = 40;
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // 3. Draw Radar Concentric Rings
      const rings = [0.25, 0.5, 0.75, 1.0];
      rings.forEach((rRatio, idx) => {
        const r = radius * rRatio;
        ctx.beginPath();
        ctx.arc(centerX, centerY, r, 0, 2 * Math.PI);
        ctx.strokeStyle = idx === rings.length - 1 
          ? (isDark ? '#222E42' : '#94A3B8') 
          : (isDark ? '#1C2538' : '#CBD5E1');
        ctx.lineWidth = idx === rings.length - 1 ? 1.5 : 1;
        ctx.setLineDash(idx % 2 === 0 ? [4, 4] : []);
        ctx.stroke();
        ctx.setLineDash([]);

        // Ring distance text
        ctx.fillStyle = isDark ? '#64748B' : '#94A3B8';
        ctx.font = '9px "JetBrains Mono", monospace';
        ctx.fillText(`${Math.round(rRatio * 100)}m`, centerX + 4, centerY - r + 10);
      });

      // 4. Polar Axis Lines & Degree Labels
      const angles = [0, 45, 90, 135, 180, 225, 270, 315];
      angles.forEach((deg) => {
        const rad = (deg * Math.PI) / 180;
        const endX = centerX + Math.cos(rad) * radius;
        const endY = centerY + Math.sin(rad) * radius;

        ctx.beginPath();
        ctx.moveTo(centerX, centerY);
        ctx.lineTo(endX, endY);
        ctx.strokeStyle = isDark ? '#1C2538' : '#E2E8F0';
        ctx.lineWidth = 1;
        ctx.stroke();

        // Degree label at perimeter
        const labelX = centerX + Math.cos(rad) * (radius + 14);
        const labelY = centerY + Math.sin(rad) * (radius + 14);
        ctx.fillStyle = isDark ? '#64748B' : '#94A3B8';
        ctx.font = '9px "JetBrains Mono", monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(`${deg}°`, labelX, labelY);
      });

      // 5. Sweeping Radar Beam with Gradient
      const sweepAngle = radarAngleRef.current;
      const sweepArc = Math.PI / 4; // 45 degrees tail

      const sweepGrad = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, radius);
      sweepGrad.addColorStop(0, 'rgba(59, 130, 246, 0.15)');
      sweepGrad.addColorStop(1, 'rgba(16, 185, 129, 0.01)');

      ctx.save();
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.arc(centerX, centerY, radius, sweepAngle - sweepArc, sweepAngle, false);
      ctx.closePath();
      ctx.fillStyle = sweepGrad;
      ctx.fill();

      // Sharp beam line at leading edge
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.lineTo(centerX + Math.cos(sweepAngle) * radius, centerY + Math.sin(sweepAngle) * radius);
      ctx.strokeStyle = 'rgba(59, 130, 246, 0.7)';
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.restore();

      // 6. Center Gateway Node (Suricata Gateway 192.168.1.1)
      ctx.beginPath();
      ctx.arc(centerX, centerY, 7, 0, 2 * Math.PI);
      ctx.fillStyle = '#10B981';
      ctx.fill();
      ctx.strokeStyle = isDark ? '#0B0F17' : '#FFFFFF';
      ctx.lineWidth = 2;
      ctx.stroke();

      // Center crosshair
      ctx.strokeStyle = '#3B82F6';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(centerX - 12, centerY);
      ctx.lineTo(centerX + 12, centerY);
      ctx.moveTo(centerX, centerY - 12);
      ctx.lineTo(centerX, centerY + 12);
      ctx.stroke();

      ctx.fillStyle = isDark ? '#F1F5F9' : '#0F172A';
      ctx.font = 'bold 10px "JetBrains Mono", monospace';
      ctx.textAlign = 'center';
      ctx.fillText('GW: 192.168.1.1', centerX, centerY + 20);

      // 7. Draw Node Blips
      radarNodes.forEach((node) => {
        const nodeDist = radius * node.distance;
        const nodeX = centerX + Math.cos(node.angle) * nodeDist;
        const nodeY = centerY + Math.sin(node.angle) * nodeDist;

        const isQuarantined = blocklist.includes(node.ip);
        const hasActiveAlert = alerts.some((a) => a.sourceIp === node.ip || a.targetIp === node.ip);
        const isSelected = selectedNodeIp === node.ip;

        // Proximity to sweeping radar beam for glowing ping effect
        let angleDiff = sweepAngle - node.angle;
        while (angleDiff < 0) angleDiff += 2 * Math.PI;
        while (angleDiff >= 2 * Math.PI) angleDiff -= 2 * Math.PI;
        const isPinged = angleDiff < 0.25;

        // Threat or Healthy color
        let color = '#10B981'; // Emerald
        if (node.isExternal || hasActiveAlert) {
          color = '#F43F5E'; // Rose
        }
        if (isQuarantined) {
          color = '#F43F5E';
        }

        // Concentric pulse shockwave if pinged or under attack
        if (hasActiveAlert || isPinged) {
          ctx.beginPath();
          ctx.arc(nodeX, nodeY, isPinged ? 16 : 14, 0, 2 * Math.PI);
          ctx.strokeStyle = color;
          ctx.lineWidth = 1;
          ctx.stroke();
        }

        // Selected Target Reticle
        if (isSelected) {
          ctx.strokeStyle = '#3B82F6';
          ctx.lineWidth = 1.5;
          ctx.strokeRect(nodeX - 12, nodeY - 12, 24, 24);

          // Corner reticle accents
          ctx.beginPath();
          ctx.moveTo(nodeX - 16, nodeY);
          ctx.lineTo(nodeX - 12, nodeY);
          ctx.moveTo(nodeX + 12, nodeY);
          ctx.lineTo(nodeX + 16, nodeY);
          ctx.moveTo(nodeX, nodeY - 16);
          ctx.lineTo(nodeX, nodeY - 12);
          ctx.moveTo(nodeX, nodeY + 12);
          ctx.lineTo(nodeX, nodeY + 16);
          ctx.stroke();
        }

        // Node blip circle
        ctx.beginPath();
        ctx.arc(nodeX, nodeY, 5, 0, 2 * Math.PI);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.strokeStyle = isDark ? '#0B0F17' : '#FFFFFF';
        ctx.lineWidth = 1.5;
        ctx.stroke();

        // Node label
        ctx.fillStyle = isDark ? '#CBD5E1' : '#334155';
        ctx.font = '9px "JetBrains Mono", monospace';
        ctx.textAlign = 'center';
        ctx.fillText(node.name.split(' ')[0], nodeX, nodeY + 14);
      });

      animFrameIdRef.current = requestAnimationFrame(render);
    };

    animFrameIdRef.current = requestAnimationFrame(render);

    return () => {
      if (animFrameIdRef.current) {
        cancelAnimationFrame(animFrameIdRef.current);
      }
    };
  }, [radarNodes, blocklist, alerts, selectedNodeIp, sweepSpeed, isDark]);

  // Click on canvas to lock onto a node
  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const clickX = e.clientX - rect.left;
    const clickY = e.clientY - rect.top;

    const width = canvas.width;
    const height = canvas.height;
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(centerX, centerY) - 24;

    // Find closest node within 20px
    let closestNode: RadarNode | null = null;
    let minDist = 25;

    radarNodes.forEach((node) => {
      const nodeDist = radius * node.distance;
      const nodeX = centerX + Math.cos(node.angle) * nodeDist;
      const nodeY = centerY + Math.sin(node.angle) * nodeDist;

      const d = Math.sqrt(Math.pow(clickX - nodeX, 2) + Math.pow(clickY - nodeY, 2));
      if (d < minDist) {
        minDist = d;
        closestNode = node;
      }
    });

    if (closestNode) {
      setSelectedNodeIp((closestNode as RadarNode).ip);
      soundEngine.playChirp(720, 0.04);
    }
  };

  const selectedDevice = devices.find((d) => d.ip === selectedNodeIp);
  const selectedNode = radarNodes.find((n) => n.ip === selectedNodeIp);
  const isSelectedQuarantined = blocklist.includes(selectedNodeIp);
  const isSelectedExternal = selectedNode?.isExternal ?? false;
  const selectedNodeAlerts = alerts.filter(
    (a) => a.sourceIp === selectedNodeIp || a.targetIp === selectedNodeIp
  );

  const getDeviceIcon = (type: string) => {
    switch (type) {
      case 'thermostat': return <Thermometer className="w-4 h-4 text-blue-500" />;
      case 'camera': return <Camera className="w-4 h-4 text-emerald-500" />;
      case 'doorlock': return <Lock className="w-4 h-4 text-amber-500" />;
      case 'smart_plug': return <Plug className="w-4 h-4 text-purple-500" />;
      case 'smoke_detector': return <Flame className="w-4 h-4 text-rose-500" />;
      default: return <Cpu className="w-4 h-4 text-blue-500" />;
    }
  };

  return (
    <div className="space-y-4">
      
      {/* 1. Radar HUD Header Ribbon */}
      <div className={`border rounded-xl p-3.5 lg:p-4 flex flex-wrap items-center justify-between gap-3 transition-colors ${
        isDark ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
      }`}>
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-blue-500/10 text-blue-500">
            <Radio className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-display font-bold text-sm">Real-Time Polar Tactical Radar</span>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold border ${
                isDark ? 'bg-slate-800 text-blue-400 border-slate-700' : 'bg-blue-50 text-blue-700 border-blue-200'
              }`}>
                Live L4/L7 Sweep
              </span>
            </div>
            <div className="text-xs text-slate-400 mt-0.5">
              Subnet 192.168.1.0/24 &bull; Ingress Intercepts &bull; Anomaly Reticle Tracking
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border ${
            isDark ? 'bg-[#0B0F17] border-[#222E42]' : 'bg-slate-50 border-slate-200'
          }`}>
            <Activity className="w-3.5 h-3.5 text-blue-500" />
            <span className="text-slate-400">INGRESS:</span>
            <span className="font-bold text-blue-500 tabular-nums">{packetRate} Pkt/s</span>
          </div>

          <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border ${
            isDark ? 'bg-[#0B0F17] border-[#222E42]' : 'bg-slate-50 border-slate-200'
          }`}>
            <ShieldAlert className="w-3.5 h-3.5 text-rose-500" />
            <span className="text-slate-400">THREATS:</span>
            <span className="font-bold text-rose-500 tabular-nums">{alerts.length}</span>
          </div>

          {/* Audio Telemetry Toggle */}
          <button
            onClick={handleToggleAudio}
            className={`px-3 py-1.5 rounded-lg border flex items-center gap-1.5 transition-all cursor-pointer ${
              audioEnabled
                ? isDark
                  ? 'bg-blue-500/15 text-blue-400 border-blue-500/40'
                  : 'bg-blue-50 text-blue-700 border-blue-200'
                : isDark
                  ? 'bg-[#0B0F17] text-slate-400 border-[#222E42] hover:text-white'
                  : 'bg-white text-slate-600 border-slate-200 hover:text-slate-900'
            }`}
          >
            {audioEnabled ? <Volume2 className="w-3.5 h-3.5 text-blue-500" /> : <VolumeX className="w-3.5 h-3.5" />}
            <span>AUDIO HUD: {audioEnabled ? 'ACTIVE' : 'MUTED'}</span>
          </button>

          {/* Text-to-Speech Voice Alerts Toggle */}
          <button
            onClick={handleToggleTts}
            className={`px-3 py-1.5 rounded-lg border flex items-center gap-1.5 transition-all cursor-pointer ${
              ttsEnabled
                ? isSpeakingTts
                  ? 'bg-rose-500/20 text-rose-400 border-rose-500 animate-pulse'
                  : isDark
                    ? 'bg-blue-500/15 text-blue-400 border-blue-500/40'
                    : 'bg-blue-50 text-blue-700 border-blue-200'
                : isDark
                  ? 'bg-[#0B0F17] text-slate-400 border-[#222E42] hover:text-white'
                  : 'bg-white text-slate-600 border-slate-200 hover:text-slate-900'
            }`}
          >
            {ttsEnabled ? (
              <Volume2 className={`w-3.5 h-3.5 text-blue-500 ${isSpeakingTts ? 'animate-bounce' : ''}`} />
            ) : (
              <VolumeX className="w-3.5 h-3.5" />
            )}
            <span>TTS VOICE: {isSpeakingTts ? 'SPEAKING...' : ttsEnabled ? 'ACTIVE' : 'MUTED'}</span>
          </button>
        </div>

      </div>

      {/* 2. Main Radar Stage + Target Hologram Inspector Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        
        {/* Left 8 Cols: Interactive 360° Polar Radar View */}
        <div className={`lg:col-span-8 border rounded-xl p-4 flex flex-col relative overflow-hidden transition-colors ${
          isDark ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
        }`}>
          
          {/* Radar Header with Controls */}
          <div className="flex items-center justify-between pb-3 border-b border-inherit mb-3 text-xs font-mono">
            <div className="flex items-center gap-2">
              <Radio className="w-4 h-4 text-blue-500" />
              <span className="font-display font-bold text-xs uppercase tracking-wider">
                360° Polar Intercept Radar
              </span>
              <span className="text-[10px] text-emerald-500 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20 font-bold">
                BEAM ACTIVE
              </span>
            </div>

            <div className="flex items-center gap-2 text-xs">
              <button
                onClick={() => setSweepSpeed((s) => (s === 1 ? 2 : 1))}
                className={`px-2.5 py-1 rounded border transition-colors cursor-pointer ${
                  isDark 
                    ? 'bg-[#0B0F17] border-[#222E42] text-slate-300 hover:text-white' 
                    : 'bg-slate-100 border-slate-200 text-slate-700 hover:text-slate-900'
                }`}
              >
                SWEEP: {sweepSpeed}X
              </button>
              <button
                onClick={() => setParticlesEnabled(!particlesEnabled)}
                className={`px-2.5 py-1 rounded border cursor-pointer transition-colors ${
                  particlesEnabled
                    ? 'bg-blue-600 text-white border-blue-600'
                    : isDark ? 'bg-[#0B0F17] text-slate-400 border-[#222E42]' : 'bg-slate-100 text-slate-600 border-slate-200'
                }`}
              >
                BEAMS: {particlesEnabled ? 'ON' : 'OFF'}
              </button>
            </div>
          </div>

          {/* Interactive Canvas Container */}
          <div className={`flex-1 flex items-center justify-center relative min-h-[460px] rounded-xl border overflow-hidden ${
            isDark ? 'bg-[#0B0F17] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
          }`}>
            <canvas
              ref={canvasRef}
              width={640}
              height={460}
              onClick={handleCanvasClick}
              className="cursor-crosshair max-w-full h-auto"
            />

            {/* Tactical Scale Overlay */}
            <div className="absolute top-3 left-3.5 font-mono text-[10px] text-slate-400 space-y-0.5 pointer-events-none">
              <div>RANGE: 100m SUBNET PERIMETER</div>
              <div>ANTENNA: OMNI-DIRECTIONAL 2.4/5GHz</div>
              <div>GATEWAY: eth0 (192.168.1.1)</div>
            </div>

            <div className="absolute bottom-3 left-3.5 font-mono text-[10px] text-slate-400 flex items-center gap-3 pointer-events-none">
              <span className="flex items-center gap-1.5 text-emerald-500 font-semibold">
                <span className="w-2 h-2 rounded-full bg-emerald-500"></span> BENIGN IOT
              </span>
              <span className="flex items-center gap-1.5 text-rose-500 font-semibold">
                <span className="w-2 h-2 rounded-full bg-rose-500"></span> ADVERSARY / QUARANTINED
              </span>
            </div>

            <div className="absolute bottom-3 right-3.5 font-mono text-[10px] text-slate-400 pointer-events-none">
              Click node to lock reticle
            </div>
          </div>

          {/* Quick Subnet Selector Strip */}
          <div className="mt-3 pt-2.5 border-t border-inherit flex items-center gap-2 overflow-x-auto no-scrollbar font-mono text-xs">
            <span className="text-[11px] text-slate-400 uppercase tracking-wider shrink-0 font-medium">Quick Target:</span>
            {radarNodes.map((n) => {
              const isSelected = selectedNodeIp === n.ip;
              const isBlocked = blocklist.includes(n.ip);
              return (
                <button
                  key={n.id}
                  onClick={() => {
                    setSelectedNodeIp(n.ip);
                    soundEngine.playChirp(680, 0.03);
                  }}
                  className={`px-2.5 py-1 rounded-md text-[11px] shrink-0 border transition-all cursor-pointer ${
                    isSelected
                      ? 'bg-blue-600 text-white font-bold border-blue-600 shadow-xs'
                      : isBlocked
                        ? isDark
                          ? 'bg-rose-500/15 text-rose-400 border-rose-500/40'
                          : 'bg-rose-50 text-rose-700 border-rose-200'
                        : isDark
                          ? 'bg-[#121824] text-slate-300 border-[#1C2538] hover:border-slate-700'
                          : 'bg-slate-100 text-slate-700 border-slate-200 hover:border-slate-300'
                  }`}
                >
                  {n.isExternal ? '⚠ ' : ''}{n.name.split(' ')[0]} ({n.ip.split('.').slice(2).join('.')})
                </button>
              );
            })}
          </div>

        </div>

        {/* Right 4 Cols: Target Hologram & Quarantine Lock */}
        <div className={`lg:col-span-4 border rounded-xl p-4 lg:p-5 flex flex-col justify-between space-y-4 transition-colors ${
          isDark ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
        }`}>
          
          <div>
            {/* Hologram Card Header */}
            <div className="flex items-center justify-between pb-3 border-b border-inherit">
              <div className="flex items-center gap-2">
                <Crosshair className="w-4 h-4 text-blue-500" />
                <span className="font-display font-bold text-xs uppercase tracking-wider">
                  Target Node Hologram
                </span>
              </div>
              <span className={`px-2 py-0.5 rounded-full font-mono text-[10px] font-bold tracking-wider uppercase border ${
                isSelectedQuarantined
                  ? 'border-rose-500/40 text-rose-400 bg-rose-500/10'
                  : 'border-emerald-500/30 text-emerald-500 bg-emerald-500/10'
              }`}>
                {isSelectedQuarantined ? 'DROP ACTIVE' : 'PERMITTED'}
              </span>
            </div>

            {/* Node Identity Display */}
            <div className={`mt-3.5 border p-3.5 rounded-xl space-y-3 ${
              isDark ? 'bg-[#121824] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
            }`}>
              <div className="flex items-start justify-between">
                <div>
                  <div className="text-sm font-bold font-display">
                    {selectedDevice?.name || (isSelectedExternal ? 'External Host / Scanner' : 'Node: ' + selectedNodeIp)}
                  </div>
                  <div className="text-xs text-slate-400 font-mono mt-0.5">
                    {selectedDevice?.deviceType || (isSelectedExternal ? 'WAN Remote Adversary' : 'LAN Node')}
                  </div>
                </div>
                <div className={`w-8 h-8 rounded-lg border flex items-center justify-center ${
                  isDark ? 'bg-[#0B0F17] border-[#222E42]' : 'bg-white border-slate-200 shadow-xs'
                }`}>
                  {selectedDevice ? getDeviceIcon(selectedDevice.deviceType) : <Server className="w-4 h-4 text-rose-500" />}
                </div>
              </div>

              <div className="space-y-1.5 text-xs font-mono pt-2 border-t border-inherit">
                <div className="flex justify-between">
                  <span className="text-slate-400">IPV4 ADDR:</span>
                  <span className="text-blue-500 font-bold">{selectedNodeIp}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">HARDWARE MAC:</span>
                  <span className="text-slate-300 text-[11px]">{selectedDevice?.mac || '52:54:00:12:34:56'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">VLAN ZONE:</span>
                  <span className="font-semibold">{isSelectedExternal ? 'WAN INGRESS' : 'VLAN 10 (IoT Isolated)'}</span>
                </div>
                {selectedDevice && (
                  <div className="flex justify-between">
                    <span className="text-slate-400">NORMAL PORTS:</span>
                    <span className="text-slate-300">{selectedDevice.normalPorts.join(', ')}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Active Threat Intercepts for this Node */}
            <div className="mt-4 space-y-2">
              <div className="text-xs font-mono font-bold text-slate-400 uppercase tracking-wider flex items-center justify-between">
                <span>Suricata Intercepts ({selectedNodeAlerts.length})</span>
                <span className="text-blue-500">L4/L7 Heuristics</span>
              </div>

              {selectedNodeAlerts.length === 0 ? (
                <div className={`p-3 rounded-lg border text-xs font-mono flex items-center gap-2 ${
                  isDark ? 'bg-[#121824] border-[#1C2538] text-emerald-400' : 'bg-emerald-50 border-emerald-200 text-emerald-700'
                }`}>
                  <ShieldCheck className="w-4 h-4 text-emerald-500 shrink-0" />
                  <span>No active anomaly signatures detected.</span>
                </div>
              ) : (
                <div className="space-y-2 max-h-36 overflow-y-auto pr-1 font-mono text-xs">
                  {selectedNodeAlerts.map((a) => (
                    <div
                      key={a.id}
                      className={`p-2.5 rounded-lg border text-xs space-y-1 ${
                        isDark 
                          ? 'bg-rose-500/10 border-rose-500/30 text-rose-300' 
                          : 'bg-rose-50 border-rose-200 text-rose-800'
                      }`}
                    >
                      <div className="font-bold flex items-center justify-between">
                        <span>{a.title}</span>
                        <span className="text-[10px] uppercase font-bold">{a.severity}</span>
                      </div>
                      <div className="text-[11px] font-sans opacity-90">{a.description}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Action Triggers */}
          <div className="space-y-2.5 pt-3 border-t border-inherit font-mono text-xs">
            {/* Primary Isolate Button */}
            <button
              onClick={() => {
                onToggleIsolate(selectedNodeIp);
                soundEngine.playIsolate();
              }}
              className={`w-full py-2.5 px-3 rounded-lg font-bold text-xs uppercase tracking-wider flex items-center justify-center gap-2 cursor-pointer transition-all shadow-xs ${
                isSelectedQuarantined
                  ? isDark
                    ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/25'
                    : 'bg-emerald-50 text-emerald-700 border border-emerald-200 hover:bg-emerald-100'
                  : 'bg-rose-600 hover:bg-rose-700 text-white'
              }`}
            >
              {isSelectedQuarantined ? (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  <span>Lift Kernel Drop &amp; Permit</span>
                </>
              ) : (
                <>
                  <AlertTriangle className="w-4 h-4" />
                  <span>Enforce Quarantine (-j DROP)</span>
                </>
              )}
            </button>

            {/* Quick Attack Simulator Trigger against this node */}
            <div className="grid grid-cols-2 gap-2 text-xs">
              <button
                onClick={() => {
                  onInjectAttack('PORT_SCAN', selectedNodeIp);
                  soundEngine.playChirp(880, 0.05);
                }}
                className={`py-2 px-2.5 rounded-lg border flex items-center justify-center gap-1.5 cursor-pointer transition-colors ${
                  isDark 
                    ? 'bg-[#121824] border-[#1C2538] text-slate-300 hover:text-white' 
                    : 'bg-slate-100 border-slate-200 text-slate-700 hover:text-slate-900'
                }`}
              >
                <Crosshair className="w-3.5 h-3.5 text-blue-500" />
                <span>Sim Port Scan</span>
              </button>

              <button
                onClick={() => {
                  onInjectAttack('BRUTE_FORCE', selectedNodeIp);
                  soundEngine.playChirp(880, 0.05);
                }}
                className={`py-2 px-2.5 rounded-lg border flex items-center justify-center gap-1.5 cursor-pointer transition-colors ${
                  isDark 
                    ? 'bg-[#121824] border-[#1C2538] text-slate-300 hover:text-white' 
                    : 'bg-slate-100 border-slate-200 text-slate-700 hover:text-slate-900'
                }`}
              >
                <KeyRound className="w-3.5 h-3.5 text-rose-500" />
                <span>Sim Brute Auth</span>
              </button>
            </div>
          </div>

        </div>

      </div>

      {/* 3. Real-Time Intercept Ticker Ribbon */}
      <div className={`border rounded-xl p-3.5 font-mono text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 transition-colors ${
        isDark ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
      }`}>
        <div className="flex items-center gap-2.5">
          <div className="p-1 rounded-md bg-blue-500/10 text-blue-500">
            <Zap className="w-3.5 h-3.5" />
          </div>
          <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
            Kernel Verdict:
          </span>
          <span className="text-xs truncate max-w-md font-medium">
            {recentPacketBursts.length > 0 
              ? `[INSPECTED] ${recentPacketBursts[recentPacketBursts.length - 1].from} -> ${recentPacketBursts[recentPacketBursts.length - 1].to}` 
              : 'Sliding window idle. Awaiting incoming network telemetry.'}
          </span>
        </div>

        <div className="flex items-center gap-3 text-xs text-slate-400">
          <span>Mode: <strong className={safetyMode ? 'text-amber-500' : 'text-emerald-500'}>{safetyMode ? 'DRY-RUN' : 'LIVE KERNEL'}</strong></span>
          <span>&bull;</span>
          <span>Forward Chain: <strong className="text-emerald-500 font-bold">ACTIVE</strong></span>
        </div>
      </div>

    </div>
  );
};
