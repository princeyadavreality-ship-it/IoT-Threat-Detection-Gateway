import React, { useState, useMemo } from 'react';
import { 
  ShieldAlert, 
  ChevronDown, 
  ChevronRight, 
  ArrowUpDown, 
  Search, 
  Crosshair, 
  KeyRound, 
  Radio, 
  Zap,
  Trash2,
  Ban,
  Filter,
  CheckCircle2,
  Download,
  Check,
  ArrowUpRight,
  HardDrive
} from 'lucide-react';
import { ThreatAlert, Packet } from '../types';
import { AlertDetailDrawer } from './AlertDetailDrawer';

interface AlertsDataTableProps {
  alerts: ThreatAlert[];
  packets?: Packet[];
  blocklist?: string[];
  onClearAlerts: () => void;
  onSelectAlertIp?: (ip: string) => void;
  theme?: 'dark' | 'light';
  selectedSeverity?: 'ALL' | 'LOW' | 'MEDIUM' | 'HIGH';
  onSeverityChange?: (severity: 'ALL' | 'LOW' | 'MEDIUM' | 'HIGH') => void;
}

type SortField = 'timestamp' | 'category' | 'severity' | 'sourceIp' | 'targetIp';
type SortOrder = 'asc' | 'desc';

export const AlertsDataTable: React.FC<AlertsDataTableProps> = ({
  alerts,
  packets = [],
  blocklist = [],
  onClearAlerts,
  onSelectAlertIp,
  theme = 'dark',
  selectedSeverity,
  onSeverityChange,
}) => {
  const [selectedAlertForDrawer, setSelectedAlertForDrawer] = useState<ThreatAlert | null>(null);
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [internalSeverityFilter, setInternalSeverityFilter] = useState<'ALL' | 'LOW' | 'MEDIUM' | 'HIGH'>('ALL');

  const severityFilter = selectedSeverity !== undefined ? selectedSeverity : internalSeverityFilter;
  const setSeverityFilter = (sev: 'ALL' | 'LOW' | 'MEDIUM' | 'HIGH') => {
    setInternalSeverityFilter(sev);
    if (onSeverityChange) {
      onSeverityChange(sev);
    }
  };

  const severityCounts = useMemo(() => {
    return {
      ALL: alerts.length,
      LOW: alerts.filter((a) => a.severity === 'LOW').length,
      MEDIUM: alerts.filter((a) => a.severity === 'MEDIUM').length,
      HIGH: alerts.filter((a) => a.severity === 'HIGH').length,
    };
  }, [alerts]);

  const [sortField, setSortField] = useState<SortField>('timestamp');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [exported, setExported] = useState(false);

  const isDark = theme === 'dark';

  const handleExportCSV = () => {
    if (alerts.length === 0) return;

    // Standard SIEM & compliance audit CSV columns
    const headers = [
      'Alert ID',
      'Timestamp (ISO 8601)',
      'Timestamp (Epoch ms)',
      'Severity',
      'Rule Category',
      'Source IP',
      'Target IP',
      'Status',
      'Detail',
      'Evidence Summary',
    ];

    const escapeCsv = (str: string | number | null | undefined): string => {
      if (str === null || str === undefined) return '""';
      const text = String(str).replace(/"/g, '""');
      return `"${text}"`;
    };

    // Use currently filtered alerts or full alert set
    const dataToExport = filteredAlerts.length > 0 ? filteredAlerts : alerts;

    const rows = dataToExport.map((alt) => {
      const isoDate = new Date(alt.timestamp).toISOString();
      const evidenceStr = alt.evidence ? JSON.stringify(alt.evidence) : '';
      return [
        escapeCsv(alt.id),
        escapeCsv(isoDate),
        escapeCsv(alt.timestamp),
        escapeCsv(alt.severity),
        escapeCsv(alt.category),
        escapeCsv(alt.sourceIp),
        escapeCsv(alt.targetIp),
        escapeCsv(alt.status),
        escapeCsv(alt.detail),
        escapeCsv(evidenceStr),
      ].join(',');
    });

    const csvContent = [headers.join(','), ...rows].join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const now = new Date();
    const dateStamp = now.toISOString().replace(/[:.]/g, '-').slice(0, 19);
    a.href = url;
    a.download = `iot-threat-alerts-${dateStamp}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    setExported(true);
    setTimeout(() => setExported(false), 2000);
  };

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case 'PORT_SCAN':
        return <Crosshair className="w-3.5 h-3.5 text-blue-500" />;
      case 'BRUTE_FORCE':
        return <KeyRound className="w-3.5 h-3.5 text-rose-500" />;
      case 'C2_BEACONING':
        return <Radio className="w-3.5 h-3.5 text-amber-500" />;
      case 'USB_EXFILTRATION':
        return <HardDrive className="w-3.5 h-3.5 text-amber-500" />;
      case 'VOLUME_FLOOD':
      default:
        return <Zap className="w-3.5 h-3.5 text-purple-500" />;
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'HIGH':
        return (
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${
            isDark 
              ? 'bg-rose-500/15 text-rose-400 border-rose-500/30' 
              : 'bg-rose-50 text-rose-700 border-rose-200'
          }`}>
            CRITICAL
          </span>
        );
      case 'MEDIUM':
        return (
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold border ${
            isDark 
              ? 'bg-amber-500/15 text-amber-400 border-amber-500/30' 
              : 'bg-amber-50 text-amber-800 border-amber-200'
          }`}>
            MED
          </span>
        );
      case 'LOW':
      default:
        return (
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-medium border ${
            isDark 
              ? 'bg-slate-800 text-slate-400 border-slate-700' 
              : 'bg-slate-100 text-slate-600 border-slate-200'
          }`}>
            LOW
          </span>
        );
    }
  };

  const filteredAlerts = alerts
    .filter((alt) => {
      if (severityFilter !== 'ALL' && alt.severity !== severityFilter) return false;
      if (searchTerm) {
        const q = searchTerm.toLowerCase();
        return (
          alt.id.toLowerCase().includes(q) ||
          alt.sourceIp.toLowerCase().includes(q) ||
          alt.targetIp.toLowerCase().includes(q) ||
          alt.category.toLowerCase().includes(q) ||
          alt.detail.toLowerCase().includes(q)
        );
      }
      return true;
    })
    .sort((a, b) => {
      let comparison = 0;
      if (sortField === 'timestamp') {
        comparison = a.timestamp - b.timestamp;
      } else if (sortField === 'category') {
        comparison = a.category.localeCompare(b.category);
      } else if (sortField === 'severity') {
        const weight = { HIGH: 3, MEDIUM: 2, LOW: 1 };
        comparison = (weight[a.severity] || 0) - (weight[b.severity] || 0);
      } else if (sortField === 'sourceIp') {
        comparison = a.sourceIp.localeCompare(b.sourceIp);
      } else if (sortField === 'targetIp') {
        comparison = a.targetIp.localeCompare(b.targetIp);
      }
      return sortOrder === 'asc' ? comparison : -comparison;
    });

  return (
    <div className={`border rounded-xl overflow-hidden transition-colors ${
      isDark ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
    }`}>
      
      {/* Table Toolbar */}
      <div className={`p-3.5 lg:p-4 border-b flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
        isDark ? 'border-[#1C2538] bg-[#121824]' : 'border-slate-200 bg-slate-50'
      }`}>
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-rose-500/10 text-rose-500">
            <ShieldAlert className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-display font-bold text-sm">Security Incident Ledger</span>
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold border ${
                isDark ? 'bg-slate-800 text-slate-300 border-slate-700' : 'bg-white text-slate-700 border-slate-200'
              }`}>
                {filteredAlerts.length} shown of {alerts.length}
              </span>
            </div>
          </div>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {/* Search Input */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search host, category..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className={`pl-8 pr-3 py-1.5 rounded-lg text-xs font-mono border transition-colors outline-none focus:ring-1 focus:ring-blue-500 ${
                isDark 
                  ? 'bg-[#0B0F17] border-[#222E42] text-slate-200 placeholder-slate-500' 
                  : 'bg-white border-slate-300 text-slate-900 placeholder-slate-400'
              }`}
            />
          </div>

          {/* Quick Severity Filter Buttons: All, Low, Medium, High */}
          <div className={`flex items-center rounded-lg p-1 border font-medium ${
            isDark ? 'bg-[#0B0F17] border-[#222E42]' : 'bg-slate-100 border-slate-200'
          }`}>
            {(
              [
                { id: 'ALL', label: 'All', count: severityCounts.ALL },
                { id: 'LOW', label: 'Low', count: severityCounts.LOW },
                { id: 'MEDIUM', label: 'Medium', count: severityCounts.MEDIUM },
                { id: 'HIGH', label: 'High', count: severityCounts.HIGH },
              ] as const
            ).map((btn) => {
              const isActive = severityFilter === btn.id;
              return (
                <button
                  key={btn.id}
                  onClick={() => setSeverityFilter(btn.id)}
                  className={`px-2.5 py-1 rounded-md text-[11px] flex items-center gap-1.5 transition-all cursor-pointer ${
                    isActive
                      ? btn.id === 'HIGH'
                        ? 'bg-rose-600 text-white font-semibold shadow-xs'
                        : btn.id === 'MEDIUM'
                        ? 'bg-amber-600 text-white font-semibold shadow-xs'
                        : btn.id === 'LOW'
                        ? 'bg-sky-600 text-white font-semibold shadow-xs'
                        : isDark
                        ? 'bg-blue-600 text-white font-semibold shadow-xs'
                        : 'bg-white text-blue-700 font-semibold shadow-xs'
                      : isDark
                      ? 'text-slate-400 hover:text-white'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                  title={`Filter by ${btn.label} severity alerts`}
                >
                  <span>{btn.label}</span>
                  <span
                    className={`text-[9px] font-mono px-1 py-0.2 rounded-full ${
                      isActive
                        ? 'bg-white/20 text-white font-bold'
                        : isDark
                        ? 'bg-slate-800 text-slate-400'
                        : 'bg-slate-200 text-slate-600'
                    }`}
                  >
                    {btn.count}
                  </span>
                </button>
              );
            })}
          </div>

          {/* Export CSV Button */}
          <button
            onClick={handleExportCSV}
            disabled={alerts.length === 0}
            className={`px-2.5 py-1.5 rounded-lg border text-xs font-medium flex items-center gap-1.5 transition-all cursor-pointer ${
              alerts.length === 0
                ? 'opacity-40 cursor-not-allowed border-transparent'
                : exported
                ? isDark
                  ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                  : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                : isDark
                ? 'bg-[#141B28] text-slate-200 hover:text-white border-[#222E42] hover:border-blue-500/50'
                : 'bg-white text-slate-700 hover:text-slate-900 border-slate-300 hover:border-blue-400 shadow-xs'
            }`}
            title="Export alert logs as RFC-4180 CSV for external SIEM audit and compliance reporting"
          >
            {exported ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-500" />
                <span className="font-semibold text-emerald-500">Exported</span>
              </>
            ) : (
              <>
                <Download className="w-3.5 h-3.5 text-blue-500" />
                <span>Export CSV</span>
              </>
            )}
          </button>

          {/* Purge / Clear Button */}
          {alerts.length > 0 && (
            <button
              onClick={onClearAlerts}
              className={`p-1.5 rounded-lg border text-xs flex items-center gap-1 transition-all cursor-pointer ${
                isDark
                  ? 'bg-[#0B0F17] border-[#222E42] text-slate-400 hover:text-rose-400 hover:border-rose-500/40'
                  : 'bg-white border-slate-200 text-slate-600 hover:text-rose-600 hover:border-rose-200'
              }`}
              title="Clear active incident buffer"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Main Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className={`border-b text-[11px] font-mono tracking-wider uppercase ${
              isDark ? 'border-[#1C2538] bg-[#0C111C] text-slate-400' : 'border-slate-200 bg-slate-50 text-slate-500'
            }`}>
              <th className="py-2.5 pl-4 pr-2 w-8"></th>
              <th 
                onClick={() => handleSort('timestamp')}
                className="py-2.5 px-3 cursor-pointer select-none hover:text-blue-500 whitespace-nowrap"
              >
                <div className="flex items-center gap-1">
                  <span>Timestamp</span>
                  <ArrowUpDown className="w-2.5 h-2.5" />
                </div>
              </th>
              <th 
                onClick={() => handleSort('category')}
                className="py-2.5 px-3 cursor-pointer select-none hover:text-blue-500 whitespace-nowrap"
              >
                <div className="flex items-center gap-1">
                  <span>Rule Category</span>
                  <ArrowUpDown className="w-2.5 h-2.5" />
                </div>
              </th>
              <th 
                onClick={() => handleSort('severity')}
                className="py-2.5 px-3 cursor-pointer select-none hover:text-blue-500 whitespace-nowrap"
              >
                <div className="flex items-center gap-1">
                  <span>Severity</span>
                  <ArrowUpDown className="w-2.5 h-2.5" />
                </div>
              </th>
              <th 
                onClick={() => handleSort('sourceIp')}
                className="py-2.5 px-3 cursor-pointer select-none hover:text-blue-500 whitespace-nowrap"
              >
                <div className="flex items-center gap-1">
                  <span>Source Host</span>
                  <ArrowUpDown className="w-2.5 h-2.5" />
                </div>
              </th>
              <th 
                onClick={() => handleSort('targetIp')}
                className="py-2.5 px-3 cursor-pointer select-none hover:text-blue-500 whitespace-nowrap"
              >
                <div className="flex items-center gap-1">
                  <span>Target Node</span>
                  <ArrowUpDown className="w-2.5 h-2.5" />
                </div>
              </th>
              <th className="py-2.5 px-3">Description</th>
              <th className="py-2.5 pr-4 text-right whitespace-nowrap">Containment</th>
            </tr>
          </thead>

          <tbody className={`divide-y ${isDark ? 'divide-[#1C2538]' : 'divide-slate-200'}`}>
            {filteredAlerts.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-12 text-center text-slate-500">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <CheckCircle2 className="w-8 h-8 text-emerald-500 opacity-80" />
                    <span className="font-medium text-sm">No Active Security Incidents</span>
                    <span className="text-xs text-slate-400">All ingress packets meet baseline heuristic security policies.</span>
                  </div>
                </td>
              </tr>
            ) : (
              filteredAlerts.map((alt) => {
                const isExpanded = expandedAlertId === alt.id;
                const timeStr = new Date(alt.timestamp).toISOString().slice(11, 19);

                return (
                  <React.Fragment key={alt.id}>
                    <tr 
                      onClick={() => setSelectedAlertForDrawer(alt)}
                      className={`cursor-pointer transition-colors group ${
                        isExpanded || selectedAlertForDrawer?.id === alt.id
                          ? isDark ? 'bg-[#151D2C]' : 'bg-slate-100'
                          : isDark ? 'hover:bg-[#121824]' : 'hover:bg-slate-50'
                      }`}
                      title="Click to view detailed packet metadata & forensic evidence logs"
                    >
                      {/* Expand Toggle Chevron */}
                      <td 
                        className="py-3 pl-4 pr-2 text-slate-400"
                        onClick={(e) => {
                          e.stopPropagation();
                          setExpandedAlertId(isExpanded ? null : alt.id);
                        }}
                        title={isExpanded ? "Collapse inline preview" : "Expand inline preview"}
                      >
                        {isExpanded ? (
                          <ChevronDown className="w-3.5 h-3.5 text-blue-500" />
                        ) : (
                          <ChevronRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-blue-400" />
                        )}
                      </td>

                      {/* Timestamp */}
                      <td className="py-3 px-3 font-mono text-[11px] text-slate-400 whitespace-nowrap tabular-nums">
                        {timeStr}
                      </td>

                      {/* Category */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <div className="flex items-center gap-2 font-medium">
                          {getCategoryIcon(alt.category)}
                          <span>{alt.category}</span>
                        </div>
                      </td>

                      {/* Severity Badge */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        {getSeverityBadge(alt.severity)}
                      </td>

                      {/* Source Host */}
                      <td className="py-3 px-3 font-mono font-semibold text-rose-400 whitespace-nowrap tabular-nums">
                        {alt.sourceIp}
                      </td>

                      {/* Target Host */}
                      <td className="py-3 px-3 font-mono text-slate-300 whitespace-nowrap tabular-nums">
                        {alt.targetIp}
                      </td>

                      {/* Description */}
                      <td className="py-3 px-3 truncate max-w-xs text-slate-400">
                        {alt.detail}
                      </td>

                      {/* Containment CTA */}
                      <td className="py-3 pr-4 text-right whitespace-nowrap" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => setSelectedAlertForDrawer(alt)}
                            className={`px-2 py-1 rounded-md text-[11px] font-medium flex items-center gap-1 border transition-all cursor-pointer ${
                              isDark
                                ? 'bg-[#141B28] border-[#222E42] text-slate-300 hover:text-white hover:border-blue-500/40'
                                : 'bg-white border-slate-300 text-slate-700 hover:text-slate-900 shadow-xs hover:border-blue-400'
                            }`}
                            title="Inspect full threat forensics and packet breakdown"
                          >
                            <span>Inspect</span>
                            <ArrowUpRight className="w-3 h-3 text-blue-400" />
                          </button>
                          <button
                            onClick={() => onSelectAlertIp && onSelectAlertIp(alt.sourceIp)}
                            className={`px-2.5 py-1 rounded-md text-[11px] font-semibold flex items-center gap-1.5 border transition-all cursor-pointer ${
                              isDark
                                ? 'bg-rose-500/10 text-rose-300 border-rose-500/30 hover:bg-rose-600 hover:text-white'
                                : 'bg-rose-50 text-rose-700 border-rose-200 hover:bg-rose-600 hover:text-white'
                            }`}
                          >
                            <Ban className="w-3 h-3" />
                            <span>Isolate IP</span>
                          </button>
                        </div>
                      </td>
                    </tr>

                    {/* Expandable Heuristic Evidence Panel */}
                    {isExpanded && (
                      <tr className={isDark ? 'bg-[#0B0F17]' : 'bg-slate-50'}>
                        <td colSpan={8} className="py-3 px-4 lg:px-6">
                          <div className={`p-4 rounded-lg border space-y-3 ${
                            isDark ? 'bg-[#101622] border-[#222E42]' : 'bg-white border-slate-200 shadow-xs'
                          }`}>
                            <div className="flex items-center justify-between pb-2 border-b border-inherit">
                              <span className="text-xs font-bold font-mono text-blue-500 uppercase tracking-wider">
                                Forensic Packet Evidence &bull; Incident {alt.id}
                              </span>
                              <span className="text-[11px] font-mono text-slate-400">
                                Target Protocol Port: {alt.evidence?.targetPort || 'Multiple'}
                              </span>
                            </div>

                            <div className="text-xs space-y-1">
                              <div className="font-medium text-slate-300">Rule Violation Description:</div>
                              <p className="text-slate-400 font-sans">{alt.detail}</p>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 text-xs font-mono">
                              <div className={`p-2.5 rounded border ${
                                isDark ? 'bg-[#141B28] border-[#222E42]' : 'bg-slate-50 border-slate-200'
                              }`}>
                                <div className="text-[10px] text-slate-400">EVALUATION WINDOW</div>
                                <div className="font-bold mt-0.5">{alt.evidence?.windowSec || 60} seconds sliding</div>
                              </div>
                              <div className={`p-2.5 rounded border ${
                                isDark ? 'bg-[#141B28] border-[#222E42]' : 'bg-slate-50 border-slate-200'
                              }`}>
                                <div className="text-[10px] text-slate-400">EVIDENCE METRIC</div>
                                <div className="font-bold text-rose-400 mt-0.5">
                                  {alt.evidence?.uniquePortsCount ? `${alt.evidence.uniquePortsCount} Probed Ports` :
                                   alt.evidence?.failedAttempts ? `${alt.evidence.failedAttempts} Auth Failures` :
                                   alt.evidence?.packetCount ? `${alt.evidence.packetCount} Packet Burst` :
                                   'Anomalous Frequency Surge'}
                                </div>
                              </div>
                              <div className={`p-2.5 rounded border ${
                                isDark ? 'bg-[#141B28] border-[#222E42]' : 'bg-slate-50 border-slate-200'
                              }`}>
                                <div className="text-[10px] text-slate-400">QUARANTINE ENFORCEMENT</div>
                                <div className="font-bold text-emerald-500 mt-0.5">iptables -A FORWARD -s {alt.sourceIp} -j DROP</div>
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Slide-Out Detail View Drawer */}
      <AlertDetailDrawer
        alert={selectedAlertForDrawer}
        packets={packets}
        onClose={() => setSelectedAlertForDrawer(null)}
        onIsolateIp={(ip) => onSelectAlertIp && onSelectAlertIp(ip)}
        isIsolated={blocklist.includes(selectedAlertForDrawer?.sourceIp || '')}
        theme={theme}
      />
    </div>
  );
};
