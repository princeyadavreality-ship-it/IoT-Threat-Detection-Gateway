import React, { useState } from 'react';
import { Terminal, Copy, Check, FileCode, Download, Laptop, Server } from 'lucide-react';
import { PYTHON_CODE_FILES } from '../data/mockData';

interface PythonProjectViewerProps {
  theme?: 'dark' | 'light';
}

export const PythonProjectViewer: React.FC<PythonProjectViewerProps> = ({
  theme = 'dark',
}) => {
  const [activeFile, setActiveFile] = useState<keyof typeof PYTHON_CODE_FILES>('traffic_simulator.py');
  const [copied, setCopied] = useState(false);
  const isDark = theme === 'dark';

  const fileNames = Object.keys(PYTHON_CODE_FILES) as (keyof typeof PYTHON_CODE_FILES)[];

  const handleCopy = () => {
    navigator.clipboard.writeText(PYTHON_CODE_FILES[activeFile]);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = (fileName: string, content: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      
      {/* Overview Card */}
      <div className={`border rounded-xl p-4 lg:p-5 transition-colors ${
        isDark ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
      }`}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-inherit">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="p-1.5 rounded-lg bg-blue-500/10 text-blue-500">
                <Terminal className="w-4 h-4" />
              </div>
              <h2 className="text-sm font-display font-bold">
                Python IoT Security Gateway Suite
              </h2>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl font-sans">
              Production-ready Python modules for embedded Linux routers and Raspberry Pi edge nodes. Located in <code className={`font-mono px-1.5 py-0.5 rounded border text-[11px] ${
                isDark ? 'bg-[#141B28] border-[#222E42] text-blue-400' : 'bg-slate-100 border-slate-200 text-blue-700'
              }`}>/iot_gateway/</code>.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => handleDownload(activeFile, PYTHON_CODE_FILES[activeFile])}
              className={`px-3 py-1.5 rounded-lg border text-xs font-semibold flex items-center gap-1.5 cursor-pointer transition-all ${
                isDark 
                  ? 'bg-[#141B28] border-[#222E42] text-slate-300 hover:text-white' 
                  : 'bg-slate-100 border-slate-200 text-slate-700 hover:text-slate-900'
              }`}
            >
              <Download className="w-3.5 h-3.5 text-blue-500" />
              <span>Download {activeFile}</span>
            </button>
            <button
              onClick={handleCopy}
              className="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold flex items-center gap-1.5 cursor-pointer transition-all shadow-xs"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-white" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy Code'}</span>
            </button>
          </div>
        </div>

        {/* Guides Grid */}
        <div className="mt-3.5 grid grid-cols-1 md:grid-cols-2 gap-3.5 text-xs">
          <div className={`p-4 rounded-xl border space-y-2.5 ${
            isDark ? 'bg-[#121824] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
          }`}>
            <div className="flex items-center gap-2 font-bold font-display uppercase tracking-wider text-[11px]">
              <Laptop className="w-4 h-4 text-blue-500" />
              <span>Execution Guide (CLI &amp; PowerShell)</span>
            </div>
            <div className="space-y-1.5 font-mono text-[11px]">
              <div className="text-slate-400"># Navigate to Python package root:</div>
              <div className={`px-2.5 py-1 rounded border font-semibold ${
                isDark ? 'bg-[#0B0F17] border-[#222E42] text-slate-200' : 'bg-white border-slate-200 text-slate-800'
              }`}>cd iot_gateway</div>
              <div className="text-slate-400"># Install dependencies:</div>
              <div className={`px-2.5 py-1 rounded border font-semibold ${
                isDark ? 'bg-[#0B0F17] border-[#222E42] text-slate-200' : 'bg-white border-slate-200 text-slate-800'
              }`}>pip install -r requirements.txt</div>
              <div className="text-slate-400"># Run terminal engine simulation:</div>
              <div className={`px-2.5 py-1 rounded border font-bold text-emerald-500 ${
                isDark ? 'bg-[#0B0F17] border-[#222E42]' : 'bg-white border-slate-200'
              }`}>python main.py</div>
            </div>
          </div>

          <div className={`p-4 rounded-xl border space-y-2.5 ${
            isDark ? 'bg-[#121824] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
          }`}>
            <div className="flex items-center gap-2 font-bold font-display uppercase tracking-wider text-[11px]">
              <Server className="w-4 h-4 text-emerald-500" />
              <span>Hardware Gateway &amp; Live Sniffing</span>
            </div>
            <div className="space-y-2 text-slate-400 font-sans leading-relaxed">
              <p>
                To monitor physical IoT devices on a Linux router interface or Raspberry Pi, install tshark:
              </p>
              <div className={`px-2.5 py-1 rounded text-xs font-mono font-bold border text-blue-500 ${
                isDark ? 'bg-[#0B0F17] border-[#222E42]' : 'bg-white border-slate-200'
              }`}>
                sudo apt-get install tshark &amp;&amp; pip install pyshark
              </div>
              <p>
                Pipe <code className="text-emerald-500 font-mono">pyshark.LiveCapture(interface='eth0')</code> directly into <code className="text-emerald-500 font-mono">DetectionEngine.analyze_packets()</code>.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Code Viewer */}
      <div className={`border rounded-xl overflow-hidden transition-colors ${
        isDark ? 'bg-[#0B0F17] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
      }`}>
        
        {/* File Tabs */}
        <div className={`flex border-b overflow-x-auto no-scrollbar ${
          isDark ? 'border-[#1C2538] bg-[#121824]' : 'border-slate-200 bg-slate-50'
        }`}>
          {fileNames.map((name) => (
            <button
              key={name}
              onClick={() => setActiveFile(name)}
              className={`px-4 py-2.5 text-xs font-mono font-semibold flex items-center gap-2 border-b-2 whitespace-nowrap cursor-pointer transition-all ${
                activeFile === name
                  ? isDark
                    ? 'border-blue-500 text-blue-400 bg-[#0B0F17]'
                    : 'border-blue-600 text-blue-700 bg-white'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>{name}</span>
            </button>
          ))}
        </div>

        {/* Code Content */}
        <div className={`p-4 overflow-x-auto max-h-[550px] overflow-y-auto font-mono text-xs leading-relaxed select-text ${
          isDark ? 'bg-[#0B0F17] text-slate-300' : 'bg-slate-900 text-slate-100'
        }`}>
          <pre>
            <code>{PYTHON_CODE_FILES[activeFile]}</code>
          </pre>
        </div>

      </div>

    </div>
  );
};
