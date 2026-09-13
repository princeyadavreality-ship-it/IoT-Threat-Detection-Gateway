import React, { useState, useEffect } from 'react';
import { Sliders, Check, RotateCcw, ShieldCheck, Volume2, VolumeX, Play, MessageSquare, Radio, Shield } from 'lucide-react';
import { DetectionThresholds } from '../types';
import { DEFAULT_THRESHOLDS } from '../data/mockData';
import { speechEngine, SpeechSettings } from '../utils/speechNotification';

interface SettingsPanelProps {
  thresholds: DetectionThresholds;
  onSave: (thresholds: DetectionThresholds) => void;
  safetyMode: boolean;
  onToggleSafety: () => void;
  ttsEnabled: boolean;
  onToggleTts: () => void;
  theme?: 'dark' | 'light';
}

export const SettingsPanel: React.FC<SettingsPanelProps> = ({
  thresholds,
  onSave,
  safetyMode,
  onToggleSafety,
  ttsEnabled,
  onToggleTts,
  theme = 'dark',
}) => {
  const [formData, setFormData] = useState<DetectionThresholds>(thresholds);
  const [savedSuccess, setSavedSuccess] = useState(false);
  const [speechSettings, setSpeechSettings] = useState<SpeechSettings>(speechEngine.getSettings());
  const [availableVoices, setAvailableVoices] = useState<SpeechSynthesisVoice[]>([]);
  const [isTestingSpeech, setIsTestingSpeech] = useState<boolean>(false);
  const isSpeechSupported = speechEngine.isSupported();
  const isDark = theme === 'dark';

  useEffect(() => {
    setAvailableVoices(speechEngine.getVoices());
    const interval = setInterval(() => {
      const voices = speechEngine.getVoices();
      if (voices.length > 0) {
        setAvailableVoices(voices);
      }
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleSpeechSettingChange = (partial: Partial<SpeechSettings>) => {
    speechEngine.updateSettings(partial);
    setSpeechSettings(speechEngine.getSettings());
  };

  const handleTestSpeech = () => {
    setIsTestingSpeech(true);
    speechEngine.testVoiceAlert();
    setTimeout(() => setIsTestingSpeech(false), 2500);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave(formData);
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2000);
  };

  const handleReset = () => {
    setFormData(DEFAULT_THRESHOLDS);
  };

  return (
    <div className="max-w-4xl space-y-4">
      
      {/* Safety Mode Box */}
      <div className={`border rounded-xl p-4 lg:p-5 transition-colors ${
        isDark ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
      }`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="text-sm font-display font-bold flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-500" />
              <span>Kernel Response &amp; Isolation Enforcement Policy</span>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-xl font-sans">
              Specifies whether the mitigation engine compiles real operating system directives (<code className={`font-mono text-xs px-1.5 py-0.5 rounded border ${
                isDark ? 'bg-[#141B28] border-[#222E42] text-blue-400' : 'bg-slate-100 border-slate-200 text-blue-700'
              }`}>iptables / netsh</code>) or simulates execution within an in-memory test bench.
            </p>
          </div>

          <button
            onClick={onToggleSafety}
            className={`px-3.5 py-2 rounded-lg font-mono text-xs font-bold border transition-all cursor-pointer whitespace-nowrap ${
              safetyMode
                ? isDark
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                  : 'bg-emerald-50 text-emerald-700 border-emerald-200 hover:bg-emerald-100'
                : isDark
                  ? 'bg-rose-500/15 text-rose-300 border-rose-500/40 hover:bg-rose-500/25'
                  : 'bg-rose-50 text-rose-700 border-rose-200 hover:bg-rose-100'
            }`}
          >
            {safetyMode ? 'DRY-RUN (SIMULATED)' : 'ACTIVE KERNEL'}
          </button>
        </div>
      </div>

      {/* Browser Text-to-Speech Configuration Card */}
      <div className={`border rounded-xl p-4 lg:p-5 space-y-4 transition-colors ${
        isDark ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
      }`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-inherit">
          <div>
            <div className="flex items-center gap-2">
              <Volume2 className="w-4 h-4 text-blue-500" />
              <span className="font-display font-bold text-sm">
                Tactical Voice Synthesizer (TTS)
              </span>
              <span className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${
                ttsEnabled 
                  ? 'text-emerald-500 bg-emerald-500/10 border-emerald-500/20' 
                  : 'text-slate-400 bg-slate-800 border-slate-700'
              }`}>
                {ttsEnabled ? 'ACTIVE' : 'MUTED'}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl font-sans">
              Speaks tactical incident announcements using Web Speech synthesis when High-severity threat patterns trigger.
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={handleTestSpeech}
              disabled={isTestingSpeech}
              className={`px-3 py-1.5 rounded-lg border text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer disabled:opacity-50 ${
                isDark 
                  ? 'bg-[#141B28] border-[#222E42] text-slate-300 hover:text-white' 
                  : 'bg-slate-100 border-slate-200 text-slate-700 hover:text-slate-900'
              }`}
            >
              <Play className="w-3 h-3 text-blue-500" />
              <span>{isTestingSpeech ? 'Speaking...' : 'Test Speech'}</span>
            </button>

            <button
              type="button"
              onClick={() => {
                onToggleTts();
                handleSpeechSettingChange({ enabled: !ttsEnabled });
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold border transition-all cursor-pointer ${
                ttsEnabled
                  ? 'bg-blue-600 hover:bg-blue-700 text-white border-blue-600 shadow-xs'
                  : isDark 
                    ? 'bg-slate-800 text-slate-400 border-slate-700' 
                    : 'bg-slate-100 text-slate-600 border-slate-200'
              }`}
            >
              {ttsEnabled ? 'Voice Enabled' : 'Voice Muted'}
            </button>
          </div>
        </div>

        {/* TTS Parameters Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1 text-xs">
          
          {/* Verbosity */}
          <div className={`p-3 rounded-lg border space-y-2 ${
            isDark ? 'bg-[#121824] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
          }`}>
            <label className="text-slate-400 text-[11px] font-bold block uppercase tracking-wider">
              Speech Verbosity
            </label>
            <div className="grid grid-cols-2 gap-1.5">
              {(['brief', 'detailed'] as const).map((v) => (
                <button
                  key={v}
                  type="button"
                  onClick={() => handleSpeechSettingChange({ verbosity: v })}
                  className={`py-1 px-2 rounded text-xs font-semibold border cursor-pointer transition-all uppercase ${
                    speechSettings.verbosity === v
                      ? 'bg-blue-600 text-white border-blue-600 shadow-xs'
                      : isDark ? 'border-[#222E42] text-slate-400' : 'border-slate-200 text-slate-600'
                  }`}
                >
                  {v}
                </button>
              ))}
            </div>
            <span className="text-[11px] text-slate-400 block">
              {speechSettings.verbosity === 'brief' ? 'Speedy alerts (type + IP)' : 'Full report with verdict'}
            </span>
          </div>

          {/* Cadence Speed */}
          <div className={`p-3 rounded-lg border space-y-2 ${
            isDark ? 'bg-[#121824] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
          }`}>
            <div className="flex items-center justify-between">
              <label className="text-slate-400 text-[11px] font-bold block uppercase tracking-wider">
                Cadence Speed
              </label>
              <span className="text-blue-500 font-bold font-mono">
                {speechSettings.rate}x
              </span>
            </div>
            <input
              type="range"
              min="0.8"
              max="1.4"
              step="0.05"
              value={speechSettings.rate}
              onChange={(e) => handleSpeechSettingChange({ rate: parseFloat(e.target.value) })}
              className="w-full accent-blue-600 cursor-pointer"
            />
            <div className="flex justify-between text-[10px] text-slate-400 font-mono">
              <span>0.8x</span>
              <span>1.0x</span>
              <span>1.4x</span>
            </div>
          </div>

          {/* Voice Selector */}
          <div className={`p-3 rounded-lg border space-y-2 ${
            isDark ? 'bg-[#121824] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
          }`}>
            <label className="text-slate-400 text-[11px] font-bold block uppercase tracking-wider">
              Speech Voice
            </label>
            <select
              value={speechSettings.voiceURI || ''}
              onChange={(e) => handleSpeechSettingChange({ voiceURI: e.target.value || null })}
              className={`w-full px-2.5 py-1 rounded border text-xs outline-none focus:ring-1 focus:ring-blue-500 ${
                isDark 
                  ? 'bg-[#0B0F17] border-[#222E42] text-slate-200' 
                  : 'bg-white border-slate-300 text-slate-900'
              }`}
            >
              <option value="">Default English Voice (Auto)</option>
              {availableVoices
                .filter((v) => v.lang.startsWith('en'))
                .map((voice) => (
                  <option key={voice.voiceURI} value={voice.voiceURI}>
                    {voice.name} ({voice.lang})
                  </option>
                ))}
            </select>
            <span className="text-[11px] text-slate-400 block">
              {isSpeechSupported ? 'Web Speech API active' : 'Voice synthesis unavailable'}
            </span>
          </div>

        </div>
      </div>

      {/* Heuristic Thresholds Form */}
      <form onSubmit={handleSubmit} className={`border rounded-xl p-4 lg:p-5 space-y-4 font-mono text-xs transition-colors ${
        isDark ? 'bg-[#0F1522] border-[#1C2538]' : 'bg-white border-slate-200 shadow-xs'
      }`}>
        <div className="flex items-center justify-between border-b border-inherit pb-3">
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-blue-500" />
            <span className="font-display font-bold text-sm">
              Detection Heuristic Thresholds
            </span>
          </div>
          {savedSuccess && (
            <span className="text-emerald-500 text-xs flex items-center gap-1 font-bold bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
              <Check className="w-3.5 h-3.5" /> APPLIED
            </span>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
          
          {/* Port Scan */}
          <div className={`p-3.5 rounded-lg border space-y-2 ${
            isDark ? 'bg-[#121824] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
          }`}>
            <div className="font-bold uppercase text-[11px] flex items-center justify-between">
              <span>1. TCP Port Scan Reconnaissance</span>
              <span className="w-2 h-2 rounded-full bg-blue-500"></span>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div>
                <label className="text-slate-400 text-[10px] block mb-1">PROBED PORTS</label>
                <input
                  type="number"
                  min={2}
                  max={100}
                  value={formData.portScanUniquePorts}
                  onChange={(e) => setFormData({ ...formData, portScanUniquePorts: Number(e.target.value) })}
                  className={`w-full px-2.5 py-1 rounded border outline-none focus:ring-1 focus:ring-blue-500 ${
                    isDark ? 'bg-[#0B0F17] border-[#222E42] text-slate-200' : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>
              <div>
                <label className="text-slate-400 text-[10px] block mb-1">WINDOW (SEC)</label>
                <input
                  type="number"
                  step={0.5}
                  value={formData.portScanWindowSec}
                  onChange={(e) => setFormData({ ...formData, portScanWindowSec: Number(e.target.value) })}
                  className={`w-full px-2.5 py-1 rounded border outline-none focus:ring-1 focus:ring-blue-500 ${
                    isDark ? 'bg-[#0B0F17] border-[#222E42] text-slate-200' : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>
            </div>
          </div>

          {/* Brute Force */}
          <div className={`p-3.5 rounded-lg border space-y-2 ${
            isDark ? 'bg-[#121824] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
          }`}>
            <div className="font-bold uppercase text-[11px] flex items-center justify-between">
              <span>2. Credential Brute-Force Burst</span>
              <span className="w-2 h-2 rounded-full bg-rose-500"></span>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div>
                <label className="text-slate-400 text-[10px] block mb-1">FAILED ATTEMPTS</label>
                <input
                  type="number"
                  min={2}
                  max={50}
                  value={formData.bruteForceFailures}
                  onChange={(e) => setFormData({ ...formData, bruteForceFailures: Number(e.target.value) })}
                  className={`w-full px-2.5 py-1 rounded border outline-none focus:ring-1 focus:ring-blue-500 ${
                    isDark ? 'bg-[#0B0F17] border-[#222E42] text-slate-200' : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>
              <div>
                <label className="text-slate-400 text-[10px] block mb-1">WINDOW (SEC)</label>
                <input
                  type="number"
                  step={0.5}
                  value={formData.bruteForceWindowSec}
                  onChange={(e) => setFormData({ ...formData, bruteForceWindowSec: Number(e.target.value) })}
                  className={`w-full px-2.5 py-1 rounded border outline-none focus:ring-1 focus:ring-blue-500 ${
                    isDark ? 'bg-[#0B0F17] border-[#222E42] text-slate-200' : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>
            </div>
          </div>

          {/* C2 Beaconing */}
          <div className={`p-3.5 rounded-lg border space-y-2 ${
            isDark ? 'bg-[#121824] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
          }`}>
            <div className="font-bold uppercase text-[11px] flex items-center justify-between">
              <span>3. C2 Periodicity &amp; Jitter</span>
              <span className="w-2 h-2 rounded-full bg-amber-500"></span>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div>
                <label className="text-slate-400 text-[10px] block mb-1">MIN PULSES</label>
                <input
                  type="number"
                  min={3}
                  max={20}
                  value={formData.beaconingMinPackets}
                  onChange={(e) => setFormData({ ...formData, beaconingMinPackets: Number(e.target.value) })}
                  className={`w-full px-2.5 py-1 rounded border outline-none focus:ring-1 focus:ring-blue-500 ${
                    isDark ? 'bg-[#0B0F17] border-[#222E42] text-slate-200' : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>
              <div>
                <label className="text-slate-400 text-[10px] block mb-1">MAX JITTER (SEC)</label>
                <input
                  type="number"
                  step={0.05}
                  value={formData.beaconingMaxJitterSec}
                  onChange={(e) => setFormData({ ...formData, beaconingMaxJitterSec: Number(e.target.value) })}
                  className={`w-full px-2.5 py-1 rounded border outline-none focus:ring-1 focus:ring-blue-500 ${
                    isDark ? 'bg-[#0B0F17] border-[#222E42] text-slate-200' : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>
            </div>
          </div>

          {/* Volume Flood */}
          <div className={`p-3.5 rounded-lg border space-y-2 ${
            isDark ? 'bg-[#121824] border-[#1C2538]' : 'bg-slate-50 border-slate-200'
          }`}>
            <div className="font-bold uppercase text-[11px] flex items-center justify-between">
              <span>4. Volume Flood / Surge</span>
              <span className="w-2 h-2 rounded-full bg-purple-500"></span>
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div>
                <label className="text-slate-400 text-[10px] block mb-1">BYTES CEILING</label>
                <input
                  type="number"
                  step={1000}
                  value={formData.volumeFloodBytes}
                  onChange={(e) => setFormData({ ...formData, volumeFloodBytes: Number(e.target.value) })}
                  className={`w-full px-2.5 py-1 rounded border outline-none focus:ring-1 focus:ring-blue-500 ${
                    isDark ? 'bg-[#0B0F17] border-[#222E42] text-slate-200' : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>
              <div>
                <label className="text-slate-400 text-[10px] block mb-1">WINDOW (SEC)</label>
                <input
                  type="number"
                  step={0.5}
                  value={formData.volumeFloodWindowSec}
                  onChange={(e) => setFormData({ ...formData, volumeFloodWindowSec: Number(e.target.value) })}
                  className={`w-full px-2.5 py-1 rounded border outline-none focus:ring-1 focus:ring-blue-500 ${
                    isDark ? 'bg-[#0B0F17] border-[#222E42] text-slate-200' : 'bg-white border-slate-300 text-slate-900'
                  }`}
                />
              </div>
            </div>
          </div>

        </div>

        {/* Footer Actions */}
        <div className="pt-3 border-t border-inherit flex items-center justify-between">
          <button
            type="button"
            onClick={handleReset}
            className={`px-3 py-1.5 rounded-lg border flex items-center gap-1.5 cursor-pointer font-semibold transition-colors ${
              isDark 
                ? 'bg-[#141B28] text-slate-400 hover:text-white border-[#222E42]' 
                : 'bg-slate-100 text-slate-600 hover:text-slate-900 border-slate-200'
            }`}
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Defaults</span>
          </button>

          <button
            type="submit"
            className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-bold flex items-center gap-1.5 cursor-pointer transition-colors shadow-xs"
          >
            <Check className="w-3.5 h-3.5" />
            <span>Save Configuration</span>
          </button>
        </div>

      </form>

    </div>
  );
};
