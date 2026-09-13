import React, { useState } from 'react';
import { X, Sliders, Check, RotateCcw } from 'lucide-react';
import { DetectionThresholds } from '../types';
import { DEFAULT_THRESHOLDS } from '../data/mockData';

interface ThresholdsModalProps {
  isOpen: boolean;
  onClose: () => void;
  thresholds: DetectionThresholds;
  onSave: (thresholds: DetectionThresholds) => void;
}

export const ThresholdsModal: React.FC<ThresholdsModalProps> = ({
  isOpen,
  onClose,
  thresholds,
  onSave,
}) => {
  const [formData, setFormData] = useState<DetectionThresholds>(thresholds);

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave(formData);
    onClose();
  };

  const handleReset = () => {
    setFormData(DEFAULT_THRESHOLDS);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg overflow-hidden shadow-2xl">
        
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-blue-400" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider">
              Detection Rule Thresholds &amp; Parameters
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4 text-xs">
          <p className="text-slate-400 text-[11px]">
            Adjust the heuristic thresholds used by the Suricata/Snort-style detection engine to classify traffic anomalies into high-severity alerts.
          </p>

          {/* 1. Port Scan */}
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-2">
            <div className="font-bold text-white">1. Port Scan Thresholds</div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-slate-400 block mb-1">Unique Ports Trigger</label>
                <input
                  type="number"
                  min={2}
                  max={100}
                  value={formData.portScanUniquePorts}
                  onChange={(e) => setFormData({ ...formData, portScanUniquePorts: Number(e.target.value) })}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Sliding Window (Sec)</label>
                <input
                  type="number"
                  step={0.5}
                  value={formData.portScanWindowSec}
                  onChange={(e) => setFormData({ ...formData, portScanWindowSec: Number(e.target.value) })}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </div>
            </div>
          </div>

          {/* 2. Brute Force */}
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-2">
            <div className="font-bold text-white">2. Brute-Force Auth Thresholds</div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-slate-400 block mb-1">Failed Attempts Trigger</label>
                <input
                  type="number"
                  min={2}
                  max={50}
                  value={formData.bruteForceFailures}
                  onChange={(e) => setFormData({ ...formData, bruteForceFailures: Number(e.target.value) })}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Sliding Window (Sec)</label>
                <input
                  type="number"
                  step={0.5}
                  value={formData.bruteForceWindowSec}
                  onChange={(e) => setFormData({ ...formData, bruteForceWindowSec: Number(e.target.value) })}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </div>
            </div>
          </div>

          {/* 3. C2 Beaconing */}
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-2">
            <div className="font-bold text-white">3. C2 Beaconing Jitter Metric</div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-slate-400 block mb-1">Min Consecutive Packets</label>
                <input
                  type="number"
                  min={3}
                  max={20}
                  value={formData.beaconingMinPackets}
                  onChange={(e) => setFormData({ ...formData, beaconingMinPackets: Number(e.target.value) })}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Max Jitter Std-Dev (Sec)</label>
                <input
                  type="number"
                  step={0.05}
                  value={formData.beaconingMaxJitterSec}
                  onChange={(e) => setFormData({ ...formData, beaconingMaxJitterSec: Number(e.target.value) })}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </div>
            </div>
          </div>

          {/* 4. Volume Flood */}
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-2">
            <div className="font-bold text-white">4. Volume Flood Ceiling</div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-slate-400 block mb-1">Byte Ceiling Limit</label>
                <input
                  type="number"
                  step={1000}
                  value={formData.volumeFloodBytes}
                  onChange={(e) => setFormData({ ...formData, volumeFloodBytes: Number(e.target.value) })}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </div>
              <div>
                <label className="text-slate-400 block mb-1">Time Window (Sec)</label>
                <input
                  type="number"
                  step={0.5}
                  value={formData.volumeFloodWindowSec}
                  onChange={(e) => setFormData({ ...formData, volumeFloodWindowSec: Number(e.target.value) })}
                  className="w-full px-2.5 py-1.5 rounded bg-slate-900 border border-slate-700 text-white font-mono"
                />
              </div>
            </div>
          </div>

          {/* Modal Footer Actions */}
          <div className="pt-2 flex items-center justify-between">
            <button
              type="button"
              onClick={handleReset}
              className="px-3 py-1.5 rounded bg-slate-800 text-slate-400 hover:text-white border border-slate-700 flex items-center gap-1.5 cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Reset to Defaults</span>
            </button>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={onClose}
                className="px-3 py-1.5 rounded bg-slate-800 text-slate-300 hover:bg-slate-700 cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-semibold flex items-center gap-1.5 cursor-pointer"
              >
                <Check className="w-3.5 h-3.5" />
                <span>Apply Thresholds</span>
              </button>
            </div>
          </div>

        </form>

      </div>
    </div>
  );
};
