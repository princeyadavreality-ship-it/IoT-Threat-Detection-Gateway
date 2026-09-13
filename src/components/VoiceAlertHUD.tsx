import React, { useState, useEffect, useRef } from 'react';
import { Volume2, VolumeX, Square, X, AlertTriangle, Radio } from 'lucide-react';
import { speechEngine } from '../utils/speechNotification';

interface VoiceAlertHUDProps {
  theme?: 'dark' | 'light';
}

export const VoiceAlertHUD: React.FC<VoiceAlertHUDProps> = ({
  theme = 'dark',
}) => {
  const [isSpeaking, setIsSpeaking] = useState<boolean>(() => speechEngine.isSpeaking());
  const [spokenText, setSpokenText] = useState<string | null>(() => speechEngine.getCurrentText());
  const [visible, setVisible] = useState<boolean>(() => speechEngine.isSpeaking());
  const autoDismissTimerRef = useRef<NodeJS.Timeout | null>(null);
  const isDark = theme === 'dark';

  useEffect(() => {
    const unsubscribe = speechEngine.subscribe((speaking, text) => {
      setIsSpeaking(speaking);
      if (speaking && text) {
        setSpokenText(text);
        setVisible(true);
        if (autoDismissTimerRef.current) {
          clearTimeout(autoDismissTimerRef.current);
          autoDismissTimerRef.current = null;
        }
      } else if (!speaking) {
        if (autoDismissTimerRef.current) {
          clearTimeout(autoDismissTimerRef.current);
        }
        // Keep visible for 4 seconds after finishing speech so user can read transcript
        autoDismissTimerRef.current = setTimeout(() => {
          setVisible(false);
        }, 4000);
      }
    });

    return () => {
      unsubscribe();
      if (autoDismissTimerRef.current) {
        clearTimeout(autoDismissTimerRef.current);
      }
    };
  }, []);

  const handleClose = () => {
    setVisible(false);
    if (autoDismissTimerRef.current) {
      clearTimeout(autoDismissTimerRef.current);
      autoDismissTimerRef.current = null;
    }
  };

  if (!visible || !spokenText) return null;

  return (
    <div className="fixed bottom-6 right-6 z-50 max-w-md w-full animate-in slide-in-from-bottom-5 duration-300 pointer-events-auto">
      <div className={`border rounded-2xl p-4 shadow-2xl backdrop-blur-md transition-all ${
        isDark 
          ? 'bg-[#0F1522]/95 border-rose-500/40 text-slate-100' 
          : 'bg-white/95 border-rose-200 text-slate-900 shadow-xl'
      }`}>
        
        {/* Header Ribbon */}
        <div className="flex items-center justify-between pb-3 border-b border-inherit">
          <div className="flex items-center gap-2.5">
            <span className="relative flex h-2.5 w-2.5">
              {isSpeaking ? (
                <>
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-500 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-rose-500"></span>
                </>
              ) : (
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
              )}
            </span>
            <span className="font-display font-bold text-xs uppercase tracking-wider text-rose-500">
              {isSpeaking ? 'Voice Alert Transmitting...' : 'High Priority Voice Broadcast'}
            </span>
          </div>

          <div className="flex items-center gap-2">
            {isSpeaking && (
              <button
                onClick={() => speechEngine.stop()}
                className={`px-2.5 py-1 rounded-md text-xs font-semibold flex items-center gap-1 cursor-pointer transition-all border ${
                  isDark 
                    ? 'bg-[#141B28] text-slate-300 border-[#222E42] hover:text-white' 
                    : 'bg-slate-100 text-slate-700 border-slate-200 hover:text-slate-900'
                }`}
                title="Silence active audio playback"
              >
                <Square className="w-2.5 h-2.5 fill-current text-rose-500" />
                <span>Silence</span>
              </button>
            )}
            <button
              onClick={handleClose}
              className="p-1 rounded-lg text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
              title="Dismiss notification"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content */}
        <div className="mt-3 flex items-start gap-3">
          <div className="w-9 h-9 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-500 flex items-center justify-center shrink-0">
            <Volume2 className={`w-5 h-5 ${isSpeaking ? 'animate-pulse' : ''}`} />
          </div>

          <div className="flex-1 space-y-1">
            <div className="text-[11px] font-mono text-slate-400 flex items-center justify-between">
              <span>VOICE TRANSMISSION TRANSCRIPT</span>
              {isSpeaking && (
                <div className="flex items-center gap-0.5">
                  <span className="w-1 h-3 bg-rose-500 animate-[pulse_0.6s_ease-in-out_infinite]"></span>
                  <span className="w-1 h-4 bg-rose-500 animate-[pulse_0.4s_ease-in-out_infinite]"></span>
                  <span className="w-1 h-2.5 bg-rose-500 animate-[pulse_0.7s_ease-in-out_infinite]"></span>
                  <span className="w-1 h-3.5 bg-rose-500 animate-[pulse_0.5s_ease-in-out_infinite]"></span>
                </div>
              )}
            </div>

            <p className="text-xs font-sans leading-relaxed select-text font-medium">
              "{spokenText}"
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-3 pt-2.5 border-t border-inherit flex items-center justify-between text-[11px] font-mono text-slate-400">
          <span className="flex items-center gap-1.5 text-rose-500 font-semibold">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>CRITICAL INCIDENT</span>
          </span>

          <span>Web Speech API</span>
        </div>

      </div>
    </div>
  );
};
