// Browser-based Text-to-Speech (TTS) Notification Engine using Web Speech API
import { ThreatAlert } from '../types';

export interface SpeechSettings {
  enabled: boolean;
  rate: number; // 0.8 to 1.4
  pitch: number; // 0.8 to 1.2
  volume: number; // 0.0 to 1.0
  verbosity: 'brief' | 'detailed';
  voiceURI: string | null;
}

type SpeechListener = (isSpeaking: boolean, text: string | null, alertId?: string) => void;

class TacticalSpeechEngine {
  private synth: SpeechSynthesis | null = null;
  private settings: SpeechSettings = {
    enabled: true,
    rate: 1.05,
    pitch: 1.0,
    volume: 1.0,
    verbosity: 'brief',
    voiceURI: null,
  };
  private availableVoices: SpeechSynthesisVoice[] = [];
  private listeners: Set<SpeechListener> = new Set();
  private currentlySpeaking: boolean = false;
  private currentText: string | null = null;
  private lastSpokenAlertKey: string | null = null;
  private lastSpokenTime: number = 0;

  constructor() {
    if (typeof window !== 'undefined' && 'speechSynthesis' in window) {
      this.synth = window.speechSynthesis;
      this.loadSettings();
      this.initVoices();
    }
  }

  private loadSettings() {
    try {
      const saved = localStorage.getItem('tactical_tts_settings');
      if (saved) {
        const parsed = JSON.parse(saved);
        this.settings = { ...this.settings, ...parsed };
      }
    } catch {
      // LocalStorage unavailable
    }
  }

  private saveSettings() {
    try {
      localStorage.setItem('tactical_tts_settings', JSON.stringify(this.settings));
    } catch {
      // Ignore
    }
  }

  private initVoices() {
    if (!this.synth) return;

    const populate = () => {
      if (!this.synth) return;
      this.availableVoices = this.synth.getVoices();
    };

    populate();
    if (this.synth.onvoiceschanged !== undefined) {
      this.synth.onvoiceschanged = populate;
    }
  }

  public isSupported(): boolean {
    return typeof window !== 'undefined' && 'speechSynthesis' in window;
  }

  public getVoices(): SpeechSynthesisVoice[] {
    if (this.availableVoices.length === 0 && this.synth) {
      this.availableVoices = this.synth.getVoices();
    }
    return this.availableVoices;
  }

  public getSettings(): SpeechSettings {
    return { ...this.settings };
  }

  public updateSettings(partial: Partial<SpeechSettings>) {
    this.settings = { ...this.settings, ...partial };
    this.saveSettings();
  }

  public setEnabled(enabled: boolean) {
    this.settings.enabled = enabled;
    this.saveSettings();
    if (!enabled) {
      this.stop();
    }
  }

  public isEnabled(): boolean {
    return this.settings.enabled;
  }

  public isSpeaking(): boolean {
    return this.currentlySpeaking;
  }

  public getCurrentText(): string | null {
    return this.currentText;
  }

  public subscribe(listener: SpeechListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(isSpeaking: boolean, text: string | null, alertId?: string) {
    this.currentlySpeaking = isSpeaking;
    this.currentText = text;
    this.listeners.forEach((l) => l(isSpeaking, text, alertId));
  }

  public stop() {
    if (this.synth) {
      try {
        this.synth.cancel();
      } catch {
        // Ignore
      }
    }
    this.notify(false, null);
  }

  /**
   * Speak a notification for HIGH severity threat alerts.
   */
  public speakHighThreatAlert(alert: ThreatAlert): boolean {
    if (!this.settings.enabled || !this.synth) return false;
    if (alert.severity !== 'HIGH') return false;

    // Suppress repeated calls for the identical alert within 8 seconds
    const now = Date.now();
    const alertKey = `${alert.category}-${alert.sourceIp}-${alert.targetIp}`;
    if (this.lastSpokenAlertKey === alertKey && now - this.lastSpokenTime < 8000) {
      return false;
    }
    this.lastSpokenAlertKey = alertKey;
    this.lastSpokenTime = now;

    const spokenText = this.formatAlertMessage(alert, this.settings.verbosity);
    return this.speakText(spokenText, alert.id);
  }

  /**
   * Speak multiple HIGH alerts arriving in a batch
   */
  public speakBatchHighAlerts(highAlerts: ThreatAlert[]): boolean {
    if (!this.settings.enabled || !this.synth || highAlerts.length === 0) return false;

    if (highAlerts.length === 1) {
      return this.speakHighThreatAlert(highAlerts[0]);
    }

    const first = highAlerts[0];
    const categoryName = this.formatCategoryName(first.category);
    const spokenText = `Security Alert: ${highAlerts.length} high severity threats intercepted. Primary vector: ${categoryName} from IP ${first.sourceIp}. Automated quarantine engaged.`;

    return this.speakText(spokenText, first.id);
  }

  /**
   * Test current voice settings with a preview sentence
   */
  public testVoiceAlert(): boolean {
    const sampleText = 'Security Alert: High severity intrusion detected on IoT gateway. Threat containment active.';
    return this.speakText(sampleText, 'test-preview');
  }

  /**
   * Core speech dispatcher
   */
  public speakText(text: string, alertId?: string): boolean {
    if (!this.synth) return false;

    try {
      // Cancel any ongoing speech to ensure immediate priority for this high alert
      this.synth.cancel();

      const utterance = new SpeechSynthesisUtterance(text);
      utterance.rate = this.settings.rate;
      utterance.pitch = this.settings.pitch;
      utterance.volume = this.settings.volume;

      // Select preferred voice
      const voices = this.getVoices();
      if (this.settings.voiceURI) {
        const matching = voices.find((v) => v.voiceURI === this.settings.voiceURI);
        if (matching) utterance.voice = matching;
      } else if (voices.length > 0) {
        // Default to a clear English voice
        const preferred =
          voices.find(
            (v) =>
              v.lang.startsWith('en') &&
              (v.name.includes('Natural') ||
                v.name.includes('Google') ||
                v.name.includes('Samantha') ||
                v.name.includes('David') ||
                v.name.includes('Daniel') ||
                v.name.includes('Alex'))
          ) ||
          voices.find((v) => v.lang.startsWith('en')) ||
          voices[0];

        if (preferred) {
          utterance.voice = preferred;
        }
      }

      utterance.onstart = () => {
        this.notify(true, text, alertId);
      };

      utterance.onend = () => {
        this.notify(false, null);
      };

      utterance.onerror = () => {
        this.notify(false, null);
      };

      this.synth.speak(utterance);
      return true;
    } catch {
      this.notify(false, null);
      return false;
    }
  }

  private formatCategoryName(cat: string): string {
    switch (cat) {
      case 'PORT_SCAN':
        return 'Port Scan';
      case 'BRUTE_FORCE':
        return 'Credential Brute Force';
      case 'C2_BEACONING':
        return 'Command and Control Beacon';
      case 'VOLUME_FLOOD':
        return 'Volume Flood Denial of Service';
      default:
        return cat.replace(/_/g, ' ');
    }
  }

  private formatAlertMessage(alert: ThreatAlert, verbosity: 'brief' | 'detailed'): string {
    const categoryName = this.formatCategoryName(alert.category);

    if (verbosity === 'brief') {
      switch (alert.category) {
        case 'PORT_SCAN':
          return `Warning: High severity Port Scan detected from IP ${alert.sourceIp} targeting ${alert.targetIp}.`;
        case 'BRUTE_FORCE':
          return `Warning: High severity Brute Force attack detected from IP ${alert.sourceIp}. Credential surge blocked.`;
        case 'C2_BEACONING':
          return `Warning: High severity Command and Control beacon detected on device ${alert.sourceIp}. Checkin halted.`;
        case 'VOLUME_FLOOD':
          return `Warning: High severity Volume Flood attack detected from IP ${alert.sourceIp}. Traffic dropped.`;
        default:
          return `Warning: High severity security alert. ${categoryName} from IP ${alert.sourceIp}.`;
      }
    }

    // Detailed format
    switch (alert.category) {
      case 'PORT_SCAN':
        return `Security Alert: High severity TCP port scan detected from host ${alert.sourceIp} probing ${alert.targetIp}. Automated firewall isolation engaged.`;
      case 'BRUTE_FORCE':
        return `Security Alert: High severity credential brute force detected from host ${alert.sourceIp} against management port on ${alert.targetIp}. Authentication attempts dropped.`;
      case 'C2_BEACONING':
        return `Security Alert: High severity Command and Control telemetry beacon detected from internal host ${alert.sourceIp}. Malicious outbound session quarantined.`;
      case 'VOLUME_FLOOD':
        return `Security Alert: High severity UDP volume flood surge detected from host ${alert.sourceIp}. Ingress packets dropped at gateway.`;
      default:
        return `Security Alert: High severity threat detected. Category: ${categoryName}. Originating IP: ${alert.sourceIp}. Target: ${alert.targetIp}. Containment active.`;
    }
  }
}

export const speechEngine = new TacticalSpeechEngine();
