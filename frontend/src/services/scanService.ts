import { Scan, ScanProfile, SCAN_PROFILES } from '../types/scan';
import { INITIAL_SCANS } from './mockData';

const STORAGE_KEY = 'sentinel_ai_scans';

function getStoredScans(): Scan[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(INITIAL_SCANS));
      return INITIAL_SCANS;
    }
    return JSON.parse(raw);
  } catch (e) {
    console.warn('Failed to parse scans from localStorage, falling back to defaults', e);
    return INITIAL_SCANS;
  }
}

function saveStoredScans(scans: Scan[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(scans));
  } catch (e) {
    console.error('Failed to save scans to localStorage', e);
  }
}

export const scanService = {
  async getScans(): Promise<Scan[]> {
    // Simulated async to allow drop-in replacement with fetch('/runs')
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve(getStoredScans());
      }, 80);
    });
  },

  async getScanById(id: string): Promise<Scan | undefined> {
    return new Promise((resolve) => {
      setTimeout(() => {
        const scans = getStoredScans();
        resolve(scans.find((s) => s.id === id));
      }, 50);
    });
  },

  async createScan(params: {
    target: string;
    profile: ScanProfile;
    goal?: string;
  }): Promise<Scan> {
    return new Promise((resolve) => {
      setTimeout(() => {
        const scans = getStoredScans();
        const profileInfo = SCAN_PROFILES[params.profile];
        const newId = `scan-${Math.random().toString(36).substring(2, 10)}`;

        const totalSteps = params.profile === 'recon' ? 4 : params.profile === 'web_assessment' ? 5 : 6;

        const newScan: Scan = {
          id: newId,
          target: params.target.trim().replace(/^https?:\/\//, ''),
          profile: params.profile,
          status: 'running',
          startedAt: new Date().toISOString(),
          findingsCount: {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            info: 0,
            total: 0,
          },
          currentStep: 1,
          totalSteps,
          goal: params.goal || profileInfo.description,
          notes: `Autonomous scan initiated with ${profileInfo.name} profile.`,
          isSimulated: true,
        };

        const updated = [newScan, ...scans];
        saveStoredScans(updated);
        resolve(newScan);
      }, 150);
    });
  },

  async stopScan(id: string): Promise<Scan | undefined> {
    return new Promise((resolve) => {
      const scans = getStoredScans();
      const index = scans.findIndex((s) => s.id === id);
      if (index === -1) {
        resolve(undefined);
        return;
      }

      scans[index] = {
        ...scans[index],
        status: 'cancelled',
        completedAt: new Date().toISOString(),
        notes: 'Scan interrupted by operator.',
      };

      saveStoredScans(scans);
      resolve(scans[index]);
    });
  },

  async updateScanStatus(id: string, updates: Partial<Scan>): Promise<Scan | undefined> {
    return new Promise((resolve) => {
      const scans = getStoredScans();
      const index = scans.findIndex((s) => s.id === id);
      if (index === -1) {
        resolve(undefined);
        return;
      }

      scans[index] = {
        ...scans[index],
        ...updates,
      };

      saveStoredScans(scans);
      resolve(scans[index]);
    });
  },

  async resetToDefaults(): Promise<Scan[]> {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(INITIAL_SCANS));
    return INITIAL_SCANS;
  },
};
