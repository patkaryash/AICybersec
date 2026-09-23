import { Finding, Severity } from '../types/finding';
import { INITIAL_FINDINGS } from './mockData';

const STORAGE_KEY = 'sentinel_ai_findings';

function getStoredFindings(): Finding[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(INITIAL_FINDINGS));
      return INITIAL_FINDINGS;
    }
    return JSON.parse(raw);
  } catch (e) {
    console.warn('Failed to parse findings from localStorage, falling back to defaults', e);
    return INITIAL_FINDINGS;
  }
}

function saveStoredFindings(findings: Finding[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(findings));
  } catch (e) {
    console.error('Failed to save findings to localStorage', e);
  }
}

export const findingsService = {
  async getFindings(): Promise<Finding[]> {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve(getStoredFindings());
      }, 80);
    });
  },

  async getFindingById(id: string): Promise<Finding | undefined> {
    return new Promise((resolve) => {
      setTimeout(() => {
        const findings = getStoredFindings();
        resolve(findings.find((f) => f.id === id));
      }, 50);
    });
  },

  async getFindingsByScanId(scanId: string): Promise<Finding[]> {
    return new Promise((resolve) => {
      setTimeout(() => {
        const findings = getStoredFindings();
        resolve(findings.filter((f) => f.scanId === scanId));
      }, 60);
    });
  },

  async addFinding(finding: Finding): Promise<Finding> {
    return new Promise((resolve) => {
      const findings = getStoredFindings();
      const updated = [finding, ...findings];
      saveStoredFindings(updated);
      resolve(finding);
    });
  },

  async updateFindingStatus(id: string, status: Finding['status']): Promise<Finding | undefined> {
    return new Promise((resolve) => {
      const findings = getStoredFindings();
      const index = findings.findIndex((f) => f.id === id);
      if (index === -1) {
        resolve(undefined);
        return;
      }
      findings[index] = {
        ...findings[index],
        status,
      };
      saveStoredFindings(findings);
      resolve(findings[index]);
    });
  },

  async getSeverityStats(): Promise<{
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  }> {
    const findings = getStoredFindings();
    const stats = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      total: findings.length,
    };

    findings.forEach((f) => {
      if (f.severity in stats) {
        stats[f.severity as Severity]++;
      }
    });

    return stats;
  },

  async resetToDefaults(): Promise<Finding[]> {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(INITIAL_FINDINGS));
    return INITIAL_FINDINGS;
  },
};
