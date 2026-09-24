import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { Scan, ScanProfile } from '../types/scan';
import { Finding, SeverityCount } from '../types/finding';
import { scanService } from '../services/scanService';
import { findingsService } from '../services/findingsService';

interface ScanContextType {
  scans: Scan[];
  findings: Finding[];
  loading: boolean;
  severityStats: SeverityCount;
  createScan: (target: string, profile: ScanProfile, goal?: string) => Promise<Scan>;
  stopScan: (id: string) => Promise<void>;
  resetDemoData: () => Promise<void>;
  refreshData: () => Promise<void>;
  updateFindingStatus: (id: string, status: Finding['status']) => Promise<void>;
}

const ScanContext = createContext<ScanContextType | undefined>(undefined);

export const ScanProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [severityStats, setSeverityStats] = useState<SeverityCount>({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: 0,
  });

  const refreshData = useCallback(async () => {
    try {
      const [allScans, allFindings, stats] = await Promise.all([
        scanService.getScans(),
        findingsService.getFindings(),
        findingsService.getSeverityStats(),
      ]);
      setScans(allScans);
      setFindings(allFindings);
      setSeverityStats(stats);
    } catch (err) {
      console.error('Failed to load initial security data', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshData();
  }, [refreshData]);

  const createScan = async (target: string, profile: ScanProfile, goal?: string): Promise<Scan> => {
    const newScan = await scanService.createScan({ target, profile, goal });
    await refreshData();
    return newScan;
  };

  const stopScan = async (id: string): Promise<void> => {
    await scanService.stopScan(id);
    await refreshData();
  };

  const updateFindingStatus = async (id: string, status: Finding['status']): Promise<void> => {
    await findingsService.updateFindingStatus(id, status);
    await refreshData();
  };

  const resetDemoData = async (): Promise<void> => {
    setLoading(true);
    await scanService.resetToDefaults();
    await findingsService.resetToDefaults();
    await refreshData();
  };

  return (
    <ScanContext.Provider
      value={{
        scans,
        findings,
        loading,
        severityStats,
        createScan,
        stopScan,
        resetDemoData,
        refreshData,
        updateFindingStatus,
      }}
    >
      {children}
    </ScanContext.Provider>
  );
};

export function useScans() {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error('useScans must be used within a ScanProvider');
  }
  return context;
}
