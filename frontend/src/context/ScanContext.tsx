import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
} from 'react';
import { Scan, ScanProfile } from '../types/scan';
import { Finding, SeverityCount } from '../types/finding';
import { ProjectOut } from '../types/contract';
import { isDemoMode, setDemoMode as setConfigDemoMode } from '../services/config';
import { scanService as realScanService } from '../services/api/scanService';
import { findingService as realFindingService } from '../services/api/findingService';
import { projectService as realProjectService } from '../services/api/projectService';
import { dashboardService as realDashboardService } from '../services/api/dashboardService';
import { scanService as mockScanService } from '../services/scanService';
import { findingsService as mockFindingsService } from '../services/findingsService';
import {
  mapScanOutToScan,
  mapFindingOutToFinding,
  inferScopeFromTarget,
} from '../services/adapters';
import { ApiClientError } from '../services/apiClient';
import { useAuth } from './AuthContext';

interface ScanContextType {
  scans: Scan[];
  findings: Finding[];
  projects: ProjectOut[];
  loading: boolean;
  error: string | null;
  severityStats: SeverityCount;
  isDemo: boolean;
  createScan: (
    target: string,
    profile: ScanProfile,
    goal?: string,
    projectId?: string
  ) => Promise<Scan>;
  stopScan: (id: string) => Promise<void>;
  resetDemoData: () => Promise<void>;
  refreshData: () => Promise<void>;
  updateFindingStatus: (id: string, status: Finding['status']) => Promise<void>;
  toggleDemoMode: (enable: boolean) => void;
  clearError: () => void;
}

const ScanContext = createContext<ScanContextType | undefined>(undefined);

export const ScanProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // Auth state gates real-API fetching: ScanProvider mounts inside
  // AuthProvider, but child effects run BEFORE parent effects — so an
  // ungated fetch here would hit the API before the session restore
  // attaches the token, 401, and wipe the stored session via the
  // apiClient's global unauthorized handler.
  const { isAuthenticated, isLoading: authLoading } = useAuth();
  const [isDemo, setIsDemo] = useState<boolean>(isDemoMode);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [projects, setProjects] = useState<ProjectOut[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [severityStats, setSeverityStats] = useState<SeverityCount>({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: 0,
  });

  const isRefreshingRef = useRef(false);

  const toggleDemoMode = useCallback((enable: boolean) => {
    setConfigDemoMode(enable);
    setIsDemo(enable);
    setError(null);
  }, []);

  const refreshData = useCallback(async () => {
    // Protected data fetching must wait until session restoration has finished.
    // If not demo mode and session restoration is still in progress, do NOT
    // execute requests or prematurely treat the state as unauthenticated.
    if (!isDemo && authLoading) {
      return;
    }

    if (isRefreshingRef.current) return;
    isRefreshingRef.current = true;
    setError(null);

    try {
      if (isDemo) {
        // DEMO MODE: load mock data from localStorage
        const [allScans, allFindings, stats] = await Promise.all([
          mockScanService.getScans(),
          mockFindingsService.getFindings(),
          mockFindingsService.getSeverityStats(),
        ]);
        setScans(allScans);
        setFindings(allFindings);
        setSeverityStats(stats);
        setProjects([]);
      } else if (!isAuthenticated) {
        // Session restoration finished and user is not authenticated:
        // Present empty state; ProtectedRoute will handle unauthenticated redirect.
        setScans([]);
        setFindings([]);
        setProjects([]);
        setSeverityStats({
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
          total: 0,
        });
      } else {
        // REAL API MODE: load from /api/v1 (authenticated session verified)
        const [dash, scansRes, projectsRes] = await Promise.all([
          realDashboardService.getDashboard(10),
          realScanService.listScans({ pageSize: 50 }),
          realProjectService.listProjects(1, 50),
        ]);

        const mappedScans = scansRes.items.map(mapScanOutToScan);
        setScans(mappedScans);
        setProjects(projectsRes.items);

        // Fetch findings across scans (first 5 scans to avoid excessive requests)
        const activeOrRecentScans = scansRes.items.slice(0, 5);
        const findingsPromises = activeOrRecentScans.map((s) =>
          realFindingService
            .listFindingsForScan(s.id, { pageSize: 50 })
            .catch(() => ({ items: [] }))
        );
        const findingsResults = await Promise.all(findingsPromises);
        const allFindings = findingsResults.flatMap((r) => r.items.map(mapFindingOutToFinding));
        setFindings(allFindings);

        // Compute severity counts from dashboard or findings
        const stats: SeverityCount = {
          critical: dash.findings_by_severity?.critical || 0,
          high: dash.findings_by_severity?.high || 0,
          medium: dash.findings_by_severity?.medium || 0,
          low: dash.findings_by_severity?.low || 0,
          info: dash.findings_by_severity?.info || 0,
          total: dash.total_findings || 0,
        };
        setSeverityStats(stats);
      }
    } catch (err: unknown) {
      console.error('Failed to load CyberSec AI security telemetry:', err);
      if (err instanceof ApiClientError) {
        setError(`Backend error: ${err.message} (${err.code})`);
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('An unexpected error occurred while communicating with the API.');
      }
    } finally {
      setLoading(false);
      isRefreshingRef.current = false;
    }
  }, [isDemo, isAuthenticated, authLoading]);

  useEffect(() => {
    // Wait for session restore before the first real-mode fetch; re-runs
    // on login/logout (isAuthenticated flip changes refreshData identity).
    if (!isDemo && authLoading) return;
    // A real authenticated session always wins over the demo flag (e.g.
    // left over from the login page's demo bypass): exit demo mode so the
    // user sees live backend data, not mock telemetry.
    if (isDemo && isAuthenticated) {
      toggleDemoMode(false);
      return;
    }
    refreshData();
  }, [refreshData, isDemo, authLoading, isAuthenticated, toggleDemoMode]);

  const createScan = async (
    target: string,
    profile: ScanProfile,
    goal?: string,
    projectId?: string
  ): Promise<Scan> => {
    if (isDemo) {
      const newScan = await mockScanService.createScan({ target, profile, goal });
      await refreshData();
      return newScan;
    }

    // REAL API: Resolve or create project with target in scope
    let targetProjectId = projectId;
    if (!targetProjectId) {
      const scopeEntry = inferScopeFromTarget(target);
      const newProj = await realProjectService.createProject({
        name: `Target: ${scopeEntry.value}`,
        description: `Automated assessment project for ${target}`,
        scope: [scopeEntry],
      });
      targetProjectId = newProj.id;
    }

    // Map profile string to valid backend profile ('recon' | 'web' | 'full')
    const apiProfile =
      profile === 'web_assessment' ? 'web' : profile === 'full_assessment' ? 'full' : profile;

    const createdOut = await realScanService.createScan({
      project_id: targetProjectId,
      profile: apiProfile,
      goal: goal || undefined,
    });

    const newScan = mapScanOutToScan(createdOut);
    setScans((prev) => [newScan, ...prev]);
    return newScan;
  };

  const stopScan = async (id: string): Promise<void> => {
    if (isDemo) {
      await mockScanService.stopScan(id);
    } else {
      const updatedOut = await realScanService.cancelScan(id);
      const updated = mapScanOutToScan(updatedOut);
      setScans((prev) => prev.map((s) => (s.id === id ? updated : s)));
    }
    await refreshData();
  };

  const updateFindingStatus = async (
    id: string,
    status: Finding['status']
  ): Promise<void> => {
    if (isDemo) {
      await mockFindingsService.updateFindingStatus(id, status);
      await refreshData();
    } else {
      // Backend Phase 2 contract: findings are read-only scanner evidence
      // Update local state for optimistic UI review
      setFindings((prev) =>
        prev.map((f) => (f.id === id ? { ...f, status } : f))
      );
    }
  };

  const resetDemoData = async (): Promise<void> => {
    if (!isDemo) return;
    setLoading(true);
    await mockScanService.resetToDefaults();
    await mockFindingsService.resetToDefaults();
    await refreshData();
  };

  const clearError = () => setError(null);

  return (
    <ScanContext.Provider
      value={{
        scans,
        findings,
        projects,
        loading,
        error,
        severityStats,
        isDemo,
        createScan,
        stopScan,
        resetDemoData,
        refreshData,
        updateFindingStatus,
        toggleDemoMode,
        clearError,
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
