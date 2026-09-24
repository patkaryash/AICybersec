import { useState, useEffect, useRef, useCallback } from 'react';
import { Scan } from '../types/scan';
import { AgentTimelineEvent } from '../types/agent';
import { TIMELINE_TEMPLATES } from '../services/mockData';
import { scanService } from '../services/scanService';
import { findingsService } from '../services/findingsService';
import { useScans } from '../context/ScanContext';
import { Finding } from '../types/finding';

export function useAgentSimulation(scan?: Scan) {
  const { refreshData } = useScans();
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(0);
  const [isPaused, setIsPaused] = useState<boolean>(false);
  const [events, setEvents] = useState<AgentTimelineEvent[]>([]);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Initialize events based on profile
  useEffect(() => {
    if (!scan) return;

    const template = TIMELINE_TEMPLATES[scan.profile] || TIMELINE_TEMPLATES.recon;
    const initialEvents: AgentTimelineEvent[] = template.map((tmpl, idx) => ({
      ...tmpl,
      id: `${scan.id}-evt-${idx + 1}`,
      timestamp: new Date(new Date(scan.startedAt).getTime() + idx * 3000).toISOString(),
      status: scan.status === 'finished' 
        ? 'completed' 
        : scan.status === 'cancelled'
        ? (idx < scan.currentStep ? 'completed' : 'pending')
        : (idx === 0 ? 'in_progress' : 'pending'),
    }));

    setEvents(initialEvents);

    if (scan.status === 'finished') {
      setCurrentStepIndex(template.length);
    } else if (scan.status === 'cancelled') {
      setCurrentStepIndex(scan.currentStep);
    } else {
      setCurrentStepIndex(scan.currentStep > 0 ? scan.currentStep - 1 : 0);
    }
  }, [scan?.id, scan?.status, scan?.profile, scan?.startedAt, scan?.currentStep]);

  // Step advancement loop
  const advanceStep = useCallback(async () => {
    if (!scan || scan.status !== 'running' || isPaused) return;

    const template = TIMELINE_TEMPLATES[scan.profile] || TIMELINE_TEMPLATES.recon;
    const nextIndex = currentStepIndex + 1;

    if (nextIndex < template.length) {
      // Move to next step
      setCurrentStepIndex(nextIndex);
      setEvents((prev) =>
        prev.map((evt, idx) => {
          if (idx < nextIndex) return { ...evt, status: 'completed' };
          if (idx === nextIndex) return { ...evt, status: 'in_progress' };
          return { ...evt, status: 'pending' };
        })
      );
      await scanService.updateScanStatus(scan.id, { currentStep: nextIndex + 1 });
    } else {
      // Completed all steps
      setCurrentStepIndex(template.length);
      setEvents((prev) => prev.map((evt) => ({ ...evt, status: 'completed' })));

      // Generate a synthetic finding if profile matches
      let newFindingCount = scan.findingsCount;
      if (scan.profile === 'recon') {
        newFindingCount = { critical: 0, high: 0, medium: 0, low: 1, info: 1, total: 2 };
      } else if (scan.profile === 'web_assessment') {
        newFindingCount = { critical: 0, high: 1, medium: 1, low: 0, info: 0, total: 2 };
      } else {
        newFindingCount = { critical: 1, high: 1, medium: 1, low: 0, info: 1, total: 4 };
        
        // Add a demo finding specifically linked to this new scan
        const dynamicFinding: Finding = {
          id: `fnd-${scan.id.substring(5, 11)}`,
          scanId: scan.id,
          title: `Sensitive API Route Exposure on ${scan.target}`,
          severity: 'high',
          target: scan.target,
          asset: `https://${scan.target}/api/internal/health-metrics`,
          description: `Discovered unauthenticated internal diagnostics endpoint on ${scan.target} disclosing live memory utilization and database connection stats.`,
          tool: 'nuclei_full',
          confidence: 'high',
          status: 'open',
          detectedAt: new Date().toISOString(),
          evidence: {
            request: `GET /api/internal/health-metrics HTTP/1.1\nHost: ${scan.target}`,
            response: `HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"status": "UP", "threads": 48, "activeConnections": 12, "dbPool": "master-write"}`,
            matchedPattern: '"dbPool": "master-write"',
          },
          aiAnalysis: {
            summary: `Automated assessment observed debug diagnostics accessible without API gateway bearer token.`,
            impact: `Architectural mapping and internal thread telemetry disclosure.`,
            attackVector: 'Unauthenticated HTTP GET',
            exploitLikelihood: 'High',
          },
          remediation: {
            summary: `Enforce gateway authentication filter on internal metrics route.`,
            steps: [
              `Restrict access to internal subnet IPs only.`,
              `Require admin OAuth2 bearer token for /api/internal paths.`,
            ],
          },
          references: ['https://cwe.mitre.org/data/definitions/200.html'],
          isSynthetic: true,
        };
        await findingsService.addFinding(dynamicFinding);
      }

      await scanService.updateScanStatus(scan.id, {
        status: 'finished',
        currentStep: template.length,
        completedAt: new Date().toISOString(),
        findingsCount: newFindingCount,
      });

      await refreshData();
    }
  }, [scan, currentStepIndex, isPaused, refreshData]);

  useEffect(() => {
    if (!scan || scan.status !== 'running' || isPaused) {
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }

    const template = TIMELINE_TEMPLATES[scan.profile] || TIMELINE_TEMPLATES.recon;
    if (currentStepIndex >= template.length) {
      return;
    }

    timerRef.current = setTimeout(advanceStep, 3500);

    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [scan, currentStepIndex, isPaused, advanceStep]);

  const togglePause = () => {
    setIsPaused((p) => !p);
  };

  const fastForward = async () => {
    if (!scan) return;
    const template = TIMELINE_TEMPLATES[scan.profile] || TIMELINE_TEMPLATES.recon;
    setCurrentStepIndex(template.length);
    setEvents((prev) => prev.map((evt) => ({ ...evt, status: 'completed' })));

    await scanService.updateScanStatus(scan.id, {
      status: 'finished',
      currentStep: template.length,
      completedAt: new Date().toISOString(),
      findingsCount: scan.profile === 'recon'
        ? { critical: 0, high: 0, medium: 0, low: 1, info: 1, total: 2 }
        : scan.profile === 'web_assessment'
        ? { critical: 0, high: 1, medium: 1, low: 0, info: 0, total: 2 }
        : { critical: 1, high: 1, medium: 1, low: 0, info: 1, total: 4 },
    });
    await refreshData();
  };

  return {
    events,
    currentStepIndex,
    isPaused,
    togglePause,
    fastForward,
  };
}
