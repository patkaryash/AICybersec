import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Clock,
  Ban,
  Bug,
  Pause,
  Play,
  FastForward,
  Copy,
  Check,
  AlertCircle,
  Inbox,
  X,
  Radio,
  Network,
} from 'lucide-react';
import { useScans } from '../context/ScanContext';
import { useTimer } from '../hooks/useTimer';
import { useAgentSimulation } from '../hooks/useAgentSimulation';
import { StatusBadge } from '../components/common/StatusBadge';
import { SCAN_PROFILES, Scan } from '../types/scan';
import { eventService } from '../services/api/eventService';
import { scanService as realScanService } from '../services/api/scanService';
import { assetService } from '../services/api/assetService';
import { mapScanOutToScan, mapRealEventsToTimeline } from '../services/adapters';
import { AgentTimelineEvent } from '../types/agent';
import { containerVariants, itemVariants } from '../lib/motionVariants';
import { AssetOut } from '../types/contract';
import { Finding } from '../types/finding';
import { FindingDetailModal } from '../components/common/FindingDetailModal';
import { AttackSurfaceTree } from '../components/assets/AttackSurfaceTree';

export const LiveAgentPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const { scans, findings, stopScan, refreshData, isDemo } = useScans();

  const [copiedId, setCopiedId] = useState(false);
  const [expandedEvents, setExpandedEvents] = useState<Record<string, boolean>>({});
  const [realEvents, setRealEvents] = useState<AgentTimelineEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<AgentTimelineEvent | null>(null);
  const [activeTab, setActiveTab] = useState<'timeline' | 'assets'>('timeline');
  const [scanAssets, setScanAssets] = useState<AssetOut[]>([]);
  const [assetsLoading, setAssetsLoading] = useState<boolean>(false);
  const [assetsError, setAssetsError] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  // Context snapshot (loaded once per refreshData call) + live override.
  const contextScan =
    scans.find((s) => s.id === scanId) ||
    scans.find((s) => s.status === 'running' || s.status === 'queued') ||
    scans[0];

  // Live status polling: the context list does not refresh on its own, so
  // without this the header would stay "Running" (and findings at 0) after
  // the run finishes server-side. Polls until a terminal status, then
  // syncs the context lists once.
  const [liveScan, setLiveScan] = useState<Scan | undefined>(undefined);
  useEffect(() => {
    if (!scanId || isDemo) return;
    let cancelled = false;
    let interval: number | undefined;
    const poll = async () => {
      try {
        const mapped = mapScanOutToScan(await realScanService.getScan(scanId));
        if (cancelled) return;
        setLiveScan(mapped);
        if (
          mapped.status === 'completed' ||
          mapped.status === 'failed' ||
          mapped.status === 'cancelled' ||
          mapped.status === 'finished'
        ) {
          if (interval !== undefined) window.clearInterval(interval);
          await refreshData();
        }
      } catch {
        // Transient error: retry on the next tick.
      }
    };
    poll();
    interval = window.setInterval(poll, 5000);
    return () => {
      cancelled = true;
      if (interval !== undefined) window.clearInterval(interval);
    };
  }, [scanId, isDemo, refreshData]);

  const scan = liveScan ?? contextScan;

  const profileInfo = scan ? SCAN_PROFILES[scan.profile] : null;

  // Live Elapsed Timer
  const isRunning = scan?.status === 'running';
  const { formattedTime } = useTimer(
    scan?.startedAt || new Date().toISOString(),
    scan?.completedAt,
    isRunning
  );

  // Progressive simulation hook (for demo/simulated scans)
  const isSimulated = isDemo || Boolean(scan?.isSimulated);
  const {
    events: simulatedEvents,
    isPaused,
    togglePause,
    fastForward,
  } = useAgentSimulation(isSimulated ? scan : undefined);

  // Fetch real agent events for real backend scans
  const activeScanId = scan?.id;
  useEffect(() => {
    if (!activeScanId || isSimulated) return;

    let isMounted = true;
    const fetchEvents = async () => {
      try {
        const rawEvents = await eventService.listAgentEvents(activeScanId, 0, 50);
        if (isMounted) {
          setRealEvents(mapRealEventsToTimeline(rawEvents));
        }
      } catch (err) {
        console.warn('Real agent events polling error:', err);
      }
    };

    fetchEvents();
    const interval = setInterval(fetchEvents, 5000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [activeScanId, isSimulated]);

  const events = isSimulated ? simulatedEvents : realEvents;

  // Findings linked to this scan
  const scanFindings = useMemo(() => {
    return findings.filter((f) => f.scanId === scan?.id);
  }, [findings, scan?.id]);

  // Fetch discovered assets for this scan
  useEffect(() => {
    if (!scan) return;

    if (isSimulated) {
      const demoProjectId = scan.projectId || 'demo-project';
      const demoAssets: AssetOut[] = [
        {
          id: `${scan.id}-root`,
          scan_id: scan.id,
          project_id: demoProjectId,
          asset_type: 'domain',
          value: scan.target,
          host: scan.target,
          port: null,
          scheme: null,
          parent_asset_id: null,
          attributes: {
            verification_status: 'resolved',
            source: 'scope',
          },
          source_tool: 'scope',
          created_at: scan.startedAt,
          last_seen: scan.startedAt,
        },
        {
          id: `${scan.id}-sub1`,
          scan_id: scan.id,
          project_id: demoProjectId,
          asset_type: 'subdomain',
          value: `api.${scan.target}`,
          host: `api.${scan.target}`,
          port: null,
          scheme: null,
          parent_asset_id: `${scan.id}-root`,
          attributes: {
            parent_domain: scan.target,
            source: 'subfinder',
            verification_status: 'resolved',
            dns_a: ['10.0.0.15'],
          },
          source_tool: 'subfinder',
          created_at: scan.startedAt,
          last_seen: scan.startedAt,
        },
        {
          id: `${scan.id}-sub2`,
          scan_id: scan.id,
          project_id: demoProjectId,
          asset_type: 'subdomain',
          value: `staging.${scan.target}`,
          host: `staging.${scan.target}`,
          port: null,
          scheme: null,
          parent_asset_id: `${scan.id}-root`,
          attributes: {
            parent_domain: scan.target,
            source: 'subfinder',
            verification_status: 'unverified',
            dns_cname: [`lb.${scan.target}`],
          },
          source_tool: 'subfinder',
          created_at: scan.startedAt,
          last_seen: scan.startedAt,
        },
      ];
      setScanAssets(demoAssets);
      return;
    }

    let isMounted = true;
    const loadAssets = async () => {
      try {
        setAssetsLoading((prev) => (scanAssets.length === 0 ? true : prev));
        const res = await assetService.listAssetsForScan(scan.id, { pageSize: 100 });
        if (isMounted) {
          setScanAssets(res.items);
          setAssetsError(null);
        }
      } catch (err: unknown) {
        if (isMounted) {
          setAssetsError(err instanceof Error ? err.message : 'Failed to load assets');
        }
      } finally {
        if (isMounted) setAssetsLoading(false);
      }
    };

    loadAssets();
    const interval = isRunning ? setInterval(loadAssets, 7000) : undefined;
    return () => {
      isMounted = false;
      if (interval) clearInterval(interval);
    };
  }, [scan?.id, scan?.target, scan?.projectId, scan?.startedAt, isSimulated, isRunning]);

  const handleCopyScanId = () => {
    if (!scan) return;
    navigator.clipboard.writeText(scan.id);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
  };

  const handleCancel = async () => {
    if (!scan) return;
    try {
      await stopScan(scan.id);
    } catch {
      // Already terminal server-side (cancel rejects on finished scans):
      // fall through and re-sync so the header stops saying "Running".
    }
    await refreshData();
    setLiveScan(undefined);
  };

  const toggleEventExpand = useCallback((id: string) => {
    setExpandedEvents((prev) => ({ ...prev, [id]: !prev[id] }));
  }, []);

  const closeInspector = useCallback(() => {
    setSelectedEvent(null);
  }, []);

  // Handle ESC key to close inspector
  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && selectedEvent) {
        closeInspector();
      }
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [selectedEvent, closeInspector]);

  const progressStage = useMemo(() => {
    if (!scan) return { current: 0, stages: ['Scope', 'Discovery', 'Enumeration', 'Analysis', 'Validation', 'Report'] };
    const stages = ['Scope', 'Discovery', 'Enumeration', 'Analysis', 'Validation', 'Report'];
    const completed = events.filter(e => e.status === 'completed').length;
    const inProgress = events.findIndex(e => e.status === 'in_progress');
    const current = inProgress >= 0 ? inProgress : completed;
    return { current, stages };
  }, [scan, events]);

  const progressIndex = progressStage.current;
  const progressStages = progressStage.stages;

  // Get current running event for prominent display
  const currentEvent = useMemo(() => {
    return events.find(e => e.status === 'in_progress');
  }, [events]);

  if (!scan) {
    return (
      <div className="py-20 text-center space-y-4">
        <AlertCircle size={36} className="mx-auto text-amber-500" />
        <h3 className="text-lg font-bold text-[#0B1220]">Scan Not Found</h3>
        <p className="text-xs text-[#475569] max-w-sm mx-auto">
          The requested scan session could not be located in current state.
        </p>
        <button
          onClick={() => navigate('/new-scan')}
          className="px-4 py-2 rounded-lg bg-[#1D4ED8] hover:bg-[#1E40AF] text-white font-semibold text-xs transition-colors shadow-sm"
        >
          Launch New Pentest
        </button>
      </div>
    );
  }

  const isCancellable =
    scan.status === 'queued' || scan.status === 'initializing' || scan.status === 'running';

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="space-y-4"
    >
      {/* Compact Demo Environment Banner */}
      <motion.div variants={itemVariants}>
        <div className="flex items-center gap-3 px-4 py-2 rounded-lg bg-amber-50 border border-amber-200">
          <Radio size={14} className="text-amber-600" />
          <div className="flex-1">
            <span className="text-xs font-semibold text-amber-800">DEMO ENVIRONMENT</span>
            <span className="text-xs text-amber-700 ml-2">Offline Mode</span>
          </div>
          <span className="text-[10px] text-amber-600 max-w-md hidden sm:block">
            Simulated telemetry. No live offensive operations are executed in this mode.
          </span>
        </div>
      </motion.div>

      {/* Run Command Center */}
      <motion.div variants={itemVariants}>
        <div className="bg-white/90 backdrop-blur-md border border-slate-200/80 rounded-xl p-4 sm:p-5 shadow-sm">
          <div className="flex flex-col lg:flex-row lg:items-start gap-4">
            {/* Left: Target & Status */}
            <div className="flex-1 space-y-3">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-blue-50 border border-blue-200 text-[#1D4ED8]">
                  {profileInfo?.name || scan.profile}
                </span>
                <button
                  onClick={handleCopyScanId}
                  className="text-xs font-mono text-[#64748B] bg-slate-100 hover:text-[#0B1220] hover:bg-slate-200/60 px-2 py-0.5 rounded border border-slate-200 flex items-center gap-1 transition-colors"
                  title="Copy Scan ID"
                >
                  <span>{scan.id.slice(0, 8)}</span>
                  {copiedId ? <Check size={11} className="text-[#059669]" /> : <Copy size={11} />}
                </button>
                <StatusBadge status={scan.status} size="sm" />
              </div>

              <div>
                <h2 className="text-xl sm:text-2xl font-bold font-mono text-[#0B1220] tracking-tight">
                  {scan.target}
                </h2>
                <p className="text-xs text-[#475569] mt-1">Security assessment</p>
              </div>

              {/* Assessment Progress Pipeline */}
              <div className="flex items-center gap-1 overflow-x-auto pb-1">
                {progressStages.map((stage, idx) => {
                  const isCompleted = idx < progressIndex;
                  const isCurrent = idx === progressIndex;
                  return (
                    <React.Fragment key={stage}>
                      <div className="flex items-center gap-1 flex-shrink-0">
                        <span
                          className={`text-[10px] font-mono font-semibold ${
                            isCompleted
                              ? 'text-[#059669]'
                              : isCurrent
                              ? 'text-[#1D4ED8]'
                              : 'text-[#64748B]'
                          }`}
                        >
                          {isCompleted ? '✓' : isCurrent ? '●' : '○'}
                        </span>
                        <span
                          className={`text-[11px] font-semibold ${
                            isCompleted
                              ? 'text-[#059669]'
                              : isCurrent
                              ? 'text-[#1D4ED8] font-bold'
                              : 'text-[#64748B]'
                          }`}
                        >
                          {stage}
                        </span>
                      </div>
                      {idx < progressStages.length - 1 && (
                        <span className="text-[#D8E1EB] flex-shrink-0">/</span>
                      )}
                    </React.Fragment>
                  );
                })}
              </div>
            </div>

            {/* Right: Metrics & Actions */}
            <div className="flex flex-col sm:flex-row lg:flex-col items-start sm:items-center lg:items-start gap-3 lg:border-l lg:pl-4 lg:border-slate-200">
              <div className="flex items-center gap-3 flex-wrap">
                <div className="flex items-center gap-2">
                  <Clock
                    size={14}
                    className={isRunning ? 'text-[#1D4ED8] animate-pulse' : 'text-[#64748B]'}
                  />
                  <span className="font-mono text-sm font-bold text-[#0B1220]">
                    {scan.status === 'queued' ? 'Queued' : formattedTime}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <Bug
                    size={14}
                    className={
                      scan.findingsCount.total > 0
                        ? 'text-[#DC2626]'
                        : 'text-[#64748B]'
                    }
                  />
                  <span className="font-mono text-sm font-bold text-[#0B1220]">
                    {scan.findingsCount.total} findings
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                {isSimulated && isRunning && (
                  <>
                    <button
                      onClick={togglePause}
                      className="p-2 rounded-lg border border-[#D8E1EB] bg-white hover:bg-[#EEF3F8] text-[#0B1220] transition-colors"
                      title={isPaused ? 'Resume Simulation' : 'Pause Simulation'}
                    >
                      {isPaused ? <Play size={14} className="fill-current text-[#059669]" /> : <Pause size={14} />}
                    </button>
                    <button
                      onClick={fastForward}
                      className="p-2 rounded-lg border border-[#D8E1EB] bg-white hover:bg-[#EEF3F8] text-[#1D4ED8] transition-colors"
                      title="Fast-forward / Complete Scan"
                    >
                      <FastForward size={14} />
                    </button>
                  </>
                )}
                {isCancellable && (
                  <button
                    onClick={handleCancel}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-rose-200 bg-rose-50 text-[#DC2626] hover:bg-rose-100 text-xs font-semibold transition-colors"
                  >
                    <Ban size={13} />
                    <span className="hidden sm:inline">Cancel</span>
                  </button>
                )}
                <button
                  onClick={() => navigate('/findings')}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#1D4ED8] text-white font-semibold text-xs tracking-wide hover:bg-[#1E40AF] transition-colors"
                >
                  <Bug size={13} />
                  <span>View Findings</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Current Agent Action - Prominent when running */}
      <AnimatePresence>
        {currentEvent && (
          <motion.div
            variants={itemVariants}
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
          >
            <div className="bg-gradient-to-r from-blue-50/50 to-indigo-50/50 border border-[#1D4ED8]/30 rounded-xl p-4 sm:p-5 shadow-sm">
              <div className="flex items-start gap-3">
                <div className="mt-0.5 w-3 h-3 rounded-full bg-[#1D4ED8] animate-pulse flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className="text-xs font-mono font-semibold text-[#1D4ED8] uppercase tracking-wider">
                      Current Agent Action
                    </span>
                    {currentEvent.tool && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-100 border border-blue-300 text-[#1D4ED8]">
                        {currentEvent.tool}
                      </span>
                    )}
                  </div>
                  <h4 className="text-sm font-bold text-[#0B1220] mb-1">{currentEvent.title}</h4>
                  <p className="text-xs text-[#475569] line-clamp-2">{currentEvent.description}</p>
                  {currentEvent.reasoning && (
                    <div className="mt-2">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          toggleEventExpand(currentEvent.id);
                        }}
                        className="text-[10px] text-[#64748B] hover:text-[#1D4ED8] flex items-center gap-1 font-mono transition-colors"
                      >
                        <span>Why this action? {expandedEvents[currentEvent.id] ? '−' : '+'}</span>
                      </button>
                      <AnimatePresence>
                        {expandedEvents[currentEvent.id] && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            className="mt-2 p-2 rounded bg-white/60 border border-indigo-200 text-[11px] text-slate-700"
                          >
                            {currentEvent.reasoning}
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Security Signals Panel */}
      <motion.div variants={itemVariants}>
        <div className="bg-white/90 backdrop-blur-md border border-slate-200/80 rounded-xl p-4 sm:p-5 shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-bold text-[#0B1220]">Security Signals</h3>
              <p className="text-xs text-[#475569] mt-0.5">Findings detected during assessment</p>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold font-mono text-[#0B1220]">{scan.findingsCount.total}</div>
                <div className="text-[10px] text-[#64748B] uppercase tracking-wider">Findings</div>
              </div>
              <div className="h-10 w-px bg-[#D8E1EB]" />
              <div className="flex gap-3 text-xs">
                <div className="text-center">
                  <div className="font-mono font-bold text-[#DC2626]">{scan.findingsCount.critical}</div>
                  <div className="text-[10px] text-[#64748B]">Critical</div>
                </div>
                <div className="text-center">
                  <div className="font-mono font-bold text-[#D97706]">{scan.findingsCount.high}</div>
                  <div className="text-[10px] text-[#64748B]">High</div>
                </div>
                <div className="text-center">
                  <div className="font-mono font-bold text-[#CA8A04]">{scan.findingsCount.medium}</div>
                  <div className="text-[10px] text-[#64748B]">Medium</div>
                </div>
                <div className="text-center">
                  <div className="font-mono font-bold text-[#059669]">{scan.findingsCount.low}</div>
                  <div className="text-[10px] text-[#64748B]">Low</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Agent Activity Timeline */}
      <motion.div variants={itemVariants}>
        <div className="bg-white/90 backdrop-blur-md border border-slate-200/80 rounded-xl p-4 sm:p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-[#0B1220]">Agent Activity</h3>
              <p className="text-xs text-[#475569] mt-0.5">
                Chronological sequence of autonomous decisions and tool executions
              </p>

              {isRunning && (
              <span className="text-xs font-mono text-[#1D4ED8] flex items-center gap-1.5 font-semibold">
                <span className="w-2 h-2 rounded-full bg-[#1D4ED8] animate-ping" />
                Live
              </span>
            )}

          {events.length === 0 ? (
            <div className="py-8 text-center space-y-2">
              <Inbox size={24} className="mx-auto text-[#64748B]" />
              <p className="text-xs text-[#475569]">
                {scan.status === 'queued'
                  ? 'Scan queued. Events will stream when execution begins.'
                  : 'No agent telemetry events recorded yet.'}
              </p>
            </div>
          ) : (
            <div className="space-y-2">
              {events.map((evt) => {
                const isCompleted = evt.status === 'completed';
                const isInProgress = evt.status === 'in_progress';
                const isExpanded = expandedEvents[evt.id] || false;

                return (
                  <div
                    key={evt.id}
                    onClick={() => setSelectedEvent(evt)}
                    className={`group relative pl-4 py-2.5 rounded-lg border transition-all cursor-pointer ${
                      isInProgress
                        ? 'bg-blue-50/30 border-[#1D4ED8] shadow-sm'
                        : isCompleted
                        ? 'bg-white border-[#D8E1EB] hover:border-[#1D4ED8]/50'
                        : 'bg-slate-50/50 border-[#D8E1EB] opacity-60'
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <div
                        className={`mt-0.5 w-2 h-2 rounded-full flex-shrink-0 ${
                          isCompleted
                            ? 'bg-[#059669]'
                            : isInProgress
                            ? 'bg-[#1D4ED8] animate-pulse'
                            : 'bg-[#64748B]'
                        }`}
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs font-semibold text-[#0B1220]">{evt.title}</span>
                          {evt.tool && (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-50 border border-blue-200 text-[#1D4ED8]">
                              {evt.tool}
                            </span>
                          )}
                          {isInProgress && (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-50 text-[#1D4ED8] border border-blue-200 animate-pulse">
                              RUNNING
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-[#475569] mt-0.5 line-clamp-1">{evt.description}</p>
                        
                        {/* Collapsible Reasoning */}
                        {evt.reasoning && (
                          <div className="mt-2">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                toggleEventExpand(evt.id);
                              }}
                              className="text-[10px] text-[#64748B] hover:text-[#1D4ED8] flex items-center gap-1 font-mono transition-colors"
                            >
                              <span>{isExpanded ? 'Why? −' : 'Why? +'}</span>
                            </button>
                            <AnimatePresence>
                              {isExpanded && (
                                <motion.div
                                  initial={{ opacity: 0, height: 0 }}
                                  animate={{ opacity: 1, height: 'auto' }}
                                  exit={{ opacity: 0, height: 0 }}
                                  className="mt-2 p-2 rounded bg-indigo-50/50 border border-indigo-200 text-[11px] text-slate-700"
                                >
                                  {evt.reasoning}
                                </motion.div>
                              )}
                            </AnimatePresence>
                          </div>
                        )}
                      </div>
                      <div className="text-[10px] text-[#64748B] font-mono whitespace-nowrap">
                        {evt.durationMs ? `${(evt.durationMs / 1000).toFixed(1)}s` : ''}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </motion.div>

      {/* Event Inspector Panel */}
      <AnimatePresence>
        {selectedEvent && (
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 20 }}
            className="fixed right-0 top-0 bottom-0 w-96 bg-white/95 backdrop-blur-md border-l border-slate-200/80 shadow-xl z-50 overflow-y-auto"
          >
            <div className="p-4 border-b border-slate-200/80 flex items-center justify-between">
              <h3 className="text-sm font-bold text-[#0B1220]">Event Inspector</h3>
              <button
                onClick={closeInspector}
                className="p-1.5 rounded-lg text-[#64748B] hover:text-[#0B1220] hover:bg-slate-100 transition-colors"
                aria-label="Close inspector"
              >
                <X size={16} />
              </button>
            </div>
            <div className="p-4 space-y-4">
              <div>
                <div className="text-[10px] text-[#64748B] uppercase tracking-wider font-semibold mb-1">Title</div>
                <div className="text-sm font-semibold text-[#0B1220]">{selectedEvent.title}</div>
              </div>
              
              {selectedEvent.tool && (
                <div>
                  <div className="text-[10px] text-[#64748B] uppercase tracking-wider font-semibold mb-1">Tool</div>
                  <div className="text-sm font-mono text-[#1D4ED8]">{selectedEvent.tool}</div>
                </div>
              )}

              <div>
                <div className="text-[10px] text-[#64748B] uppercase tracking-wider font-semibold mb-1">Status</div>
                <div className="text-sm font-semibold text-[#0B1220] capitalize">{selectedEvent.status.replace('_', ' ')}</div>
              </div>

              {selectedEvent.durationMs && (
                <div>
                  <div className="text-[10px] text-[#64748B] uppercase tracking-wider font-semibold mb-1">Duration</div>
                  <div className="text-sm font-mono text-[#0B1220]">{(selectedEvent.durationMs / 1000).toFixed(2)}s</div>
                </div>
              )}

              <div>
                <div className="text-[10px] text-[#64748B] uppercase tracking-wider font-semibold mb-1">Timestamp</div>
                <div className="text-sm font-mono text-[#0B1220]">{new Date(selectedEvent.timestamp).toLocaleString()}</div>
              </div>

              {selectedEvent.description && (
                <div>
                  <div className="text-[10px] text-[#64748B] uppercase tracking-wider font-semibold mb-1">Description</div>
                  <div className="text-sm text-[#475569]">{selectedEvent.description}</div>
                </div>
              )}

              {selectedEvent.reasoning && (
                <div>
                  <div className="text-[10px] text-[#64748B] uppercase tracking-wider font-semibold mb-1">Reasoning</div>
                  <div className="text-sm text-[#475569]">{selectedEvent.reasoning}</div>
                </div>
              )}

              {selectedEvent.payload && (
                <div>
                  <div className="text-[10px] text-[#64748B] uppercase tracking-wider font-semibold mb-1">Payload</div>
                  <pre className="text-[11px] font-mono text-slate-700 bg-slate-50 p-2 rounded border border-slate-200 overflow-x-auto">
                    {JSON.stringify(selectedEvent.payload, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Backdrop for inspector */}
      <AnimatePresence>
        {selectedEvent && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={closeInspector}
            className="fixed inset-0 bg-slate-950/20 backdrop-blur-xs z-40"
            aria-hidden="true"
          />
        )}
       </AnimatePresence>

      {/* Finding Detail Modal if opened from Attack Surface */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          isOpen={Boolean(selectedFinding)}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </motion.div>
  );
};
