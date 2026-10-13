import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Clock,
  Bug,
  Check,
  Copy,
  AlertCircle,
  Radio,
  Play,
  Pause,
  FastForward,
  Ban,
  X,
  Inbox,
} from 'lucide-react';
import { useScans } from '../context/ScanContext';
import { StatusBadge } from '../components/common/StatusBadge';
import { FindingDetailModal } from '../components/common/FindingDetailModal';
import { SCAN_PROFILES, Scan } from '../types/scan';
import { AgentTimelineEvent } from '../types/agent';
import { AssetOut } from '../types/contract';
import { Finding } from '../types/finding';
import { useTimer } from '../hooks/useTimer';
import { useAgentSimulation } from '../hooks/useAgentSimulation';
import { assetService } from '../services/api/assetService';
import { containerVariants, itemVariants } from '../lib/motionVariants';

export const LiveAgentPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const {
    scans,
    stopScan,
    refreshData,
  } = useScans();

  const [copiedId, setCopiedId] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState<AgentTimelineEvent | null>(null);
  const [expandedEvents, setExpandedEvents] = useState<Record<string, boolean>>({});
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // Fallback demo state if /agent/demo route is accessed directly
  const [liveScan, setLiveScan] = useState<Scan | undefined>(() => {
    if (id === 'demo' || !id) {
      return scans.find((s) => s.status === 'running') || scans[0];
    }
    return scans.find((s) => s.id === id);
  });

  const scan = liveScan || scans.find((s) => s.id === id);

  const isSimulated = scan?.isSimulated ?? false;
  const isRunning =
    scan?.status === 'running' ||
    scan?.status === 'queued' ||
    scan?.status === 'initializing';

  // Elapsed timer based on actual startedAt or synthetic run
  const { formattedTime } = useTimer(
    scan?.startedAt || '',
    scan?.completedAt,
    isRunning
  );

  // Hook for simulation logic when in mock mode
  const {
    events,
    isPaused,
    togglePause,
    fastForward,
  } = useAgentSimulation(scan);

  const profileInfo = useMemo(() => {
    return scan ? SCAN_PROFILES[scan.profile] : null;
  }, [scan]);

  // Asset state
  const [, setScanAssets] = useState<AssetOut[]>([]);
  const [, setAssetsLoading] = useState(false);
  const [, setAssetsError] = useState<string | null>(null);

  // Fetch or mock attack surface assets
  useEffect(() => {
    if (!scan) return;

    if (isSimulated) {
      const demoProjectId = scan.projectId || 'demo-project-id';
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
        setAssetsLoading(true);
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
      // Fall through
    }
    await refreshData();
    setLiveScan(undefined);
  };

  const toggleEventExpand = useCallback((eventId: string) => {
    setExpandedEvents((prev) => ({ ...prev, [eventId]: !prev[eventId] }));
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
        <h3 className="text-lg font-bold text-white">Scan Not Found</h3>
        <p className="text-xs text-zinc-400 max-w-sm mx-auto">
          The requested scan session could not be located in current state.
        </p>
        <button
          onClick={() => navigate('/new-scan')}
          className="px-4 py-2 rounded-lg bg-zinc-100 hover:bg-zinc-200 text-zinc-900 font-medium text-xs transition-colors shadow-sm"
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
        <div className="flex items-center gap-3 px-4 py-2 rounded-xl bg-[#121214] border border-amber-900/50">
          <Radio size={14} className="text-amber-400" />
          <div className="flex-1">
            <span className="text-xs font-semibold text-amber-300 font-mono">DEMO ENVIRONMENT</span>
            <span className="text-xs text-amber-400 ml-2 font-mono">Offline Mode</span>
          </div>
          <span className="text-[10px] text-zinc-400 max-w-md hidden sm:block font-mono">
            Simulated telemetry. No live offensive operations are executed in this mode.
          </span>
        </div>
      </motion.div>

      {/* Run Command Center */}
      <motion.div variants={itemVariants}>
        <div className="bg-[#121214] border border-zinc-800 rounded-2xl p-5 sm:p-6 shadow-xl">
          <div className="flex flex-col lg:flex-row lg:items-start gap-4">
            {/* Left: Target & Status */}
            <div className="flex-1 space-y-3">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-zinc-800 border border-zinc-700 text-zinc-300">
                  {profileInfo?.name || scan.profile}
                </span>
                <button
                  onClick={handleCopyScanId}
                  className="text-xs font-mono text-zinc-400 bg-[#18181B] hover:text-white hover:bg-zinc-800 px-2 py-0.5 rounded border border-zinc-800 flex items-center gap-1 transition-colors"
                  title="Copy Scan ID"
                >
                  <span>{scan.id.slice(0, 8)}</span>
                  {copiedId ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
                </button>
                <StatusBadge status={scan.status} size="sm" />
              </div>

              <div>
                <h2 className="text-xl sm:text-2xl font-bold font-mono text-white tracking-tight">
                  {scan.target}
                </h2>
                <p className="text-xs text-zinc-400 mt-1">Autonomous security assessment runtime</p>
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
                              ? 'text-emerald-400'
                              : isCurrent
                              ? 'text-white'
                              : 'text-zinc-600'
                          }`}
                        >
                          {isCompleted ? '✓' : isCurrent ? '●' : '○'}
                        </span>
                        <span
                          className={`text-[11px] font-mono ${
                            isCompleted
                              ? 'text-emerald-400 font-medium'
                              : isCurrent
                              ? 'text-white font-bold'
                              : 'text-zinc-500'
                          }`}
                        >
                          {stage}
                        </span>
                      </div>
                      {idx < progressStages.length - 1 && (
                        <span className="text-zinc-700 flex-shrink-0">/</span>
                      )}
                    </React.Fragment>
                  );
                })}
              </div>
            </div>

            {/* Right: Metrics & Actions */}
            <div className="flex flex-col sm:flex-row lg:flex-col items-start sm:items-center lg:items-start gap-3 lg:border-l lg:pl-5 lg:border-zinc-800">
              <div className="flex items-center gap-3 flex-wrap">
                <div className="flex items-center gap-2">
                  <Clock
                    size={14}
                    className={isRunning ? 'text-zinc-300 animate-pulse' : 'text-zinc-500'}
                  />
                  <span className="font-mono text-sm font-bold text-white">
                    {scan.status === 'queued' ? 'Queued' : formattedTime}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <Bug
                    size={14}
                    className={
                      scan.findingsCount.total > 0
                        ? 'text-red-400'
                        : 'text-zinc-500'
                    }
                  />
                  <span className="font-mono text-sm font-bold text-white">
                    {scan.findingsCount.total} findings
                  </span>
                </div>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                {isSimulated && isRunning && (
                  <>
                    <button
                      onClick={togglePause}
                      className="p-2 rounded-lg border border-zinc-800 bg-[#18181B] hover:bg-zinc-800 text-zinc-300 transition-colors"
                      title={isPaused ? 'Resume Simulation' : 'Pause Simulation'}
                    >
                      {isPaused ? <Play size={14} className="fill-current text-emerald-400" /> : <Pause size={14} />}
                    </button>
                    <button
                      onClick={fastForward}
                      className="p-2 rounded-lg border border-zinc-800 bg-[#18181B] hover:bg-zinc-800 text-zinc-300 transition-colors"
                      title="Fast-forward / Complete Scan"
                    >
                      <FastForward size={14} />
                    </button>
                  </>
                )}
                {isCancellable && (
                  <button
                    onClick={handleCancel}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-red-900/60 bg-red-950/40 text-red-300 hover:bg-red-900/50 text-xs font-medium transition-colors"
                  >
                    <Ban size={13} />
                    <span className="hidden sm:inline">Cancel</span>
                  </button>
                )}
                <button
                  onClick={() => navigate('/findings')}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-zinc-100 text-zinc-900 font-medium text-xs tracking-wide hover:bg-zinc-200 transition-colors shadow-sm"
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
            <div className="bg-[#18181B] border border-zinc-700 rounded-2xl p-4 sm:p-5 shadow-lg">
              <div className="flex items-start gap-3">
                <div className="mt-0.5 w-3 h-3 rounded-full bg-emerald-400 animate-pulse flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className="text-xs font-mono font-bold text-zinc-300 uppercase tracking-wider">
                      Current Agent Action
                    </span>
                    {currentEvent.tool && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 border border-zinc-700 text-zinc-300">
                        {currentEvent.tool}
                      </span>
                    )}
                  </div>
                  <h4 className="text-sm font-bold text-white mb-1">{currentEvent.title}</h4>
                  <p className="text-xs text-zinc-400 line-clamp-2">{currentEvent.description}</p>
                  {currentEvent.reasoning && (
                    <div className="mt-2">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          toggleEventExpand(currentEvent.id);
                        }}
                        className="text-[10px] text-zinc-500 hover:text-zinc-300 flex items-center gap-1 font-mono transition-colors"
                      >
                        <span>Why this action? {expandedEvents[currentEvent.id] ? '−' : '+'}</span>
                      </button>
                      <AnimatePresence>
                        {expandedEvents[currentEvent.id] && (
                          <motion.div
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            className="mt-2 p-3 rounded-xl bg-[#09090B] border border-zinc-800 text-[11px] text-zinc-300 font-mono"
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
        <div className="bg-[#121214] border border-zinc-800 rounded-2xl p-4 sm:p-5 shadow-xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h3 className="text-sm font-semibold text-white">Security Signals</h3>
              <p className="text-xs text-zinc-400 mt-0.5">Findings detected during assessment</p>
            </div>
            <div className="flex items-center gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold font-mono text-white">{scan.findingsCount.total}</div>
                <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-mono">Findings</div>
              </div>
              <div className="h-10 w-px bg-zinc-800" />
              <div className="flex gap-3 text-xs font-mono">
                <div className="text-center">
                  <div className="font-bold text-red-400">{scan.findingsCount.critical}</div>
                  <div className="text-[10px] text-zinc-400">Critical</div>
                </div>
                <div className="text-center">
                  <div className="font-bold text-amber-400">{scan.findingsCount.high}</div>
                  <div className="text-[10px] text-zinc-400">High</div>
                </div>
                <div className="text-center">
                  <div className="font-bold text-yellow-400">{scan.findingsCount.medium}</div>
                  <div className="text-[10px] text-zinc-400">Medium</div>
                </div>
                <div className="text-center">
                  <div className="font-bold text-emerald-400">{scan.findingsCount.low}</div>
                  <div className="text-[10px] text-zinc-400">Low</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Agent Activity Timeline */}
      <motion.div variants={itemVariants}>
        <div className="bg-[#121214] border border-zinc-800 rounded-2xl p-4 sm:p-5 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-white">Agent Activity</h3>
              <p className="text-xs text-zinc-400 mt-0.5">
                Chronological sequence of autonomous decisions and tool executions
              </p>
            </div>

            {isRunning && (
              <span className="text-xs font-mono text-emerald-400 flex items-center gap-1.5 font-semibold">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                Live
              </span>
            )}
          </div>

          {events.length === 0 ? (
            <div className="py-8 text-center space-y-2">
              <Inbox size={24} className="mx-auto text-zinc-600" />
              <p className="text-xs text-zinc-400">
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
                    className={`group relative pl-4 pr-3 py-3 rounded-xl border transition-all cursor-pointer ${
                      isInProgress
                        ? 'bg-[#18181B] border-zinc-600 shadow-md'
                        : isCompleted
                        ? 'bg-[#18181B]/70 border-zinc-800 hover:border-zinc-700 hover:bg-[#18181B]'
                        : 'bg-[#121214] border-zinc-800/60 opacity-60'
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <div
                        className={`mt-1 w-2 h-2 rounded-full flex-shrink-0 ${
                          isCompleted
                            ? 'bg-emerald-400'
                            : isInProgress
                            ? 'bg-cyan-400 animate-pulse'
                            : 'bg-zinc-600'
                        }`}
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs font-semibold text-white">{evt.title}</span>
                          {evt.tool && (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 border border-zinc-700 text-zinc-300">
                              {evt.tool}
                            </span>
                          )}
                          {isInProgress && (
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800 animate-pulse">
                              RUNNING
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-zinc-400 mt-1 line-clamp-1">{evt.description}</p>
                        
                        {/* Collapsible Reasoning */}
                        {evt.reasoning && (
                          <div className="mt-2">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                toggleEventExpand(evt.id);
                              }}
                              className="text-[10px] text-zinc-500 hover:text-zinc-300 flex items-center gap-1 font-mono transition-colors"
                            >
                              <span>{isExpanded ? 'Why? −' : 'Why? +'}</span>
                            </button>
                            <AnimatePresence>
                              {isExpanded && (
                                <motion.div
                                  initial={{ opacity: 0, height: 0 }}
                                  animate={{ opacity: 1, height: 'auto' }}
                                  exit={{ opacity: 0, height: 0 }}
                                  className="mt-2 p-2.5 rounded-lg bg-[#09090B] border border-zinc-800 text-[11px] text-zinc-300 font-mono"
                                >
                                  {evt.reasoning}
                                </motion.div>
                              )}
                            </AnimatePresence>
                          </div>
                        )}
                      </div>
                      <div className="text-[10px] text-zinc-500 font-mono whitespace-nowrap">
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
            className="fixed right-0 top-0 bottom-0 w-96 bg-[#121214] border-l border-zinc-800 shadow-2xl z-50 overflow-y-auto text-zinc-100"
          >
            <div className="p-4 border-b border-zinc-800 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white">Event Inspector</h3>
              <button
                onClick={closeInspector}
                className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors"
                aria-label="Close inspector"
              >
                <X size={16} />
              </button>
            </div>
            <div className="p-4 space-y-4">
              <div>
                <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-mono font-semibold mb-1">Title</div>
                <div className="text-sm font-semibold text-white">{selectedEvent.title}</div>
              </div>
              
              {selectedEvent.tool && (
                <div>
                  <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-mono font-semibold mb-1">Tool</div>
                  <div className="text-sm font-mono text-zinc-200 bg-[#18181B] px-2 py-0.5 rounded border border-zinc-800 inline-block">{selectedEvent.tool}</div>
                </div>
              )}

              <div>
                <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-mono font-semibold mb-1">Status</div>
                <div className="text-sm font-mono text-zinc-200 capitalize">{selectedEvent.status.replace('_', ' ')}</div>
              </div>

              {selectedEvent.durationMs && (
                <div>
                  <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-mono font-semibold mb-1">Duration</div>
                  <div className="text-sm font-mono text-zinc-200">{(selectedEvent.durationMs / 1000).toFixed(2)}s</div>
                </div>
              )}

              <div>
                <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-mono font-semibold mb-1">Timestamp</div>
                <div className="text-sm font-mono text-zinc-200">{new Date(selectedEvent.timestamp).toLocaleString()}</div>
              </div>

              {selectedEvent.description && (
                <div>
                  <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-mono font-semibold mb-1">Description</div>
                  <div className="text-sm text-zinc-300">{selectedEvent.description}</div>
                </div>
              )}

              {selectedEvent.reasoning && (
                <div>
                  <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-mono font-semibold mb-1">Reasoning</div>
                  <div className="text-sm text-zinc-300">{selectedEvent.reasoning}</div>
                </div>
              )}

              {selectedEvent.payload && (
                <div>
                  <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-mono font-semibold mb-1">Payload</div>
                  <pre className="text-[11px] font-mono text-zinc-300 bg-[#09090B] p-2.5 rounded-lg border border-zinc-800 overflow-x-auto">
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
            className="fixed inset-0 bg-black/75 backdrop-blur-sm z-40"
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
