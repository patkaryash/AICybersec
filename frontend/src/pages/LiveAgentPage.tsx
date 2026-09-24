import React, { useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  Radio,
  Clock,
  Ban,
  Bug,
  Pause,
  Play,
  FastForward,
  ChevronDown,
  ChevronUp,
  Terminal,
  Cpu,
  ShieldAlert,
  CheckCircle2,
  Copy,
  Check,
  AlertCircle,
  ExternalLink,
  ArrowRight,
} from 'lucide-react';
import { useScans } from '../context/ScanContext';
import { useTimer } from '../hooks/useTimer';
import { useAgentSimulation } from '../hooks/useAgentSimulation';
import { Card } from '../components/common/Card';
import { StatusBadge } from '../components/common/StatusBadge';
import { DemoBanner } from '../components/common/DemoBanner';
import { SCAN_PROFILES } from '../types/scan';

export const LiveAgentPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate = useNavigate();
  const { scans, stopScan } = useScans();

  const [copiedId, setCopiedId] = useState(false);
  const [expandedEvents, setExpandedEvents] = useState<Record<string, boolean>>({});

  // Find targeted scan, or fallback to first running/available scan
  const scan = scans.find((s) => s.id === scanId) || scans.find((s) => s.status === 'running') || scans[0];

  const profileInfo = scan ? SCAN_PROFILES[scan.profile] : null;

  // Live Elapsed Timer
  const { formattedTime } = useTimer(
    scan?.startedAt || new Date().toISOString(),
    scan?.completedAt,
    scan?.status === 'running'
  );

  // Progressive simulation hook
  const { events, currentStepIndex, isPaused, togglePause, fastForward } = useAgentSimulation(scan);

  const handleCopyScanId = () => {
    if (!scan) return;
    navigator.clipboard.writeText(scan.id);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
  };

  const toggleEventExpand = (id: string) => {
    setExpandedEvents((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  if (!scan) {
    return (
      <div className="py-20 text-center space-y-4">
        <AlertCircle size={36} className="mx-auto text-amber-400" />
        <h3 className="text-lg font-bold text-sentinel-text">Scan Not Found</h3>
        <p className="text-xs text-sentinel-muted max-w-sm mx-auto">
          The requested scan session could not be located in current state.
        </p>
        <button
          onClick={() => navigate('/new-scan')}
          className="px-4 py-2 rounded-lg bg-sentinel-cyan text-sentinel-bg font-semibold text-xs"
        >
          Launch New Pentest
        </button>
      </div>
    );
  }

  const isRunning = scan.status === 'running';

  return (
    <div className="space-y-6">
      {/* Persistent Simulated Data Banner */}
      <DemoBanner />

      {/* Live Agent Control Header Card */}
      <div className="bg-sentinel-surface border border-sentinel-border rounded-xl p-5 sm:p-6 shadow-xl space-y-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          {/* Target & Scan Identity */}
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-mono font-semibold px-2 py-0.5 rounded bg-cyan-950/70 border border-cyan-800 text-cyan-300">
                {profileInfo?.name || scan.profile}
              </span>
              <button
                onClick={handleCopyScanId}
                className="text-xs font-mono text-sentinel-dim bg-sentinel-elevated hover:text-sentinel-text px-2 py-0.5 rounded border border-sentinel-border flex items-center gap-1 transition-colors"
                title="Copy Scan ID"
              >
                <span>{scan.id}</span>
                {copiedId ? <Check size={11} className="text-emerald-400" /> : <Copy size={11} />}
              </button>
              <StatusBadge status={scan.status} size="sm" />
            </div>

            <div className="flex items-baseline gap-3 flex-wrap">
              <h2 className="text-xl sm:text-2xl font-bold font-mono text-sentinel-text tracking-tight">
                {scan.target}
              </h2>
            </div>
          </div>

          {/* Metrics & Actions */}
          <div className="flex items-center gap-4 flex-wrap">
            {/* Live Timer Tile */}
            <div className="bg-sentinel-bg px-3.5 py-2 rounded-lg border border-sentinel-border flex items-center gap-2.5">
              <Clock size={16} className={isRunning ? 'text-cyan-400 animate-pulse' : 'text-sentinel-dim'} />
              <div>
                <span className="text-[10px] text-sentinel-dim block uppercase font-mono tracking-wider">
                  Duration
                </span>
                <span className="font-mono text-sm font-bold text-sentinel-text">
                  {formattedTime}
                </span>
              </div>
            </div>

            {/* Findings Found Tile */}
            <div className="bg-sentinel-bg px-3.5 py-2 rounded-lg border border-sentinel-border flex items-center gap-2.5">
              <Bug size={16} className={scan.findingsCount.total > 0 ? 'text-rose-400' : 'text-sentinel-dim'} />
              <div>
                <span className="text-[10px] text-sentinel-dim block uppercase font-mono tracking-wider">
                  Findings
                </span>
                <span className="font-mono text-sm font-bold text-sentinel-text">
                  {scan.findingsCount.total}
                </span>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex items-center gap-2">
              {isRunning && (
                <>
                  <button
                    onClick={togglePause}
                    className="p-2.5 rounded-lg border border-sentinel-border bg-sentinel-elevated hover:bg-sentinel-subtle text-sentinel-text transition-colors"
                    title={isPaused ? 'Resume Simulation' : 'Pause Simulation'}
                  >
                    {isPaused ? <Play size={14} className="fill-current text-emerald-400" /> : <Pause size={14} />}
                  </button>

                  <button
                    onClick={fastForward}
                    className="p-2.5 rounded-lg border border-sentinel-border bg-sentinel-elevated hover:bg-sentinel-subtle text-sentinel-cyan transition-colors"
                    title="Fast-forward / Complete Scan"
                  >
                    <FastForward size={14} />
                  </button>

                  <button
                    onClick={() => stopScan(scan.id)}
                    className="flex items-center gap-1.5 px-3 py-2 rounded-lg border border-rose-800/80 bg-rose-950/40 text-rose-300 hover:bg-rose-900/50 text-xs font-medium transition-colors"
                  >
                    <Ban size={14} />
                    <span className="hidden sm:inline">Stop Scan</span>
                  </button>
                </>
              )}

              <button
                onClick={() => navigate('/findings')}
                className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-sentinel-cyan text-sentinel-bg font-semibold text-xs tracking-wide hover:bg-sentinel-cyan-hover transition-colors shadow-sm"
              >
                <Bug size={14} />
                <span>View Findings ({scan.findingsCount.total})</span>
              </button>
            </div>
          </div>
        </div>

        {/* Scan Goal Description */}
        <div className="pt-3 border-t border-sentinel-border/60 text-xs text-sentinel-muted flex items-start gap-2">
          <Terminal size={14} className="text-sentinel-dim shrink-0 mt-0.5" />
          <span className="leading-relaxed">
            <strong className="text-sentinel-text">Agent Objective: </strong>
            {scan.goal}
          </span>
        </div>
      </div>

      {/* Timeline Section */}
      <Card
        header={
          <div className="flex items-center justify-between w-full">
            <div className="flex items-center gap-2">
              <Cpu size={18} className="text-sentinel-cyan" />
              <span className="text-base font-semibold text-sentinel-text">Autonomous AI Agent Execution Trace</span>
            </div>
            {isRunning && (
              <span className="text-xs font-mono text-cyan-400 flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                Live Reasoning Loop Active
              </span>
            )}
          </div>
        }
        subtitle="Chronological sequence of autonomous decisions, tool executions, and security findings"
      >
        <div className="relative pl-6 sm:pl-8 space-y-8 before:absolute before:left-3 sm:before:left-4 before:top-3 before:bottom-3 before:w-0.5 before:bg-sentinel-border">
          {events.map((evt, idx) => {
            const isCompleted = evt.status === 'completed';
            const isInProgress = evt.status === 'in_progress';
            const isPending = evt.status === 'pending';
            const isExpanded = expandedEvents[evt.id] || false;

            return (
              <div key={evt.id} className="relative group">
                {/* Step Marker Node */}
                <div
                  className={`absolute -left-6 sm:-left-8 top-0.5 w-6 h-6 rounded-full flex items-center justify-center font-mono text-[11px] font-bold border transition-all ${
                    isCompleted
                      ? 'bg-emerald-950 border-emerald-600 text-emerald-400'
                      : isInProgress
                      ? 'bg-cyan-950 border-cyan-400 text-cyan-300 ring-4 ring-cyan-500/20 animate-pulse'
                      : 'bg-sentinel-elevated border-sentinel-border text-sentinel-dim'
                  }`}
                >
                  {isCompleted ? <CheckCircle2 size={13} /> : idx + 1}
                </div>

                {/* Event Card Content */}
                <div
                  className={`rounded-xl border p-4 transition-all ${
                    isInProgress
                      ? 'bg-sentinel-surface border-cyan-700/80 shadow-[0_0_15px_rgba(6,182,212,0.1)]'
                      : isCompleted
                      ? 'bg-sentinel-surface/80 border-sentinel-border hover:border-sentinel-border-light'
                      : 'bg-sentinel-surface/40 border-sentinel-border/50 opacity-60'
                  }`}
                >
                  {/* Event Header */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-bold text-sentinel-text tracking-tight">
                        {evt.title}
                      </span>
                      {evt.tool && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-sentinel-elevated border border-sentinel-border text-sentinel-cyan">
                          {evt.tool}
                        </span>
                      )}
                      {isInProgress && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 animate-pulse">
                          EXECUTING
                        </span>
                      )}
                    </div>

                    <div className="flex items-center gap-3 text-xs text-sentinel-dim font-mono">
                      {evt.durationMs && (
                        <span>{(evt.durationMs / 1000).toFixed(1)}s</span>
                      )}
                      <span>{new Date(evt.timestamp).toLocaleTimeString()}</span>
                    </div>
                  </div>

                  {/* Plain-English Action Description */}
                  <p className="text-xs text-sentinel-muted mt-2 leading-relaxed">
                    {evt.description}
                  </p>

                  {/* Plain-English AI Rationale Box */}
                  {evt.reasoning && (
                    <div className="mt-3 p-3 rounded-lg border border-purple-900/40 bg-purple-950/20 text-xs flex items-start gap-2.5">
                      <Cpu size={14} className="text-purple-400 shrink-0 mt-0.5" />
                      <div className="space-y-0.5">
                        <span className="font-semibold text-purple-300 font-mono text-[11px] block">
                          AI Agent Rationale & Context
                        </span>
                        <p className="text-sentinel-text/90 leading-relaxed text-[11px]">
                          {evt.reasoning}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Toggleable Technical Details */}
                  {isCompleted && (
                    <div className="mt-3 pt-2 border-t border-sentinel-border/60">
                      <button
                        onClick={() => toggleEventExpand(evt.id)}
                        className="text-[11px] text-sentinel-dim hover:text-sentinel-cyan flex items-center gap-1 font-mono transition-colors"
                      >
                        <span>{isExpanded ? 'Hide Technical Envelope' : 'Inspect Telemetry Payload'}</span>
                        {isExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                      </button>

                      {isExpanded && (
                        <pre className="mt-2 p-3 bg-black/60 border border-sentinel-border rounded-lg text-[11px] font-mono text-emerald-300 overflow-x-auto whitespace-pre leading-relaxed">
                          {JSON.stringify(
                            {
                              event: evt.type,
                              step: evt.step,
                              target: scan.target,
                              tool: evt.tool,
                              status: evt.status,
                              timestamp: evt.timestamp,
                              synthetic: true,
                            },
                            null,
                            2
                          )}
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {/* Completed State Callout */}
        {scan.status === 'finished' && (
          <div className="mt-8 p-5 rounded-xl border border-emerald-800/80 bg-emerald-950/20 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-emerald-950 border border-emerald-700 text-emerald-400">
                <CheckCircle2 size={24} />
              </div>
              <div>
                <h4 className="text-sm font-bold text-emerald-300">Penetration Test Concluded</h4>
                <p className="text-xs text-emerald-200/80 mt-0.5">
                  Autonomous loop finished with {scan.findingsCount.total} verified security findings.
                </p>
              </div>
            </div>

            <button
              onClick={() => navigate('/findings')}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-500 text-emerald-950 font-bold text-xs hover:bg-emerald-400 transition-colors shadow-sm"
            >
              <span>Review Findings</span>
              <ArrowRight size={14} />
            </button>
          </div>
        )}
      </Card>
    </div>
  );
};
