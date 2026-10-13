import React, { useMemo, lazy, Suspense } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
  Activity,
  Bug,
  Globe,
  ShieldPlus,
  ArrowRight,
  Radio,
  AlertTriangle,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  Cpu,
  Clock,
  Loader2,
} from 'lucide-react';
import { useScans } from '../context/ScanContext';

import { Card } from '../components/common/Card';
import { StatusBadge } from '../components/common/StatusBadge';
import { EmptyState } from '../components/common/EmptyState';
import { DemoBanner } from '../components/common/DemoBanner';
import { SCAN_PROFILES } from '../types/scan';

const ThreatGlobe = lazy(() => import('../components/common/ThreatGlobe'));

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const { scans, severityStats, totalAssets, isDemo, loading, error, refreshData } = useScans();

  const activeScans = useMemo(
    () =>
      scans.filter(
        (s) => s.status === 'running' || s.status === 'queued' || s.status === 'initializing'
      ),
    [scans]
  );
  const recentScans = useMemo(() => scans.slice(0, 6), [scans]);

  // Derive unique monitored targets
  const uniqueAssets = useMemo(
    () => Array.from(new Set(scans.map((s) => s.target))),
    [scans]
  );

  // Security Posture Summary based on real severity counts
  const securityPosture = useMemo(() => {
    if (severityStats.critical > 0) {
      return {
        level: 'Critical Risk',
        description: `${severityStats.critical} critical vulnerabilities require immediate remediation`,
        badgeText: `${severityStats.critical} Critical`,
        badgeVariant: 'danger' as const,
        accentColor: 'rose' as const,
        icon: ShieldAlert,
        pillClass: 'bg-red-950/60 border-red-800 text-red-300',
        dotClass: 'bg-red-400 animate-pulse',
      };
    }

    if (severityStats.high > 0) {
      return {
        level: 'Elevated Exposure',
        description: `${severityStats.high} high severity findings identified across perimeter`,
        badgeText: `${severityStats.high} High`,
        badgeVariant: 'warning' as const,
        accentColor: 'amber' as const,
        icon: AlertTriangle,
        pillClass: 'bg-amber-950/60 border-amber-800 text-amber-300',
        dotClass: 'bg-amber-400',
      };
    }

    if (severityStats.total > 0) {
      return {
        level: 'Moderate Notice',
        description: `${severityStats.total} findings identified with zero critical weaknesses`,
        badgeText: `${severityStats.total} Findings`,
        badgeVariant: 'default' as const,
        accentColor: 'cyan' as const,
        icon: Activity,
        pillClass: 'bg-zinc-800 border-zinc-700 text-zinc-300',
        dotClass: 'bg-zinc-400',
      };
    }

    return {
      level: 'Perimeter Secure',
      description: 'Zero vulnerabilities detected across monitored attack surfaces',
      badgeText: 'Clean',
      badgeVariant: 'success' as const,
      accentColor: 'emerald' as const,
      icon: ShieldCheck,
      pillClass: 'bg-emerald-950/60 border-emerald-800 text-emerald-300',
      dotClass: 'bg-emerald-400',
    };
  }, [severityStats]);

  const activeScan = activeScans[0];

  // Use backend totalAssets as source of truth; use unique target count in demo mode
  const assetDisplayCount = isDemo ? uniqueAssets.length : totalAssets;

  if (loading) {
    return (
      <div className="py-24 text-center">
        <div className="inline-block animate-spin w-8 h-8 border-2 border-zinc-200 border-t-transparent rounded-full mb-3" />
        <p className="text-xs text-zinc-400 font-mono">Initializing Sentinel AI Telemetry...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Simulation / Live Environment Notification */}
      <DemoBanner variant="compact" />

      {/* Backend API Error Banner if request failed */}
      {error && (
        <div className="p-4 rounded-xl border border-red-900/60 bg-red-950/40 text-xs text-red-300 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <AlertTriangle size={16} className="text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button
            onClick={() => refreshData()}
            className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-red-900/50 hover:bg-red-900 text-red-200 font-mono text-[11px] transition-colors shrink-0"
          >
            <RotateCcw size={12} />
            <span>Retry Connection</span>
          </button>
        </div>
      )}

      {/* Top Hero / Welcome Banner with Streamlined Proportions & 3D Threat Globe */}
      <div className="relative overflow-hidden rounded-2xl border border-zinc-800 bg-[#121214] p-5 sm:p-6 lg:p-7 shadow-2xl">
        <div className="relative flex flex-col lg:flex-row gap-6 items-center">
          {/* Left Side: Context, Posture Status & Actions */}
          <div className="flex-1 space-y-3 w-full">
            <div className="flex flex-wrap items-center gap-2">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-zinc-800 border border-zinc-700 text-zinc-300 text-[11px] font-mono font-medium tracking-wide uppercase">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                Autonomous AI Security Engine
              </div>
              <div className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full border text-[11px] font-mono font-medium tracking-wide ${securityPosture.pillClass}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${securityPosture.dotClass}`} />
                <span>{securityPosture.level}</span>
              </div>
            </div>

            <h2 className="text-xl sm:text-2xl lg:text-[26px] font-bold tracking-tight text-white text-balance">
              Continuous AI-Assisted Penetration Testing
            </h2>
            <p className="text-xs sm:text-sm text-zinc-400 leading-relaxed max-w-xl">
              Targeted reconnaissance, autonomous multi-tool scanning, and verified vulnerability telemetry with actionable remediation guidance.
            </p>

            <div className="pt-2 flex flex-wrap items-center gap-3">
              <button
                onClick={() => navigate('/new-scan')}
                className="inline-flex items-center gap-2 px-4 sm:px-5 py-2.5 rounded-lg bg-zinc-100 text-zinc-900 font-medium text-xs hover:bg-zinc-200 transition-colors shadow-sm"
              >
                <ShieldPlus size={16} />
                <span>Start New Pentest</span>
              </button>
              <button
                onClick={() => navigate('/findings')}
                className="inline-flex items-center gap-2 px-4 sm:px-5 py-2.5 rounded-lg bg-[#18181B] border border-zinc-800 text-zinc-200 font-medium text-xs hover:bg-zinc-800 hover:text-white transition-colors"
              >
                <Bug size={15} className="text-zinc-400" />
                <span>Review Findings ({severityStats.total})</span>
              </button>
            </div>
          </div>

          {/* Right Side: The Interactive 3D Threat Globe with Constrained Height */}
          <div className="flex-1 w-full h-[220px] sm:h-[260px] lg:h-[280px] flex items-center justify-center">
            <Suspense
              fallback={
                <div className="w-full h-full flex items-center justify-center text-zinc-500 font-mono text-[11px] animate-pulse">
                  <span>INITIALIZING 3D THREAT TELEMETRY...</span>
                </div>
              }
            >
              <ThreatGlobe />
            </Suspense>
          </div>
        </div>
      </div>

      {/* Security Overview — unified compact metrics bar */}
      <div
        className="rounded-xl border border-zinc-800 bg-[#121214] shadow-lg overflow-hidden"
        style={{ animation: 'kpi-fade-in 0.35s ease both' }}
      >
        <div className="flex flex-col sm:flex-row divide-y sm:divide-y-0 sm:divide-x divide-zinc-800">

          {/* Primary: Security Posture */}
          <div className="flex items-start gap-3.5 px-5 py-4 sm:w-[38%] lg:w-[32%] shrink-0 group hover:bg-zinc-800/30 transition-colors duration-200">
            <div
              className={`mt-0.5 p-2 rounded-lg border shrink-0 transition-colors duration-200 ${
                securityPosture.accentColor === 'rose'
                  ? 'bg-red-950/40 border-red-900/60 text-red-400'
                  : securityPosture.accentColor === 'amber'
                  ? 'bg-amber-950/40 border-amber-900/60 text-amber-400'
                  : securityPosture.accentColor === 'emerald'
                  ? 'bg-emerald-950/40 border-emerald-900/60 text-emerald-400'
                  : 'bg-zinc-800 border-zinc-700 text-zinc-300'
              }`}
            >
              <securityPosture.icon size={15} aria-hidden="true" />
            </div>
            <div className="min-w-0">
              <p className="text-[10px] font-mono font-semibold uppercase tracking-wider text-zinc-500 mb-0.5">Security Posture</p>
              <p className="text-sm font-bold text-white leading-snug truncate">{securityPosture.level}</p>
              <p className="text-[11px] text-zinc-400 mt-1 leading-relaxed line-clamp-2">{securityPosture.description}</p>
              <span
                className={`inline-flex items-center gap-1 mt-2 px-2 py-0.5 rounded text-[10px] font-mono font-semibold border ${securityPosture.pillClass}`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${securityPosture.dotClass}`} />
                {securityPosture.badgeText}
              </span>
            </div>
          </div>

          {/* Supporting metrics — three equal columns */}
          <div className="flex flex-1 flex-col xs:flex-row divide-y xs:divide-y-0 xs:divide-x divide-zinc-800">

            {/* Active Scans */}
            <button
              onClick={() => navigate('/history')}
              className="flex-1 flex items-start gap-3 px-5 py-4 text-left hover:bg-zinc-800/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-zinc-500 transition-colors duration-200 group"
              aria-label="Active autonomous scans — view scan history"
            >
              <div
                className={`mt-0.5 p-2 rounded-lg border shrink-0 transition-colors duration-200 ${
                  activeScans.length > 0
                    ? 'bg-emerald-950/40 border-emerald-900/60 text-emerald-400'
                    : 'bg-zinc-800/60 border-zinc-700 text-zinc-500'
                }`}
              >
                <Radio size={14} aria-hidden="true" />
              </div>
              <div className="min-w-0">
                <p className="text-[10px] font-mono font-semibold uppercase tracking-wider text-zinc-500 mb-0.5">Active Scans</p>
                <p className="text-2xl font-bold tabular-nums text-white font-mono leading-none">
                  {activeScans.length}
                </p>
                <p className="text-[11px] text-zinc-400 mt-1 truncate">
                  {activeScans.length > 0
                    ? activeScans[0].target
                    : 'Workers standing by'}
                </p>
                {activeScans.length > 0 && (
                  <span className="inline-flex items-center gap-1 mt-1.5 text-[10px] font-mono text-emerald-400">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    Live
                  </span>
                )}
              </div>
            </button>

            {/* Vulnerabilities */}
            <button
              onClick={() => navigate('/findings')}
              className="flex-1 flex items-start gap-3 px-5 py-4 text-left hover:bg-zinc-800/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-zinc-500 transition-colors duration-200 group"
              aria-label={`${severityStats.total} vulnerabilities found — view findings`}
            >
              <div
                className={`mt-0.5 p-2 rounded-lg border shrink-0 transition-colors duration-200 ${
                  severityStats.critical > 0
                    ? 'bg-red-950/40 border-red-900/60 text-red-400'
                    : severityStats.high > 0
                    ? 'bg-amber-950/40 border-amber-900/60 text-amber-400'
                    : 'bg-zinc-800/60 border-zinc-700 text-zinc-500'
                }`}
              >
                <Bug size={14} aria-hidden="true" />
              </div>
              <div className="min-w-0">
                <p className="text-[10px] font-mono font-semibold uppercase tracking-wider text-zinc-500 mb-0.5">Vulnerabilities</p>
                <p
                  className={`text-2xl font-bold tabular-nums font-mono leading-none ${
                    severityStats.critical > 0
                      ? 'text-red-400'
                      : severityStats.high > 0
                      ? 'text-amber-400'
                      : 'text-white'
                  }`}
                >
                  {severityStats.total}
                </p>
                <p className="text-[11px] text-zinc-400 mt-1 tabular-nums font-mono">
                  {severityStats.critical}C · {severityStats.high}H · {severityStats.medium}M · {severityStats.low}L
                </p>
                {(severityStats.critical > 0 || severityStats.high > 0) && (
                  <span
                    className={`inline-flex items-center gap-1 mt-1.5 text-[10px] font-mono font-semibold ${
                      severityStats.critical > 0 ? 'text-red-400' : 'text-amber-400'
                    }`}
                  >
                    <AlertTriangle size={10} aria-hidden="true" />
                    {severityStats.critical > 0 ? 'Needs attention' : 'Elevated'}
                  </span>
                )}
              </div>
            </button>

            {/* Monitored Assets */}
            <div className="flex-1 flex items-start gap-3 px-5 py-4 hover:bg-zinc-800/30 transition-colors duration-200 group">
              <div className="mt-0.5 p-2 rounded-lg border shrink-0 bg-zinc-800/60 border-zinc-700 text-zinc-400 transition-colors duration-200">
                <Globe size={14} aria-hidden="true" />
              </div>
              <div className="min-w-0">
                <p className="text-[10px] font-mono font-semibold uppercase tracking-wider text-zinc-500 mb-0.5">Monitored Assets</p>
                <p className="text-2xl font-bold tabular-nums text-white font-mono leading-none">
                  {assetDisplayCount}
                </p>
                <p className="text-[11px] text-zinc-400 mt-1">
                  {scans.length === 1 ? '1 scan total' : `${scans.length} scans total`}
                </p>
              </div>
            </div>

          </div>
        </div>
      </div>

      {/* Main Grid: Severity Breakdown + Live AI Engine Status */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Breakdown Card (2 Cols) */}
        <div className="lg:col-span-2">
          <Card
            header="Vulnerability Severity Breakdown"
            subtitle="Distribution of security findings across all completed assessments"
            action={
              <Link
                to="/findings"
                className="text-xs text-zinc-400 hover:text-white flex items-center gap-1 font-medium transition-colors group"
              >
                <span>View All Findings</span>
                <ArrowRight size={13} className="transition-transform group-hover:translate-x-0.5" />
              </Link>
            }
          >
            {/* Inline high-density Severity section with compact counts primary, distribution bar secondary */}
            {(() => {
              const totalFindings = severityStats.total || 0;
              const severityTiers = [
                {
                  key: 'critical',
                  label: 'Critical',
                  count: severityStats.critical,
                  colorClass: 'text-rose-400',
                  barColor: 'bg-rose-500',
                  bgClass: 'bg-rose-950/30',
                  borderClass: 'border-rose-900/60',
                  dotClass: 'bg-rose-500',
                },
                {
                  key: 'high',
                  label: 'High',
                  count: severityStats.high,
                  colorClass: 'text-amber-400',
                  barColor: 'bg-amber-500',
                  bgClass: 'bg-amber-950/30',
                  borderClass: 'border-amber-900/60',
                  dotClass: 'bg-amber-500',
                },
                {
                  key: 'medium',
                  label: 'Medium',
                  count: severityStats.medium,
                  colorClass: 'text-yellow-400',
                  barColor: 'bg-yellow-500',
                  bgClass: 'bg-yellow-950/30',
                  borderClass: 'border-yellow-900/60',
                  dotClass: 'bg-yellow-400',
                },
                {
                  key: 'low',
                  label: 'Low',
                  count: severityStats.low,
                  colorClass: 'text-emerald-400',
                  barColor: 'bg-emerald-500',
                  bgClass: 'bg-emerald-950/30',
                  borderClass: 'border-emerald-900/60',
                  dotClass: 'bg-emerald-400',
                },
                {
                  key: 'info',
                  label: 'Info',
                  count: severityStats.info,
                  colorClass: 'text-zinc-400',
                  barColor: 'bg-zinc-500',
                  bgClass: 'bg-zinc-900/40',
                  borderClass: 'border-zinc-800',
                  dotClass: 'bg-zinc-500',
                },
              ];

              const getPercentage = (count: number) => {
                if (totalFindings === 0) return 0;
                return Math.round((count / totalFindings) * 100);
              };

              return (
                <div className="space-y-4">
                  {/* Primary Focal Point: 5 Compact Severity Count Blocks with Consistent Sizing */}
                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
                    {severityTiers.map((tier) => (
                      <div
                        key={tier.key}
                        className={`p-3 rounded-xl border ${tier.borderClass} ${tier.bgClass} flex flex-col justify-between transition-all duration-150 hover:border-zinc-700/80`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-1.5">
                            <span className={`w-1.5 h-1.5 rounded-full ${tier.dotClass}`} />
                            <span className={`text-xs font-semibold ${tier.colorClass}`}>{tier.label}</span>
                          </div>
                          <span className="text-[10px] font-mono text-zinc-400 tabular-nums">
                            {getPercentage(tier.count)}%
                          </span>
                        </div>
                        <div className="mt-2.5 flex items-baseline justify-between">
                          <span className="text-2xl font-bold font-mono tabular-nums text-white tracking-tight">
                            {tier.count}
                          </span>
                          <span className="text-[10px] text-zinc-400 font-mono">
                            {tier.count === 1 ? 'finding' : 'findings'}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Secondary Visual Accent: Proportional Distribution Spectrum Bar */}
                  <div className="pt-2 border-t border-zinc-800/80">
                    <div className="flex items-center justify-between text-xs mb-2 font-mono">
                      <span className="text-[11px] uppercase tracking-wider text-zinc-400 font-semibold flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                        Exposure Spectrum
                      </span>
                      <span className="text-zinc-400 text-[11px]">
                        <span className="text-white font-bold tabular-nums">{totalFindings}</span> verified findings across perimeter
                      </span>
                    </div>

                    {totalFindings === 0 ? (
                      <div className="h-2 w-full rounded-full bg-zinc-800/60 border border-zinc-800 flex items-center justify-center">
                        <span className="text-[10px] text-zinc-400 font-mono">Perimeter clean · Zero vulnerabilities detected</span>
                      </div>
                    ) : (
                      <div className="h-2 w-full rounded-full bg-zinc-800/80 border border-zinc-800/80 flex overflow-hidden shadow-inner gap-0.5">
                        {severityTiers.map((tier) => {
                          const widthPct = (tier.count / totalFindings) * 100;
                          if (widthPct === 0) return null;
                          return (
                            <div
                              key={tier.key}
                              style={{ width: `${widthPct}%` }}
                              className={`${tier.barColor} transition-all duration-300 hover:opacity-90`}
                              title={`${tier.label}: ${tier.count} (${Math.round(widthPct)}%)`}
                            />
                          );
                        })}
                      </div>
                    )}
                  </div>
                </div>
              );
            })()}
          </Card>
        </div>

        {/* Real AI Engine & Operations Status (1 Col) */}
        <div className="space-y-4">
          <Card
            header="AI Engine & Operations"
            subtitle="Autonomous assessment runtime status"
          >
            {(() => {
              const currentStep = activeScan?.currentStep || 0;
              const totalSteps = activeScan?.totalSteps || 1;
              const progressRatio = activeScan && totalSteps > 0 ? currentStep / totalSteps : 0;
              const progressPercent = Math.min(100, Math.round(progressRatio * 100));
              const isScanCompleted = activeScan?.status === 'completed' || activeScan?.status === 'finished';

              // Lifecycle stage states accurately derived from scan step progression
              // Never mark stages complete by position alone
              const getStageStatus = (stageIdx: number) => {
                if (!activeScan) return 'idle';
                if (isScanCompleted) return 'completed';

                if (stageIdx === 1) {
                  // Reconnaissance: threshold 0.33
                  if (progressRatio >= 0.33) return 'completed';
                  return 'active';
                }
                if (stageIdx === 2) {
                  // Vulnerability Scanning: threshold 0.75
                  if (progressRatio >= 0.75) return 'completed';
                  if (progressRatio >= 0.33) return 'active';
                  return 'pending';
                }
                if (stageIdx === 3) {
                  // Remediation & Evidence: threshold 1.0
                  if (progressRatio >= 1.0) return 'completed';
                  if (progressRatio >= 0.75) return 'active';
                  return 'pending';
                }
                return 'idle';
              };

              const stages = [
                { id: 1, name: 'Reconnaissance & Surface Mapping' },
                { id: 2, name: 'Dynamic Vulnerability Scanning' },
                { id: 3, name: 'Evidence Extraction & Remediation' },
              ];

              return (
                <div className="space-y-3.5 text-xs">
                  {/* Distinct Engine Health Header Bar */}
                  <div className="flex items-center justify-between text-[11px] font-mono px-3 py-2 rounded-xl bg-zinc-900/60 border border-zinc-800">
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                      <span className="font-semibold text-zinc-200">Autonomous Core</span>
                      <span className="text-zinc-400">·</span>
                      <span className="text-emerald-400 font-medium">Healthy</span>
                    </div>
                    <span className="text-zinc-400 uppercase text-[10px] tracking-wider">v2.4 Engine</span>
                  </div>

                  {/* Active / Idle Runtime Status Panel */}
                  {activeScan ? (
                    <div className="p-3.5 rounded-xl border border-cyan-800/60 bg-gradient-to-b from-[#18181B] to-cyan-950/20 space-y-2.5">
                      <div className="flex items-center justify-between">
                        <span className="flex items-center gap-1.5 text-cyan-400 font-semibold font-mono text-[11px]">
                          <Cpu size={14} className="animate-pulse" />
                          AGENT RUNTIME ACTIVE
                        </span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-zinc-800 border border-zinc-700 text-zinc-300 tabular-nums">
                          Step {activeScan.currentStep}/{activeScan.totalSteps} ({progressPercent}%)
                        </span>
                      </div>
                      <div className="space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-white font-mono font-medium truncate max-w-[160px]">
                            {activeScan.target}
                          </span>
                          <span className="text-[11px] text-zinc-400 font-mono truncate max-w-[120px]">
                            {SCAN_PROFILES[activeScan.profile]?.name || activeScan.profile}
                          </span>
                        </div>
                        <div className="h-1.5 w-full bg-zinc-800 rounded-full overflow-hidden border border-zinc-700/50">
                          <div
                            className="h-full bg-cyan-500 rounded-full transition-all duration-500"
                            style={{ width: `${progressPercent}%` }}
                          />
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => navigate(`/agent/${activeScan.id}`)}
                        className="w-full mt-1 py-1.5 px-3 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-600/50 text-cyan-200 font-medium text-[11px] flex items-center justify-center gap-1.5 transition-colors font-mono group"
                      >
                        <span>View Live Telemetry</span>
                        <ArrowRight size={12} className="transition-transform group-hover:translate-x-0.5" />
                      </button>
                    </div>
                  ) : (
                    <div className="p-3.5 rounded-xl border border-zinc-800 bg-[#18181B] space-y-2.5">
                      <div className="flex items-center justify-between">
                        <span className="flex items-center gap-1.5 text-zinc-200 font-semibold font-mono text-[11px]">
                          <CheckCircle2 size={14} className="text-emerald-400" />
                          DISPATCH READY
                        </span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-zinc-800/80 border border-zinc-700/80 text-emerald-400">
                          Standby
                        </span>
                      </div>
                      <p className="text-zinc-400 text-[11px] leading-relaxed">
                        All autonomous workers synchronized. Ready to initiate security assessments against authorized targets.
                      </p>
                      <button
                        type="button"
                        onClick={() => navigate('/new-scan')}
                        className="w-full mt-1 py-1.5 px-3 rounded-lg bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-100 font-medium text-[11px] flex items-center justify-center gap-1.5 transition-colors font-mono group"
                      >
                        <ShieldPlus size={12} className="text-zinc-400 group-hover:text-white" />
                        <span>Launch New Pentest</span>
                        <ArrowRight size={12} className="transition-transform group-hover:translate-x-0.5" />
                      </button>
                    </div>
                  )}

                  {/* Assessment Lifecycle Progress Stepper */}
                  <div className="p-3.5 rounded-xl border border-zinc-800 bg-[#18181B] space-y-2.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-mono font-semibold text-zinc-400 uppercase tracking-wider">
                        Assessment Lifecycle
                      </span>
                      <span className="text-[10px] font-mono text-zinc-400">
                        {activeScan ? `Active (${progressPercent}%)` : 'Pipeline Ready'}
                      </span>
                    </div>

                    <div className="space-y-2 text-[11px] font-mono">
                      {stages.map((stage) => {
                        const status = getStageStatus(stage.id);
                        return (
                          <div
                            key={stage.id}
                            className={`flex items-center justify-between px-2.5 py-1.5 rounded-lg border transition-all ${
                              status === 'completed'
                                ? 'bg-emerald-950/20 border-emerald-900/40 text-emerald-300'
                                : status === 'active'
                                ? 'bg-cyan-950/30 border-cyan-800/50 text-cyan-200'
                                : 'bg-zinc-900/40 border-zinc-800/60 text-zinc-400'
                            }`}
                          >
                            <div className="flex items-center gap-2 truncate">
                              {status === 'completed' ? (
                                <CheckCircle2 size={13} className="text-emerald-400 shrink-0" />
                              ) : status === 'active' ? (
                                <Loader2 size={13} className="text-cyan-400 animate-spin shrink-0" />
                              ) : (
                                <span className="w-1.5 h-1.5 rounded-full bg-zinc-400 shrink-0 ml-1 mr-0.5" />
                              )}
                              <span className="truncate">{stage.name}</span>
                            </div>

                            <span className="text-[10px] shrink-0 uppercase tracking-wider ml-2">
                              {status === 'completed' && (
                                <span className="text-emerald-400 font-semibold">Done</span>
                              )}
                              {status === 'active' && (
                                <span className="text-cyan-300 font-semibold animate-pulse">Running</span>
                              )}
                              {status === 'pending' && (
                                <span className="text-zinc-400">Pending</span>
                              )}
                              {status === 'idle' && (
                                <span className="text-zinc-400">Ready</span>
                              )}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              );
            })()}
          </Card>
        </div>
      </div>

      {/* Recent Scans Table */}
      <Card
        header="Recent Penetration Testing Runs"
        subtitle="Latest automated executions across monitored infrastructure"
        action={
          <Link
            to="/history"
            className="text-xs text-zinc-400 hover:text-white flex items-center gap-1 font-medium transition-colors group"
          >
            <span>Complete Scan Archive</span>
            <ArrowRight size={13} className="transition-transform group-hover:translate-x-0.5" />
          </Link>
        }
        noPadding
      >
        {scans.length === 0 ? (
          <EmptyState
            icon={Activity}
            title="No Penetration Tests Yet"
            description="You have not launched any penetration tests yet. Initiate an assessment against your authorized target."
            action={{
              label: 'Launch First Pentest',
              icon: ShieldPlus,
              onClick: () => navigate('/new-scan'),
            }}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-zinc-300 min-w-[720px]">
              <thead className="bg-[#18181B] text-zinc-400 uppercase tracking-wider font-mono text-[10px] border-b border-zinc-800">
                <tr>
                  <th scope="col" className="px-4 py-2.5 font-semibold">Target Asset</th>
                  <th scope="col" className="px-3 py-2.5 font-semibold">Profile</th>
                  <th scope="col" className="px-3 py-2.5 font-semibold">Status</th>
                  <th scope="col" className="px-3 py-2.5 font-semibold">Started</th>
                  <th scope="col" className="px-3 py-2.5 font-semibold">Findings Breakdown</th>
                  <th scope="col" className="px-4 py-2.5 text-right font-semibold">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/80 bg-[#121214]">
                {recentScans.map((scan) => {
                  const profile = SCAN_PROFILES[scan.profile] || { name: scan.profile };
                  const totalFindings = scan.findingsCount.total;
                  return (
                    <tr
                      key={scan.id}
                      onClick={() => navigate(`/agent/${scan.id}`)}
                      className="hover:bg-zinc-800/40 cursor-pointer transition-colors group"
                    >
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-2">
                          <code className="text-zinc-100 font-mono font-medium group-hover:text-white transition-colors">
                            {scan.target}
                          </code>
                          <span className="text-[10px] text-zinc-400 font-mono">
                            #{scan.id.slice(0, 8)}
                          </span>
                        </div>
                      </td>
                      <td className="px-3 py-2.5 text-zinc-300 font-medium">
                        <span className="px-2 py-0.5 rounded text-[11px] bg-zinc-800/70 border border-zinc-700/60 text-zinc-300 font-mono">
                          {profile.name}
                        </span>
                      </td>
                      <td className="px-3 py-2.5">
                        <StatusBadge status={scan.status} size="sm" />
                      </td>
                      <td className="px-3 py-2.5 text-zinc-400 font-mono tabular-nums whitespace-nowrap">
                        <div className="flex items-center gap-1.5 text-[11px]">
                          <Clock size={12} className="text-zinc-400 shrink-0" />
                          <span>
                            {new Date(scan.startedAt).toLocaleDateString([], { month: 'short', day: 'numeric' })}{' '}
                            {new Date(scan.startedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </span>
                        </div>
                      </td>
                      <td className="px-3 py-2.5">
                        {totalFindings === 0 ? (
                          <span className="inline-flex items-center gap-1.5 text-[11px] text-zinc-400 font-mono">
                            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500/80" />
                            Clean (0)
                          </span>
                        ) : (
                          <div className="flex items-center gap-1 font-mono">
                            {scan.findingsCount.critical > 0 && (
                              <span
                                className="px-1.5 py-0.5 rounded bg-rose-950/60 border border-rose-800 text-rose-300 text-[10px] font-bold"
                                title="Critical Findings"
                              >
                                {scan.findingsCount.critical}C
                              </span>
                            )}
                            {scan.findingsCount.high > 0 && (
                              <span
                                className="px-1.5 py-0.5 rounded bg-amber-950/60 border border-amber-800 text-amber-300 text-[10px] font-bold"
                                title="High Findings"
                              >
                                {scan.findingsCount.high}H
                              </span>
                            )}
                            {scan.findingsCount.medium > 0 && (
                              <span
                                className="px-1.5 py-0.5 rounded bg-yellow-950/60 border border-yellow-800 text-yellow-300 text-[10px]"
                                title="Medium Findings"
                              >
                                {scan.findingsCount.medium}M
                              </span>
                            )}
                            {scan.findingsCount.low > 0 && (
                              <span
                                className="px-1.5 py-0.5 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-300 text-[10px]"
                                title="Low Findings"
                              >
                                {scan.findingsCount.low}L
                              </span>
                            )}
                            {scan.findingsCount.info > 0 && (
                              <span
                                className="px-1.5 py-0.5 rounded bg-zinc-800 border border-zinc-700 text-zinc-400 text-[10px]"
                                title="Informational Findings"
                              >
                                {scan.findingsCount.info}I
                              </span>
                            )}
                            <span className="text-[10px] text-zinc-400 font-mono ml-1">
                              ({totalFindings})
                            </span>
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/agent/${scan.id}`);
                          }}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-zinc-700/80 bg-zinc-800/80 hover:bg-zinc-700 hover:border-zinc-600 text-zinc-200 hover:text-white font-mono text-[11px] font-medium transition-all shadow-sm"
                        >
                          <span>Telemetry</span>
                          <ArrowRight size={11} className="transition-transform group-hover:translate-x-0.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
};
