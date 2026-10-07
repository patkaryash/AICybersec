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
} from 'lucide-react';
import { useScans } from '../context/ScanContext';
import { StatCard } from '../components/common/StatCard';
import { Card } from '../components/common/Card';
import { SeverityChart } from '../components/common/SeverityChart';
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
        pillClass: 'bg-rose-950/80 border-rose-800 text-rose-300',
        dotClass: 'bg-rose-400 animate-pulse',
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
        pillClass: 'bg-amber-950/80 border-amber-800 text-amber-300',
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
        pillClass: 'bg-cyan-950/80 border-cyan-800 text-cyan-300',
        dotClass: 'bg-cyan-400',
      };
    }

    return {
      level: 'Perimeter Secure',
      description: 'Zero vulnerabilities detected across monitored attack surfaces',
      badgeText: 'Clean',
      badgeVariant: 'success' as const,
      accentColor: 'emerald' as const,
      icon: ShieldCheck,
      pillClass: 'bg-emerald-950/80 border-emerald-800 text-emerald-300',
      dotClass: 'bg-emerald-400',
    };
  }, [severityStats]);

  const activeScan = activeScans[0];

  // Use backend totalAssets as source of truth; use unique target count in demo mode
  const assetDisplayCount = isDemo ? uniqueAssets.length : totalAssets;

  if (loading) {
    return (
      <div className="py-24 text-center">
        <div className="inline-block animate-spin w-8 h-8 border-2 border-sentinel-cyan border-t-transparent rounded-full mb-3" />
        <p className="text-xs text-sentinel-muted font-mono">Initializing CyberSec AI Telemetry...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Simulation / Live Environment Notification */}
      <DemoBanner variant="compact" />

      {/* Backend API Error Banner if request failed */}
      {error && (
        <div className="p-4 rounded-xl border border-rose-900/80 bg-rose-950/40 text-xs text-rose-300 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <AlertTriangle size={16} className="text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button
            onClick={() => refreshData()}
            className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-rose-900/50 hover:bg-rose-900 text-rose-200 font-mono text-[11px] transition-colors shrink-0"
          >
            <RotateCcw size={12} />
            <span>Retry Connection</span>
          </button>
        </div>
      )}

      {/* Top Hero / Welcome Banner with Streamlined Proportions & 3D Threat Globe */}
      <div className="relative overflow-hidden rounded-2xl border border-sentinel-border/80 bg-gradient-to-br from-sentinel-surface via-[#111A2C] to-[#0C1B26] p-5 sm:p-6 lg:p-7 shadow-xl shadow-black/30 ring-1 ring-white/5">
        <div className="pointer-events-none absolute -top-24 -left-24 h-72 w-72 rounded-full bg-cyan-500/10 blur-[100px]" />
        <div className="pointer-events-none absolute -bottom-32 right-1/4 h-72 w-72 rounded-full bg-purple-600/10 blur-[100px]" />
        
        <div className="relative flex flex-col lg:flex-row gap-6 items-center">
          {/* Left Side: Context, Posture Status & Actions */}
          <div className="flex-1 space-y-3 w-full">
            <div className="flex flex-wrap items-center gap-2">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-800/60 text-cyan-300 text-[11px] font-mono font-medium tracking-wide uppercase">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                Autonomous AI Security Engine
              </div>
              <div className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full border text-[11px] font-mono font-medium tracking-wide ${securityPosture.pillClass}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${securityPosture.dotClass}`} />
                <span>{securityPosture.level}</span>
              </div>
            </div>

            <h2 className="text-xl sm:text-2xl lg:text-[26px] font-bold tracking-tight text-sentinel-text text-balance">
              Continuous AI-Assisted Penetration Testing
            </h2>
            <p className="text-xs sm:text-sm text-sentinel-muted leading-relaxed max-w-xl">
              Targeted reconnaissance, autonomous multi-tool scanning, and verified vulnerability telemetry with actionable remediation guidance.
            </p>

            <div className="pt-2 flex flex-wrap items-center gap-3">
              <button
                onClick={() => navigate('/new-scan')}
                className="inline-flex items-center gap-2 px-4 sm:px-5 py-2.5 rounded-xl bg-sentinel-cyan text-sentinel-bg font-semibold text-xs tracking-wide hover:bg-sentinel-cyan-hover transition-all shadow-lg shadow-cyan-950/40 hover:shadow-cyan-900/40 hover:-translate-y-px"
              >
                <ShieldPlus size={16} />
                <span>Start New Pentest</span>
              </button>
              <button
                onClick={() => navigate('/findings')}
                className="inline-flex items-center gap-2 px-4 sm:px-5 py-2.5 rounded-xl bg-white/5 border border-sentinel-border text-sentinel-text font-medium text-xs hover:bg-white/10 hover:border-sentinel-border-light transition-all"
              >
                <Bug size={15} className="text-sentinel-cyan" />
                <span>Review Findings ({severityStats.total})</span>
              </button>
            </div>
          </div>

          {/* Right Side: The Interactive 3D Threat Globe with Constrained Height */}
          <div className="flex-1 w-full h-[220px] sm:h-[260px] lg:h-[280px] flex items-center justify-center">
            <Suspense
              fallback={
                <div className="w-full h-full flex items-center justify-center text-sentinel-dim font-mono text-[11px] animate-pulse">
                  <span>INITIALIZING 3D THREAT TELEMETRY...</span>
                </div>
              }
            >
              <ThreatGlobe />
            </Suspense>
          </div>
        </div>
      </div>

      {/* 4 Standardized Metric Cards with Strong Hierarchy */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Security Posture"
          value={securityPosture.level}
          subtitle={securityPosture.description}
          icon={securityPosture.icon}
          accentColor={securityPosture.accentColor}
          badge={{
            text: securityPosture.badgeText,
            variant: securityPosture.badgeVariant,
          }}
        />
        <StatCard
          title="Active Autonomous Scans"
          value={activeScans.length}
          subtitle={activeScans.length > 0 ? `${activeScans[0].target} running` : 'Workers idle & standing by'}
          icon={Radio}
          accentColor={activeScans.length > 0 ? 'emerald' : 'purple'}
          badge={
            activeScans.length > 0
              ? { text: `${activeScans.length} Live`, variant: 'success' }
              : { text: 'Standby', variant: 'default' }
          }
        />
        <StatCard
          title="Vulnerabilities Found"
          value={severityStats.total}
          subtitle={`${severityStats.critical} critical • ${severityStats.high} high • ${severityStats.medium} med`}
          icon={Bug}
          accentColor={severityStats.critical > 0 ? 'rose' : severityStats.high > 0 ? 'amber' : 'cyan'}
          badge={
            severityStats.critical > 0
              ? { text: 'Critical Action', variant: 'danger' }
              : severityStats.high > 0
              ? { text: 'High Risk', variant: 'warning' }
              : undefined
          }
        />
        <StatCard
          title="Monitored Assets"
        <StatCard
          title="Monitored Assets"
          value={assetDisplayCount}
          subtitle="Discovered & monitored assets"
          icon={Globe}
          accentColor="purple"
          badge={{ text: `${scans.length} Scans`, variant: 'default' }}
        />
          icon={Globe}
          accentColor="purple"
          badge={{ text: `${scans.length} Scans`, variant: 'default' }}
        />
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
                className="text-xs text-sentinel-cyan hover:text-cyan-300 flex items-center gap-1 font-medium transition-colors"
              >
                <span>View All Findings</span>
                <ArrowRight size={13} />
              </Link>
            }
          >
            <SeverityChart stats={severityStats} />
          </Card>
        </div>

        {/* Real AI Engine & Operations Status (1 Col) */}
        <div className="space-y-4">
          <Card
            header="AI Engine & Operations"
            subtitle="Autonomous assessment runtime status"
          >
            <div className="space-y-3 text-xs">
              {/* Active Engine Card */}
              {activeScan ? (
                <div className="p-3.5 rounded-xl border border-cyan-800/60 bg-cyan-950/40 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-1.5 text-cyan-300 font-semibold font-mono text-[11px]">
                      <Cpu size={14} className="animate-pulse" />
                      AGENT EXECUTING
                    </span>
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-cyan-900/80 border border-cyan-700 text-cyan-200">
                      Step {activeScan.currentStep}/{activeScan.totalSteps}
                    </span>
                  </div>
                  <div className="space-y-0.5">
                    <span className="text-sentinel-text font-mono font-medium block truncate">
                      {activeScan.target}
                    </span>
                    <p className="text-[11px] text-sentinel-muted truncate">
                      {SCAN_PROFILES[activeScan.profile]?.name || activeScan.profile} assessment
                    </p>
                  </div>
                  <button
                    onClick={() => navigate(`/agent/${activeScan.id}`)}
                    className="w-full mt-1 py-1.5 px-3 rounded-lg bg-sentinel-cyan text-sentinel-bg font-semibold text-[11px] flex items-center justify-center gap-1.5 hover:bg-sentinel-cyan-hover transition-colors font-mono"
                  >
                    <span>View Live Telemetry</span>
                    <ArrowRight size={12} />
                  </button>
                </div>
              ) : (
                <div className="p-3.5 rounded-xl border border-sentinel-border bg-sentinel-elevated/40 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="flex items-center gap-1.5 text-sentinel-text font-semibold font-mono text-[11px]">
                      <CheckCircle2 size={14} className="text-emerald-400" />
                      ENGINE IDLE
                    </span>
                    <span className="text-[10px] text-sentinel-dim font-mono">Ready</span>
                  </div>
                  <p className="text-sentinel-muted text-[11px] leading-relaxed">
                    All workers standby. Launch an ethical assessment against an authorized target host.
                  </p>
                  <button
                    onClick={() => navigate('/new-scan')}
                    className="w-full mt-1 py-1.5 px-3 rounded-lg bg-white/5 hover:bg-white/10 border border-sentinel-border text-sentinel-text font-medium text-[11px] flex items-center justify-center gap-1.5 transition-colors font-mono"
                  >
                    <span>Launch New Pentest</span>
                    <ArrowRight size={12} />
                  </button>
                </div>
              )}

              {/* Assessment Protocol Summary */}
              <div className="p-3 rounded-xl border border-sentinel-border/70 bg-sentinel-elevated/20 space-y-2">
                <div className="text-[11px] font-mono font-semibold text-sentinel-dim uppercase tracking-wider">
                  Assessment Lifecycle
                </div>
                <div className="space-y-1.5 text-[11px] text-sentinel-muted">
                  <div className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                    <span>Reconnaissance & Subdomain Mapping</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />
                    <span>Dynamic Vulnerability Scanning</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                    <span>Evidence Extraction & Remediation Code</span>
                  </div>
                </div>
              </div>
            </div>
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
            className="text-xs text-sentinel-cyan hover:text-cyan-300 flex items-center gap-1 font-medium transition-colors"
          >
            <span>Complete Scan Archive</span>
            <ArrowRight size={13} />
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
            <table className="w-full text-left text-xs text-sentinel-muted">
              <thead className="bg-sentinel-elevated/60 text-sentinel-dim uppercase tracking-wider font-mono text-[10px] border-b border-sentinel-border">
                <tr>
                  <th scope="col" className="px-5 py-3 font-semibold">Target Asset</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Profile</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Status</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Started</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Findings</th>
                  <th scope="col" className="px-5 py-3 text-right font-semibold">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-border/50">
                {recentScans.map((scan) => {
                  const profile = SCAN_PROFILES[scan.profile] || { name: scan.profile };
                  return (
                    <tr
                      key={scan.id}
                      onClick={() => navigate(`/agent/${scan.id}`)}
                      className="hover:bg-sentinel-elevated/50 cursor-pointer transition-colors group"
                    >
                      <td className="px-5 py-3.5">
                        <div className="flex items-center gap-2">
                          <code className="text-sentinel-text font-mono font-medium group-hover:text-sentinel-cyan transition-colors">
                            {scan.target}
                          </code>
                          <span className="text-[10px] text-sentinel-dim font-mono">({scan.id.slice(0, 8)})</span>
                        </div>
                      </td>
                      <td className="px-4 py-3.5 font-medium text-sentinel-text">
                        {profile.name}
                      </td>
                      <td className="px-4 py-3.5">
                        <StatusBadge status={scan.status} size="sm" />
                      </td>
                      <td className="px-4 py-3.5 text-sentinel-dim font-mono tabular-nums whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <Clock size={12} className="text-sentinel-dim shrink-0" />
                          <span>
                            {new Date(scan.startedAt).toLocaleDateString()} {new Date(scan.startedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3.5">
                        <div className="flex items-center gap-1.5 font-mono">
                          {scan.findingsCount.total === 0 ? (
                            <span className="text-sentinel-dim">0</span>
                          ) : (
                            <>
                              {scan.findingsCount.critical > 0 && (
                                <span className="px-1.5 py-0.2 rounded bg-rose-950/70 border border-rose-800 text-rose-300 text-[11px] font-bold">
                                  {scan.findingsCount.critical}C
                                </span>
                              )}
                              {scan.findingsCount.high > 0 && (
                                <span className="px-1.5 py-0.2 rounded bg-orange-950/70 border border-orange-800 text-orange-300 text-[11px] font-bold">
                                  {scan.findingsCount.high}H
                                </span>
                              )}
                              {scan.findingsCount.medium > 0 && (
                                <span className="px-1.5 py-0.2 rounded bg-amber-950/70 border border-amber-800 text-amber-300 text-[11px]">
                                  {scan.findingsCount.medium}M
                                </span>
                              )}
                              {scan.findingsCount.low > 0 && (
                                <span className="px-1.5 py-0.2 rounded bg-sky-950/70 border border-sky-800 text-sky-300 text-[11px]">
                                  {scan.findingsCount.low}L
                                </span>
                              )}
                              {scan.findingsCount.info > 0 && (
                                <span className="px-1.5 py-0.2 rounded bg-indigo-950/70 border border-indigo-800 text-indigo-300 text-[11px]">
                                  {scan.findingsCount.info}I
                                </span>
                              )}
                            </>
                          )}
                        </div>
                      </td>
                      <td className="px-5 py-3.5 text-right">
                        <span className="inline-flex items-center gap-1 text-xs text-sentinel-cyan group-hover:underline font-mono">
                          <span>Telemetry</span>
                          <ArrowRight size={12} />
                        </span>
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
