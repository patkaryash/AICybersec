import React from 'react';
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
} from 'lucide-react';
import { useScans } from '../context/ScanContext';
import { StatCard } from '../components/common/StatCard';
import { Card } from '../components/common/Card';
import { SeverityChart } from '../components/common/SeverityChart';
import { StatusBadge } from '../components/common/StatusBadge';
import { EmptyState } from '../components/common/EmptyState';
import { DemoBanner } from '../components/common/DemoBanner';
import { SCAN_PROFILES } from '../types/scan';
import ThreatGlobe from '../components/common/ThreatGlobe';

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const { scans, severityStats, loading, error, refreshData } = useScans();

  const activeScans = scans.filter(
    (s) => s.status === 'running' || s.status === 'queued' || s.status === 'initializing'
  );
  const recentScans = scans.slice(0, 6);

  // Derive unique monitored targets
  const uniqueAssets = Array.from(new Set(scans.map((s) => s.target)));

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

      {/* Top Hero / Welcome Banner with Integrated Threat Globe */}
      <div className="relative overflow-hidden rounded-2xl border border-sentinel-border/80 bg-gradient-to-br from-sentinel-surface via-[#111A2C] to-[#0C1B26] p-6 sm:p-8 shadow-xl shadow-black/30 ring-1 ring-white/5">
        <div className="pointer-events-none absolute -top-24 -left-24 h-72 w-72 rounded-full bg-cyan-500/10 blur-[100px]" />
        <div className="pointer-events-none absolute -bottom-32 right-1/4 h-72 w-72 rounded-full bg-purple-600/10 blur-[100px]" />
        <div className="relative flex flex-col lg:flex-row gap-6 items-center">
          {/* Left Side: Text and Buttons */}
          <div className="flex-1 space-y-3 w-full">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-800/60 text-cyan-300 text-[11px] font-mono font-medium tracking-widest uppercase">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
              Autonomous AI Security Engine
            </div>
            <h2 className="text-2xl sm:text-[28px] font-bold tracking-tight text-sentinel-text text-balance">
              Continuous AI-Assisted Penetration Testing
            </h2>
            <p className="text-xs sm:text-sm text-sentinel-muted leading-relaxed max-w-xl">
              Execute targeted reconnaissance, identify high-impact vulnerabilities with an autonomous
              scan pipeline, and review verified findings with actionable remediation guidance.
            </p>

            <div className="pt-2 flex flex-wrap items-center gap-3">
              <button
                onClick={() => navigate('/new-scan')}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-sentinel-cyan text-sentinel-bg font-semibold text-xs tracking-wide hover:bg-sentinel-cyan-hover transition-all shadow-lg shadow-cyan-950/40 hover:shadow-cyan-900/40 hover:-translate-y-px"
              >
                <ShieldPlus size={16} />
                <span>Start New Pentest</span>
              </button>
              <button
                onClick={() => navigate('/findings')}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-white/5 border border-sentinel-border text-sentinel-text font-medium text-xs hover:bg-white/10 hover:border-sentinel-border-light transition-all"
              >
                <Bug size={15} className="text-sentinel-cyan" />
                <span>Review Findings ({severityStats.total})</span>
              </button>
            </div>
          </div>

          {/* Right Side: The Interactive 3D Threat Globe */}
          <div className="flex-1 w-full h-[280px] lg:h-[360px] flex items-center justify-center">
            <ThreatGlobe />
          </div>
        </div>
      </div>

      {/* 4 Summary Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Scans Executed"
          value={scans.length}
          subtitle="All automated sessions"
          icon={Activity}
          accentColor="cyan"
        />
        <StatCard
          title="Active Running Scans"
          value={activeScans.length}
          subtitle={activeScans.length > 0 ? 'Live telemetry transmitting' : 'No active workers'}
          icon={Radio}
          accentColor={activeScans.length > 0 ? 'emerald' : 'purple'}
          badge={activeScans.length > 0 ? { text: 'Active' } : undefined}
        />
        <StatCard
          title="Vulnerabilities Found"
          value={severityStats.total}
          subtitle={`${severityStats.critical} critical • ${severityStats.high} high`}
          icon={Bug}
          accentColor={severityStats.critical > 0 ? 'rose' : 'amber'}
        />
        <StatCard
          title="Monitored Assets"
          value={uniqueAssets.length}
          subtitle="Unique target hosts & APIs"
          icon={Globe}
          accentColor="purple"
        />
      </div>

      {/* Main Grid: Severity Breakdown + Quick Actions */}
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

        {/* Quick Operations & Guidance (1 Col) */}
        <div className="space-y-4">
          <Card
            header="Operational Guidance"
            subtitle="Recommended assessment protocols"
          >
            <div className="space-y-3 text-xs">
              <div className="p-3.5 rounded-xl border border-sentinel-border bg-sentinel-elevated/40 space-y-1.5 hover:border-sentinel-border-light transition-colors">
                <div className="flex items-center gap-2 text-sentinel-text font-semibold">
                  <span className="flex items-center justify-center w-5 h-5 rounded-md bg-cyan-950/80 border border-cyan-800/60 text-cyan-300 font-mono text-[10px]">1</span>
                  <span>Specify Scope & Authorization</span>
                </div>
                <p className="text-sentinel-muted leading-relaxed pl-7">
                  Provide valid FQDN or IPv4. The ethics gate guarantees authorized testing boundaries.
                </p>
              </div>

              <div className="p-3.5 rounded-xl border border-sentinel-border bg-sentinel-elevated/40 space-y-1.5 hover:border-sentinel-border-light transition-colors">
                <div className="flex items-center gap-2 text-sentinel-text font-semibold">
                  <span className="flex items-center justify-center w-5 h-5 rounded-md bg-cyan-950/80 border border-cyan-800/60 text-cyan-300 font-mono text-[10px]">2</span>
                  <span>Watch Live Agent Telemetry</span>
                </div>
                <p className="text-sentinel-muted leading-relaxed pl-7">
                  Monitor the autonomous AI decision loop as Nmap, httpx, and Nuclei are orchestrated.
                </p>
              </div>

              <div className="p-3.5 rounded-xl border border-sentinel-border bg-sentinel-elevated/40 space-y-1.5 hover:border-sentinel-border-light transition-colors">
                <div className="flex items-center gap-2 text-sentinel-text font-semibold">
                  <span className="flex items-center justify-center w-5 h-5 rounded-md bg-cyan-950/80 border border-cyan-800/60 text-cyan-300 font-mono text-[10px]">3</span>
                  <span>Triage & Remediate</span>
                </div>
                <p className="text-sentinel-muted leading-relaxed pl-7">
                  Inspect raw technical evidence, verify exploitability, and copy actionable code fixes.
                </p>
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
                        {new Date(scan.startedAt).toLocaleDateString()} {new Date(scan.startedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
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
