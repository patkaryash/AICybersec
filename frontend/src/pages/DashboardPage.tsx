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
  const { scans, findings, severityStats, loading, error, refreshData } = useScans();

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
      <div className="relative overflow-hidden rounded-xl border border-sentinel-border bg-gradient-to-r from-sentinel-surface via-[#131C2E] to-sentinel-surface p-6 shadow-md">
        <div className="flex flex-col lg:flex-row gap-6 items-center">
          {/* Left Side: Text and Buttons */}
          <div className="flex-1 space-y-2 w-full">
            <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-cyan-950/60 border border-cyan-800/60 text-cyan-300 text-xs font-mono font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
              Autonomous AI Security Engine
            </div>
            <h2 className="text-xl sm:text-2xl font-bold tracking-tight text-sentinel-text">
              Continuous AI-Assisted Penetration Testing
            </h2>
            <p className="text-xs sm:text-sm text-sentinel-muted leading-relaxed">
              Execute targeted reconnaissance, identify high-impact vulnerabilities with automated LLM reasoning,
              and review verified findings with actionable remediation code.
            </p>

            <div className="mt-5 flex flex-wrap items-center gap-3">
              <button
                onClick={() => navigate('/new-scan')}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-sentinel-cyan text-sentinel-bg font-semibold text-xs tracking-wide hover:bg-sentinel-cyan-hover transition-colors shadow-sm"
              >
                <ShieldPlus size={16} />
                <span>Start New Pentest</span>
              </button>
              <button
                onClick={() => navigate('/findings')}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-sentinel-elevated border border-sentinel-border text-sentinel-text font-medium text-xs hover:bg-sentinel-subtle transition-colors"
              >
                <Bug size={15} className="text-sentinel-cyan" />
                <span>Review Findings ({findings.length})</span>
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
                className="text-xs text-sentinel-cyan hover:underline flex items-center gap-1 font-mono"
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
              <div className="p-3 rounded-lg border border-sentinel-border bg-sentinel-elevated/40 space-y-1">
                <div className="flex items-center justify-between text-sentinel-text font-semibold">
                  <span>1. Specify Scope & Authorization</span>
                </div>
                <p className="text-sentinel-muted leading-relaxed">
                  Provide valid FQDN or IPv4. The ethics gate guarantees authorized testing boundaries.
                </p>
              </div>

              <div className="p-3 rounded-lg border border-sentinel-border bg-sentinel-elevated/40 space-y-1">
                <div className="flex items-center justify-between text-sentinel-text font-semibold">
                  <span>2. Watch Live Agent Telemetry</span>
                </div>
                <p className="text-sentinel-muted leading-relaxed">
                  Monitor the autonomous AI decision loop as Nmap, httpx, and Nuclei are orchestrated.
                </p>
              </div>

              <div className="p-3 rounded-lg border border-sentinel-border bg-sentinel-elevated/40 space-y-1">
                <div className="flex items-center justify-between text-sentinel-text font-semibold">
                  <span>3. Triage & Remediate</span>
                </div>
                <p className="text-sentinel-muted leading-relaxed">
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
            className="text-xs text-sentinel-cyan hover:underline flex items-center gap-1 font-mono"
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
                      <td className="px-4 py-3.5 text-sentinel-dim font-mono">
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
