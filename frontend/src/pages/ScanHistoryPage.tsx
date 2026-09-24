import React, { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  History,
  Search,
  Filter,
  Radio,
  Bug,
  ShieldPlus,
  ArrowRight,
  ExternalLink,
  RotateCcw,
  Clock,
  Terminal,
} from 'lucide-react';
import { useScans } from '../context/ScanContext';
import { StatusBadge } from '../components/common/StatusBadge';
import { Card } from '../components/common/Card';
import { EmptyState } from '../components/common/EmptyState';
import { DemoBanner } from '../components/common/DemoBanner';
import { SCAN_PROFILES, ScanStatus } from '../types/scan';

export const ScanHistoryPage: React.FC = () => {
  const navigate = useNavigate();
  const { scans } = useScans();

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [selectedProfile, setSelectedProfile] = useState<string>('all');

  const filteredScans = useMemo(() => {
    return scans.filter((scan) => {
      const matchesSearch =
        searchQuery === '' ||
        scan.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
        scan.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        scan.goal.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesStatus =
        selectedStatus === 'all' || scan.status === selectedStatus;

      const matchesProfile =
        selectedProfile === 'all' || scan.profile === selectedProfile;

      return matchesSearch && matchesStatus && matchesProfile;
    });
  }, [scans, searchQuery, selectedStatus, selectedProfile]);

  const totalCompleted = scans.filter((s) => s.status === 'finished').length;
  const totalRunning = scans.filter((s) => s.status === 'running').length;
  const totalFindingsFound = scans.reduce((acc, s) => acc + s.findingsCount.total, 0);

  return (
    <div className="space-y-6">
      {/* Simulation / Demo Notification */}
      <DemoBanner variant="compact" />

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold text-sentinel-text tracking-tight">
            Penetration Test History & Audit Trail
          </h2>
          <p className="text-xs sm:text-sm text-sentinel-muted mt-1">
            Historical archive of autonomous scans, target scopes, and detected security vulnerabilities.
          </p>
        </div>

        <button
          onClick={() => navigate('/new-scan')}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-sentinel-cyan text-sentinel-bg font-semibold text-xs tracking-wide hover:bg-sentinel-cyan-hover transition-colors shadow-sm self-start sm:self-auto"
        >
          <ShieldPlus size={14} />
          <span>New Pentest</span>
        </button>
      </div>

      {/* Metric Highlights */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-4 rounded-xl border border-sentinel-border bg-sentinel-surface">
          <span className="text-[11px] font-mono uppercase text-sentinel-dim block">Total Sessions</span>
          <span className="text-2xl font-bold font-mono text-sentinel-text mt-1 block">{scans.length}</span>
        </div>
        <div className="p-4 rounded-xl border border-sentinel-border bg-sentinel-surface">
          <span className="text-[11px] font-mono uppercase text-sentinel-dim block">Completed Audits</span>
          <span className="text-2xl font-bold font-mono text-emerald-400 mt-1 block">{totalCompleted}</span>
        </div>
        <div className="p-4 rounded-xl border border-sentinel-border bg-sentinel-surface">
          <span className="text-[11px] font-mono uppercase text-sentinel-dim block">Active Workers</span>
          <span className="text-2xl font-bold font-mono text-cyan-400 mt-1 block">{totalRunning}</span>
        </div>
        <div className="p-4 rounded-xl border border-sentinel-border bg-sentinel-surface">
          <span className="text-[11px] font-mono uppercase text-sentinel-dim block">Total Findings</span>
          <span className="text-2xl font-bold font-mono text-rose-400 mt-1 block">{totalFindingsFound}</span>
        </div>
      </div>

      {/* Main Table Card */}
      <Card noPadding>
        {/* Filters Header */}
        <div className="p-4 border-b border-sentinel-border flex flex-col md:flex-row items-center justify-between gap-3">
          {/* Search */}
          <div className="relative w-full md:w-80">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by target, scan ID, or goal..."
              className="w-full pl-9 pr-4 py-2 rounded-lg bg-sentinel-bg border border-sentinel-border text-xs text-sentinel-text placeholder:text-sentinel-dim focus:outline-none focus:border-sentinel-cyan transition-colors"
            />
            <div className="absolute left-3 top-2.5 text-sentinel-dim">
              <Search size={14} />
            </div>
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-2.5 text-sentinel-dim hover:text-sentinel-text text-xs"
              >
                ✕
              </button>
            )}
          </div>

          {/* Filters */}
          <div className="flex items-center gap-2.5 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
            <div className="flex items-center gap-1.5 shrink-0">
              <span className="text-[11px] text-sentinel-dim font-mono">Status:</span>
              <select
                value={selectedStatus}
                onChange={(e) => setSelectedStatus(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-sentinel-bg border border-sentinel-border text-xs text-sentinel-text focus:outline-none focus:border-sentinel-cyan"
              >
                <option value="all">All Statuses</option>
                <option value="running">Running</option>
                <option value="finished">Completed</option>
                <option value="cancelled">Stopped</option>
                <option value="failed">Failed</option>
              </select>
            </div>

            <div className="flex items-center gap-1.5 shrink-0">
              <span className="text-[11px] text-sentinel-dim font-mono">Profile:</span>
              <select
                value={selectedProfile}
                onChange={(e) => setSelectedProfile(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-sentinel-bg border border-sentinel-border text-xs text-sentinel-text focus:outline-none focus:border-sentinel-cyan"
              >
                <option value="all">All Profiles</option>
                <option value="recon">Reconnaissance</option>
                <option value="web_assessment">Web Assessment</option>
                <option value="full_assessment">Full Assessment</option>
              </select>
            </div>
          </div>
        </div>

        {/* Scans List Table */}
        {filteredScans.length === 0 ? (
          <EmptyState
            icon={History}
            title="No Scans Matched"
            description="No penetration test sessions found matching your search term or active filters."
            action={{
              label: 'Reset Filters',
              icon: RotateCcw,
              onClick: () => {
                setSearchQuery('');
                setSelectedStatus('all');
                setSelectedProfile('all');
              },
            }}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-sentinel-muted">
              <thead className="bg-sentinel-elevated/60 text-sentinel-dim uppercase tracking-wider font-mono text-[10px] border-b border-sentinel-border">
                <tr>
                  <th scope="col" className="px-5 py-3 font-semibold">Target & Scan ID</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Profile</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Status</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Timeline & Duration</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Findings Severity</th>
                  <th scope="col" className="px-5 py-3 text-right font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-border/50">
                {filteredScans.map((scan) => {
                  const profile = SCAN_PROFILES[scan.profile] || { name: scan.profile };

                  const start = new Date(scan.startedAt).getTime();
                  const end = scan.completedAt ? new Date(scan.completedAt).getTime() : Date.now();
                  const durationSec = Math.max(0, Math.floor((end - start) / 1000));
                  const durationMins = Math.floor(durationSec / 60);
                  const durationSecs = durationSec % 60;
                  const durationFormatted = `${durationMins}m ${durationSecs}s`;

                  return (
                    <tr
                      key={scan.id}
                      onClick={() => navigate(`/agent/${scan.id}`)}
                      className="hover:bg-sentinel-elevated/50 cursor-pointer transition-colors group"
                    >
                      <td className="px-5 py-3.5">
                        <div className="space-y-0.5">
                          <code className="text-sentinel-text font-mono font-medium group-hover:text-sentinel-cyan transition-colors block">
                            {scan.target}
                          </code>
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] text-sentinel-dim font-mono">{scan.id}</span>
                            <span className="text-[10px] text-cyan-400/80 font-mono">Simulated</span>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3.5 font-medium text-sentinel-text">
                        <span className="px-2 py-0.5 rounded bg-sentinel-bg border border-sentinel-border font-mono text-[11px]">
                          {profile.name}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 whitespace-nowrap">
                        <StatusBadge status={scan.status} size="sm" />
                      </td>
                      <td className="px-4 py-3.5 whitespace-nowrap text-sentinel-dim font-mono">
                        <div className="space-y-0.5">
                          <span className="text-sentinel-text block">
                            {new Date(scan.startedAt).toLocaleDateString()} {new Date(scan.startedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </span>
                          <span className="text-[10px] text-sentinel-dim block">
                            Duration: {durationFormatted}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3.5 whitespace-nowrap">
                        <div className="flex items-center gap-1.5 font-mono">
                          {scan.findingsCount.total === 0 ? (
                            <span className="text-sentinel-dim text-xs">0 findings</span>
                          ) : (
                            <>
                              {scan.findingsCount.critical > 0 && (
                                <span className="px-1.5 py-0.2 rounded bg-rose-950/70 border border-rose-800 text-rose-300 text-[11px] font-bold">
                                  {scan.findingsCount.critical} Crit
                                </span>
                              )}
                              {scan.findingsCount.high > 0 && (
                                <span className="px-1.5 py-0.2 rounded bg-orange-950/70 border border-orange-800 text-orange-300 text-[11px] font-bold">
                                  {scan.findingsCount.high} High
                                </span>
                              )}
                              {scan.findingsCount.medium > 0 && (
                                <span className="px-1.5 py-0.2 rounded bg-amber-950/70 border border-amber-800 text-amber-300 text-[11px]">
                                  {scan.findingsCount.medium} Med
                                </span>
                              )}
                              {scan.findingsCount.low > 0 && (
                                <span className="px-1.5 py-0.2 rounded bg-sky-950/70 border border-sky-800 text-sky-300 text-[11px]">
                                  {scan.findingsCount.low} Low
                                </span>
                              )}
                              {scan.findingsCount.info > 0 && (
                                <span className="px-1.5 py-0.2 rounded bg-indigo-950/70 border border-indigo-800 text-indigo-300 text-[11px]">
                                  {scan.findingsCount.info} Info
                                </span>
                              )}
                            </>
                          )}
                        </div>
                      </td>
                      <td className="px-5 py-3.5 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-3 font-mono text-xs">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              navigate(`/agent/${scan.id}`);
                            }}
                            className="text-sentinel-cyan hover:underline flex items-center gap-1"
                          >
                            <span>Telemetry</span>
                            <ArrowRight size={12} />
                          </button>
                        </div>
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
