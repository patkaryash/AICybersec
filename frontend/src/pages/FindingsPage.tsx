import React, { useState, useMemo } from 'react';
import {
  Search,
  Bug,
  ChevronRight,
  RotateCcw,
} from 'lucide-react';
import { useScans } from '../context/ScanContext';
import { Finding } from '../types/finding';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { FindingDetailModal } from '../components/common/FindingDetailModal';
import { Card } from '../components/common/Card';
import { EmptyState } from '../components/common/EmptyState';
import { DemoBanner } from '../components/common/DemoBanner';

export const FindingsPage: React.FC = () => {
  const { findings, updateFindingStatus } = useScans();

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [selectedTarget, setSelectedTarget] = useState<string>('all');
  const [activeFinding, setActiveFinding] = useState<Finding | null>(null);

  // Extract unique targets from findings
  const uniqueTargets = useMemo(() => {
    return Array.from(new Set(findings.map((f) => f.target)));
  }, [findings]);

  // Filtered and searched findings
  const filteredFindings = useMemo(() => {
    return findings.filter((item) => {
      // Search filter
      const matchesSearch =
        searchQuery === '' ||
        item.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.tool.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.description.toLowerCase().includes(searchQuery.toLowerCase());

      // Severity filter
      const matchesSeverity =
        selectedSeverity === 'all' || item.severity === selectedSeverity;

      // Status filter
      const matchesStatus =
        selectedStatus === 'all' || item.status === selectedStatus;

      // Target filter
      const matchesTarget =
        selectedTarget === 'all' || item.target === selectedTarget;

      return matchesSearch && matchesSeverity && matchesStatus && matchesTarget;
    });
  }, [findings, searchQuery, selectedSeverity, selectedStatus, selectedTarget]);

  return (
    <div className="space-y-6">
      {/* Simulation / Demo Notification */}
      <DemoBanner variant="compact" />

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold text-sentinel-text tracking-tight">
            Security Vulnerability Findings
          </h2>
          <p className="text-xs sm:text-sm text-sentinel-muted mt-1">
            Normalized ledger of confirmed security vulnerabilities, attack vectors, and remediation patches.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono px-3 py-1.5 rounded-lg border border-sentinel-border bg-sentinel-surface text-sentinel-text">
            {filteredFindings.length} of {findings.length} Findings
          </span>
        </div>
      </div>

      {/* Filters and Search Bar */}
      <Card noPadding>
        <div className="p-4 border-b border-sentinel-border flex flex-col md:flex-row items-center justify-between gap-3">
          {/* Search Input */}
          <div className="relative w-full md:w-80">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search findings, endpoints, CVEs..."
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

          {/* Dropdown Filters */}
          <div className="flex items-center gap-2.5 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
            {/* Severity Filter */}
            <div className="flex items-center gap-1.5 shrink-0">
              <span className="text-[11px] text-sentinel-dim font-mono">Severity:</span>
              <select
                value={selectedSeverity}
                onChange={(e) => setSelectedSeverity(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-sentinel-bg border border-sentinel-border text-xs text-sentinel-text focus:outline-none focus:border-sentinel-cyan"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>

            {/* Target Filter */}
            {uniqueTargets.length > 1 && (
              <div className="flex items-center gap-1.5 shrink-0">
                <span className="text-[11px] text-sentinel-dim font-mono">Target:</span>
                <select
                  value={selectedTarget}
                  onChange={(e) => setSelectedTarget(e.target.value)}
                  className="px-2.5 py-1.5 rounded-lg bg-sentinel-bg border border-sentinel-border text-xs text-sentinel-text focus:outline-none focus:border-sentinel-cyan max-w-[160px] truncate"
                >
                  <option value="all">All Targets</option>
                  {uniqueTargets.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </div>
            )}

            {/* Status Filter */}
            <div className="flex items-center gap-1.5 shrink-0">
              <span className="text-[11px] text-sentinel-dim font-mono">Status:</span>
              <select
                value={selectedStatus}
                onChange={(e) => setSelectedStatus(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-sentinel-bg border border-sentinel-border text-xs text-sentinel-text focus:outline-none focus:border-sentinel-cyan"
              >
                <option value="all">All Statuses</option>
                <option value="open">Open</option>
                <option value="accepted_risk">Accepted Risk</option>
                <option value="resolved">Resolved</option>
                <option value="false_positive">False Positive</option>
              </select>
            </div>
          </div>
        </div>

        {/* Findings Table */}
        {filteredFindings.length === 0 ? (
          <EmptyState
            icon={Bug}
            title="No Matching Findings"
            description="No vulnerability records match your search criteria or active filters."
            action={{
              label: 'Reset Filters',
              icon: RotateCcw,
              onClick: () => {
                setSearchQuery('');
                setSelectedSeverity('all');
                setSelectedStatus('all');
                setSelectedTarget('all');
              },
            }}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-sentinel-muted">
              <thead className="bg-sentinel-elevated/60 text-sentinel-dim uppercase tracking-wider font-mono text-[10px] border-b border-sentinel-border">
                <tr>
                  <th scope="col" className="px-5 py-3 font-semibold">Severity</th>
                  <th scope="col" className="px-5 py-3 font-semibold">Vulnerability Title</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Target & Asset</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Detection Source</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Status</th>
                  <th scope="col" className="px-5 py-3 text-right font-semibold">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sentinel-border/50">
                {filteredFindings.map((finding) => (
                  <tr
                    key={finding.id}
                    onClick={() => setActiveFinding(finding)}
                    className="hover:bg-sentinel-elevated/50 cursor-pointer transition-colors group"
                  >
                    <td className="px-5 py-3.5 whitespace-nowrap">
                      <SeverityBadge severity={finding.severity} size="sm" />
                    </td>
                    <td className="px-5 py-3.5">
                      <div className="space-y-0.5">
                        <span className="font-semibold text-sentinel-text group-hover:text-sentinel-cyan transition-colors block">
                          {finding.title}
                        </span>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] text-sentinel-dim font-mono">{finding.id.slice(0, 8)}</span>
                          <span
                            className={`text-[10px] font-mono ${
                              finding.isSynthetic ? 'text-amber-400/80' : 'text-emerald-400/80'
                            }`}
                          >
                            {finding.isSynthetic ? 'Synthetic' : 'Verified Evidence'}
                          </span>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3.5">
                      <div className="space-y-0.5 max-w-xs">
                        <span className="font-mono text-sentinel-text font-medium block truncate">
                          {finding.target}
                        </span>
                        <code className="text-[11px] text-sentinel-dim font-mono block truncate">
                          {finding.asset}
                        </code>
                      </div>
                    </td>
                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-sentinel-bg border border-sentinel-border text-sentinel-text">
                        {finding.tool}
                      </span>
                    </td>
                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <span
                        className={`text-[11px] font-mono px-2 py-0.5 rounded border capitalize ${
                          finding.status === 'open'
                            ? 'bg-rose-950/40 border-rose-800 text-rose-300'
                            : finding.status === 'resolved'
                            ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                            : 'bg-sentinel-bg border-sentinel-border text-sentinel-muted'
                        }`}
                      >
                        {finding.status.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-right whitespace-nowrap">
                      <span className="inline-flex items-center gap-1 text-xs text-sentinel-cyan group-hover:underline font-mono">
                        <span>Details</span>
                        <ChevronRight size={14} />
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Vulnerability Finding Detail Drawer */}
      <FindingDetailModal
        finding={activeFinding}
        isOpen={Boolean(activeFinding)}
        onClose={() => setActiveFinding(null)}
        onStatusChange={(id, newStatus) => {
          updateFindingStatus(id, newStatus);
          if (activeFinding) {
            setActiveFinding({ ...activeFinding, status: newStatus });
          }
        }}
      />
    </div>
  );
};
