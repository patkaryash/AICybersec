import React, { useState, useMemo, useCallback, useEffect } from 'react';
import { motion } from 'framer-motion';
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
import { containerVariants, itemVariants } from '../lib/motionVariants';

export const FindingsPage: React.FC = () => {
  const { findings, updateFindingStatus } = useScans();

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [selectedTarget, setSelectedTarget] = useState<string>('all');
  const [activeFinding, setActiveFinding] = useState<Finding | null>(null);

  // Calculate severity counts
  const severityCounts = useMemo(() => {
    return {
      total: findings.length,
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
      info: findings.filter(f => f.severity === 'info').length,
    };
  }, [findings]);

  // Reset all filters
  const resetFilters = useCallback(() => {
    setSearchQuery('');
    setSelectedSeverity('all');
    setSelectedStatus('all');
    setSelectedTarget('all');
  }, []);

  // Handle finding selection
  const handleFindingClick = useCallback((finding: Finding) => {
    setActiveFinding(finding);
  }, []);

  // Close detail modal
  const closeDetailModal = useCallback(() => {
    setActiveFinding(null);
  }, []);

  // Handle ESC key to close modal
  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && activeFinding) {
        closeDetailModal();
      }
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [activeFinding, closeDetailModal]);

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
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="space-y-6"
    >
      {/* Simulation / Demo Notification */}
      <motion.div variants={itemVariants}>
        <DemoBanner variant="compact" />
      </motion.div>

      {/* Header with Vulnerability Overview */}
      <motion.div variants={itemVariants}>
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
          <div className="flex-1">
            <h2 className="text-xl sm:text-2xl font-bold text-[#0B1220] tracking-tight">
              Security Vulnerabilities
            </h2>
            <p className="text-xs sm:text-sm text-[#475569] mt-1">
              Confirmed security findings requiring attention
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono px-3 py-1.5 rounded-lg border border-slate-200/80 bg-white/90 text-[#0B1220] shadow-sm backdrop-blur-md">
              {filteredFindings.length} of {findings.length} Findings
            </span>
          </div>
        </div>

        {/* Severity Overview Panel */}
        <div className="mt-4 bg-white/90 backdrop-blur-md border border-slate-200/80 rounded-xl p-4 shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-6">
              <div className="text-center">
                <div className="text-2xl font-bold font-mono text-[#0B1220]">{severityCounts.total}</div>
                <div className="text-[10px] text-[#64748B] uppercase tracking-wider">Total</div>
              </div>
              <div className="h-10 w-px bg-[#D8E1EB]" />
              <div className="flex gap-2 text-xs overflow-x-auto pb-1 sm:pb-0">
                <button
                  onClick={() => setSelectedSeverity(selectedSeverity === 'critical' ? 'all' : 'critical')}
                  className={`text-center px-3 py-2 rounded transition-colors shrink-0 ${
                    selectedSeverity === 'critical' ? 'bg-rose-100 border border-rose-300' : 'hover:bg-slate-100'
                  }`}
                  title="Filter by Critical"
                  aria-label={`Filter by Critical severity, ${severityCounts.critical} findings`}
                >
                  <div className="font-mono font-bold text-[#DC2626]">{severityCounts.critical}</div>
                  <div className="text-[10px] text-[#64748B]">Critical</div>
                </button>
                <button
                  onClick={() => setSelectedSeverity(selectedSeverity === 'high' ? 'all' : 'high')}
                  className={`text-center px-3 py-2 rounded transition-colors shrink-0 ${
                    selectedSeverity === 'high' ? 'bg-amber-100 border border-amber-300' : 'hover:bg-slate-100'
                  }`}
                  title="Filter by High"
                  aria-label={`Filter by High severity, ${severityCounts.high} findings`}
                >
                  <div className="font-mono font-bold text-[#D97706]">{severityCounts.high}</div>
                  <div className="text-[10px] text-[#64748B]">High</div>
                </button>
                <button
                  onClick={() => setSelectedSeverity(selectedSeverity === 'medium' ? 'all' : 'medium')}
                  className={`text-center px-3 py-2 rounded transition-colors shrink-0 ${
                    selectedSeverity === 'medium' ? 'bg-yellow-100 border border-yellow-300' : 'hover:bg-slate-100'
                  }`}
                  title="Filter by Medium"
                  aria-label={`Filter by Medium severity, ${severityCounts.medium} findings`}
                >
                  <div className="font-mono font-bold text-[#CA8A04]">{severityCounts.medium}</div>
                  <div className="text-[10px] text-[#64748B]">Medium</div>
                </button>
                <button
                  onClick={() => setSelectedSeverity(selectedSeverity === 'low' ? 'all' : 'low')}
                  className={`text-center px-3 py-2 rounded transition-colors shrink-0 ${
                    selectedSeverity === 'low' ? 'bg-emerald-100 border border-emerald-300' : 'hover:bg-slate-100'
                  }`}
                  title="Filter by Low"
                  aria-label={`Filter by Low severity, ${severityCounts.low} findings`}
                >
                  <div className="font-mono font-bold text-[#059669]">{severityCounts.low}</div>
                  <div className="text-[10px] text-[#64748B]">Low</div>
                </button>
                <button
                  onClick={() => setSelectedSeverity(selectedSeverity === 'info' ? 'all' : 'info')}
                  className={`text-center px-3 py-2 rounded transition-colors shrink-0 ${
                    selectedSeverity === 'info' ? 'bg-slate-100 border border-slate-300' : 'hover:bg-slate-100'
                  }`}
                  title="Filter by Info"
                  aria-label={`Filter by Info severity, ${severityCounts.info} findings`}
                >
                  <div className="font-mono font-bold text-[#64748B]">{severityCounts.info}</div>
                  <div className="text-[10px] text-[#64748B]">Info</div>
                </button>
              </div>
            </div>
            {selectedSeverity !== 'all' && (
              <button
                onClick={() => setSelectedSeverity('all')}
                className="text-xs text-[#64748B] hover:text-[#0B1220] flex items-center gap-1 transition-colors"
              >
                <RotateCcw size={12} />
                <span>Clear filter</span>
              </button>
            )}
          </div>
        </div>
      </motion.div>

      {/* Filters and Search Bar */}
      <motion.div variants={itemVariants}>
        <Card noPadding>
          <div className="p-4 border-b border-slate-200/70 bg-white/90 backdrop-blur-md flex flex-col md:flex-row items-center justify-between gap-3">
            {/* Search Input */}
            <div className="relative w-full md:w-80">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search findings, endpoints, CVEs..."
                className="w-full pl-9 pr-4 py-2 rounded-lg bg-[#F4F7FB] border border-[#D8E1EB] text-xs text-[#0B1220] placeholder:text-[#64748B] focus:outline-none focus:border-[#1D4ED8] focus:ring-2 focus:ring-[#1D4ED8]/25 transition-all"
              />
              <div className="absolute left-3 top-2.5 text-[#64748B]">
                <Search size={14} />
              </div>
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="absolute right-3 top-2.5 text-[#64748B] hover:text-[#0B1220] text-xs"
                >
                  ✕
                </button>
              )}
            </div>

            {/* Dropdown Filters */}
            <div className="flex items-center gap-2.5 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
              {/* Severity Filter */}
              <div className="flex items-center gap-1.5 shrink-0">
                <span className="text-[11px] text-[#64748B]">Severity:</span>
                <select
                  value={selectedSeverity}
                  onChange={(e) => setSelectedSeverity(e.target.value)}
                  className="px-2.5 py-1.5 rounded-lg bg-[#F4F7FB] border border-[#D8E1EB] text-xs text-[#0B1220] focus:outline-none focus:border-[#1D4ED8] focus:ring-2 focus:ring-[#1D4ED8]/25 transition-all"
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
                  <span className="text-[11px] text-[#64748B]">Target:</span>
                  <select
                    value={selectedTarget}
                    onChange={(e) => setSelectedTarget(e.target.value)}
                    className="px-2.5 py-1.5 rounded-lg bg-[#F4F7FB] border border-[#D8E1EB] text-xs text-[#0B1220] focus:outline-none focus:border-[#1D4ED8] focus:ring-2 focus:ring-[#1D4ED8]/25 max-w-[160px] truncate transition-all"
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
                <span className="text-[11px] text-[#64748B]">Status:</span>
                <select
                  value={selectedStatus}
                  onChange={(e) => setSelectedStatus(e.target.value)}
                  className="px-2.5 py-1.5 rounded-lg bg-[#F4F7FB] border border-[#D8E1EB] text-xs text-[#0B1220] focus:outline-none focus:border-[#1D4ED8] focus:ring-2 focus:ring-[#1D4ED8]/25 transition-all"
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
                onClick: resetFilters,
              }}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-[#475569]">
                <thead className="bg-slate-50/80 text-[#475569] uppercase tracking-wider font-mono text-[10px] border-b border-slate-200/80">
                  <tr>
                    <th scope="col" className="px-5 py-3 font-semibold">Severity</th>
                    <th scope="col" className="px-5 py-3 font-semibold">Vulnerability Title</th>
                    <th scope="col" className="px-4 py-3 font-semibold">Target & Asset</th>
                    <th scope="col" className="px-4 py-3 font-semibold">Detection Source</th>
                    <th scope="col" className="px-4 py-3 font-semibold">Status</th>
                    <th scope="col" className="px-5 py-3 text-right font-semibold">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200/70 bg-white">
                  {filteredFindings.map((finding) => (
                    <tr
                      key={finding.id}
                      onClick={() => handleFindingClick(finding)}
                      className="hover:bg-slate-50/80 cursor-pointer transition-colors group"
                    >
                      <td className="px-5 py-3.5 whitespace-nowrap">
                        <SeverityBadge severity={finding.severity} size="sm" />
                      </td>
                      <td className="px-5 py-3.5">
                        <div className="space-y-0.5">
                          <span className="font-semibold text-[#0B1220] group-hover:text-[#1D4ED8] transition-colors block">
                            {finding.title}
                          </span>
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] text-[#64748B] font-mono">{finding.id.slice(0, 8)}</span>
                            <span
                              className={`text-[10px] font-mono ${
                                finding.isSynthetic ? 'text-[#D97706]' : 'text-[#059669]'
                              }`}
                            >
                              {finding.isSynthetic ? 'Synthetic' : 'Verified Evidence'}
                            </span>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3.5">
                        <div className="space-y-0.5 max-w-xs">
                          <span className="font-mono text-[#0B1220] font-medium block truncate">
                            {finding.target}
                          </span>
                          <code className="text-[11px] text-[#64748B] font-mono block truncate">
                            {finding.asset}
                          </code>
                        </div>
                      </td>
                      <td className="px-4 py-3.5 whitespace-nowrap">
                        <span className="font-mono text-[11px] px-2 py-0.5 rounded bg-slate-100 border border-slate-200 text-[#0B1220]">
                          {finding.tool}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 whitespace-nowrap">
                        <span
                          className={`text-[11px] font-mono px-2 py-0.5 rounded border capitalize ${
                            finding.status === 'open'
                              ? 'bg-rose-50 border-rose-200 text-[#DC2626] font-bold'
                              : finding.status === 'resolved'
                              ? 'bg-emerald-50 border-emerald-200 text-[#059669] font-bold'
                              : finding.status === 'accepted_risk'
                              ? 'bg-amber-50 border-amber-200 text-[#D97706] font-bold'
                              : 'bg-slate-100 border-slate-200 text-[#64748B]'
                          }`}
                        >
                          {finding.status.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="px-5 py-3.5 text-right whitespace-nowrap">
                        <span className="inline-flex items-center gap-1 text-xs text-[#1D4ED8] group-hover:underline font-mono">
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
      </motion.div>

      {/* Vulnerability Finding Detail Drawer */}
      <FindingDetailModal
        finding={activeFinding}
        isOpen={Boolean(activeFinding)}
        onClose={closeDetailModal}
        onStatusChange={(id, newStatus) => {
          updateFindingStatus(id, newStatus);
          if (activeFinding) {
            setActiveFinding({ ...activeFinding, status: newStatus });
          }
        }}
      />
    </motion.div>
  );
};
