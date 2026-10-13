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
            <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              Security Vulnerabilities
            </h2>
            <p className="text-xs sm:text-sm text-zinc-400 mt-1">
              Confirmed security weaknesses and normalized telemetry requiring remediation
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono px-3 py-1.5 rounded-lg border border-zinc-700 bg-zinc-800 text-zinc-200 shadow-sm">
              {filteredFindings.length} of {findings.length} Findings
            </span>
          </div>
        </div>

        {/* Severity Overview Panel */}
        <div className="mt-4 bg-[#121214] border border-zinc-800 rounded-2xl p-4 shadow-xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="flex items-center gap-6">
              <div className="text-center">
                <div className="text-2xl font-bold font-mono text-white">{severityCounts.total}</div>
                <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-mono">Total</div>
              </div>
              <div className="h-10 w-px bg-zinc-800" />
              <div className="flex gap-2 text-xs overflow-x-auto pb-1 sm:pb-0">
                <button
                  onClick={() => setSelectedSeverity(selectedSeverity === 'critical' ? 'all' : 'critical')}
                  className={`text-center px-3 py-2 rounded-xl transition-all shrink-0 ${
                    selectedSeverity === 'critical'
                      ? 'bg-red-950/70 border border-red-800 text-red-300'
                      : 'hover:bg-zinc-800/60 border border-transparent'
                  }`}
                  title="Filter by Critical"
                  aria-label={`Filter by Critical severity, ${severityCounts.critical} findings`}
                >
                  <div className="font-mono font-bold text-red-400">{severityCounts.critical}</div>
                  <div className="text-[10px] text-zinc-400 font-mono">Critical</div>
                </button>
                <button
                  onClick={() => setSelectedSeverity(selectedSeverity === 'high' ? 'all' : 'high')}
                  className={`text-center px-3 py-2 rounded-xl transition-all shrink-0 ${
                    selectedSeverity === 'high'
                      ? 'bg-amber-950/70 border border-amber-800 text-amber-300'
                      : 'hover:bg-zinc-800/60 border border-transparent'
                  }`}
                  title="Filter by High"
                  aria-label={`Filter by High severity, ${severityCounts.high} findings`}
                >
                  <div className="font-mono font-bold text-amber-400">{severityCounts.high}</div>
                  <div className="text-[10px] text-zinc-400 font-mono">High</div>
                </button>
                <button
                  onClick={() => setSelectedSeverity(selectedSeverity === 'medium' ? 'all' : 'medium')}
                  className={`text-center px-3 py-2 rounded-xl transition-all shrink-0 ${
                    selectedSeverity === 'medium'
                      ? 'bg-yellow-950/70 border border-yellow-800 text-yellow-300'
                      : 'hover:bg-zinc-800/60 border border-transparent'
                  }`}
                  title="Filter by Medium"
                  aria-label={`Filter by Medium severity, ${severityCounts.medium} findings`}
                >
                  <div className="font-mono font-bold text-yellow-400">{severityCounts.medium}</div>
                  <div className="text-[10px] text-zinc-400 font-mono">Medium</div>
                </button>
                <button
                  onClick={() => setSelectedSeverity(selectedSeverity === 'low' ? 'all' : 'low')}
                  className={`text-center px-3 py-2 rounded-xl transition-all shrink-0 ${
                    selectedSeverity === 'low'
                      ? 'bg-emerald-950/70 border border-emerald-800 text-emerald-300'
                      : 'hover:bg-zinc-800/60 border border-transparent'
                  }`}
                  title="Filter by Low"
                  aria-label={`Filter by Low severity, ${severityCounts.low} findings`}
                >
                  <div className="font-mono font-bold text-emerald-400">{severityCounts.low}</div>
                  <div className="text-[10px] text-zinc-400 font-mono">Low</div>
                </button>
                <button
                  onClick={() => setSelectedSeverity(selectedSeverity === 'info' ? 'all' : 'info')}
                  className={`text-center px-3 py-2 rounded-xl transition-all shrink-0 ${
                    selectedSeverity === 'info'
                      ? 'bg-zinc-800 border border-zinc-700 text-zinc-300'
                      : 'hover:bg-zinc-800/60 border border-transparent'
                  }`}
                  title="Filter by Info"
                  aria-label={`Filter by Info severity, ${severityCounts.info} findings`}
                >
                  <div className="font-mono font-bold text-zinc-400">{severityCounts.info}</div>
                  <div className="text-[10px] text-zinc-400 font-mono">Info</div>
                </button>
              </div>
            </div>
            {selectedSeverity !== 'all' && (
              <button
                onClick={() => setSelectedSeverity('all')}
                className="text-xs text-zinc-400 hover:text-white flex items-center gap-1 transition-colors font-mono"
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
          <div className="p-4 border-b border-zinc-800 bg-[#121214] flex flex-col md:flex-row items-center justify-between gap-3">
            {/* Search Input */}
            <div className="relative w-full md:w-80">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search findings, endpoints, CVEs..."
                className="w-full pl-9 pr-4 py-2 rounded-lg bg-[#18181B] border border-zinc-800 text-xs text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-zinc-600 focus:ring-1 focus:ring-zinc-600 transition-all font-mono"
              />
              <div className="absolute left-3 top-2.5 text-zinc-500">
                <Search size={14} />
              </div>
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery('')}
                  className="absolute right-3 top-2.5 text-zinc-500 hover:text-zinc-300 text-xs"
                >
                  ✕
                </button>
              )}
            </div>

            {/* Dropdown Filters */}
            <div className="flex items-center gap-2.5 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
              {/* Severity Filter */}
              <div className="flex items-center gap-1.5 shrink-0">
                <span className="text-[11px] text-zinc-500 font-mono">Severity:</span>
                <select
                  value={selectedSeverity}
                  onChange={(e) => setSelectedSeverity(e.target.value)}
                  className="px-2.5 py-1.5 rounded-lg bg-[#18181B] border border-zinc-800 text-xs text-zinc-200 focus:outline-none focus:border-zinc-600 transition-all font-mono"
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
                  <span className="text-[11px] text-zinc-500 font-mono">Target:</span>
                  <select
                    value={selectedTarget}
                    onChange={(e) => setSelectedTarget(e.target.value)}
                    className="px-2.5 py-1.5 rounded-lg bg-[#18181B] border border-zinc-800 text-xs text-zinc-200 focus:outline-none focus:border-zinc-600 max-w-[160px] truncate transition-all font-mono"
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
                <span className="text-[11px] text-zinc-500 font-mono">Status:</span>
                <select
                  value={selectedStatus}
                  onChange={(e) => setSelectedStatus(e.target.value)}
                  className="px-2.5 py-1.5 rounded-lg bg-[#18181B] border border-zinc-800 text-xs text-zinc-200 focus:outline-none focus:border-zinc-600 transition-all font-mono"
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
              <table className="w-full text-left text-xs text-zinc-300">
                <thead className="bg-[#18181B] text-zinc-400 uppercase tracking-wider font-mono text-[10px] border-b border-zinc-800">
                  <tr>
                    <th scope="col" className="px-5 py-3 font-semibold">Severity</th>
                    <th scope="col" className="px-5 py-3 font-semibold">Vulnerability Title</th>
                    <th scope="col" className="px-4 py-3 font-semibold">Target & Asset</th>
                    <th scope="col" className="px-4 py-3 font-semibold">Detection Source</th>
                    <th scope="col" className="px-4 py-3 font-semibold">Status</th>
                    <th scope="col" className="px-5 py-3 text-right font-semibold">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800 bg-[#121214]">
                  {filteredFindings.map((finding) => (
                    <tr
                      key={finding.id}
                      onClick={() => handleFindingClick(finding)}
                      className="hover:bg-zinc-800/50 cursor-pointer transition-colors group"
                    >
                      <td className="px-5 py-3.5 whitespace-nowrap">
                        <SeverityBadge severity={finding.severity} size="sm" />
                      </td>
                      <td className="px-5 py-3.5 max-w-sm sm:max-w-md">
                        <div className="space-y-0.5">
                          <span className="font-medium text-white group-hover:text-zinc-200 transition-colors block text-xs">
                            {finding.title}
                          </span>
                          <p className="text-[11px] text-zinc-400 line-clamp-1">
                            {finding.description}
                          </p>
                        </div>
                      </td>
                      <td className="px-4 py-3.5 whitespace-nowrap">
                        <div className="space-y-0.5 font-mono">
                          <span className="text-xs text-zinc-200 block">
                            {finding.target}
                          </span>
                          <span className="text-[10px] text-zinc-500 block">
                            {finding.asset}
                          </span>
                        </div>
                      </td>
                      <td className="px-4 py-3.5 whitespace-nowrap font-mono">
                        <span className="px-2 py-0.5 rounded bg-[#18181B] border border-zinc-800 text-zinc-300 text-[11px]">
                          {finding.tool}
                        </span>
                      </td>
                      <td className="px-4 py-3.5 whitespace-nowrap">
                        <span className="px-2 py-0.5 rounded text-[11px] font-mono capitalize border border-zinc-700 bg-zinc-800 text-zinc-300">
                          {finding.status.replace('_', ' ')}
                        </span>
                      </td>
                      <td className="px-5 py-3.5 text-right whitespace-nowrap">
                        <span className="inline-flex items-center gap-1 text-xs text-zinc-400 group-hover:text-white font-mono transition-colors">
                          <span>Inspect</span>
                          <ChevronRight size={13} />
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

      {/* Detail Slideover Modal */}
      {activeFinding && (
        <FindingDetailModal
          finding={activeFinding}
          isOpen={Boolean(activeFinding)}
          onClose={closeDetailModal}
          onStatusChange={updateFindingStatus}
        />
      )}
    </motion.div>
  );
};
