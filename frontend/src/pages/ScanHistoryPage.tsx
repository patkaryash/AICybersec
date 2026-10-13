import React, { useState, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  History,
  Search,
  ShieldPlus,
  ArrowRight,
  RotateCcw,
} from 'lucide-react';
import { useScans } from '../context/ScanContext';
import { StatusBadge } from '../components/common/StatusBadge';
import { Card } from '../components/common/Card';
import { EmptyState } from '../components/common/EmptyState';
import { DemoBanner } from '../components/common/DemoBanner';
import { SCAN_PROFILES } from '../types/scan';
import { containerVariants, itemVariants } from '../lib/motionVariants';

export const ScanHistoryPage: React.FC = () => {
  const navigate = useNavigate();
  const { scans } = useScans();

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedStatus, setSelectedStatus] = useState<string>('all');
  const [selectedProfile, setSelectedProfile] = useState<string>('all');

  // Reset all filters
  const resetFilters = useCallback(() => {
    setSearchQuery('');
    setSelectedStatus('all');
    setSelectedProfile('all');
  }, []);

  // Handle scan navigation
  const handleScanClick = useCallback((scanId: string) => {
    navigate(`/agent/${scanId}`);
  }, [navigate]);

  // Sort scans by date (newest first)
  const sortedScans = useMemo(() => {
    return [...scans].sort((a, b) => {
      const dateA = new Date(a.startedAt).getTime();
      const dateB = new Date(b.startedAt).getTime();
      return dateB - dateA;
    });
  }, [scans]);

  // Format duration helper (memoized to avoid recreation on each render)
  const formatDuration = useCallback((scan: typeof scans[0]) => {
    if (scan.status === 'queued' || !scan.startedAt) return 'Queued';
    const start = new Date(scan.startedAt).getTime();
    const end = scan.completedAt ? new Date(scan.completedAt).getTime() : Date.now();
    const durationSec = Math.max(0, Math.floor((end - start) / 1000));
    const durationMins = Math.floor(durationSec / 60);
    const durationSecs = durationSec % 60;
    return scan.completedAt ? `${durationMins}m ${durationSecs}s` : 'Active';
  }, []);

  const filteredScans = useMemo(() => {
    return sortedScans.filter((scan) => {
      const matchesSearch =
        searchQuery === '' ||
        scan.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
        scan.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        scan.goal.toLowerCase().includes(searchQuery.toLowerCase());

      const matchesStatus =
        selectedStatus === 'all' ||
        scan.status === selectedStatus ||
        (selectedStatus === 'completed' && scan.status === 'finished');

      const matchesProfile =
        selectedProfile === 'all' ||
        scan.profile === selectedProfile ||
        (selectedProfile === 'web' && scan.profile === 'web_assessment') ||
        (selectedProfile === 'full' && scan.profile === 'full_assessment');

      return matchesSearch && matchesStatus && matchesProfile;
    });
  }, [sortedScans, searchQuery, selectedStatus, selectedProfile]);

  const totalCompleted = useMemo(
    () => scans.filter((s) => s.status === 'completed' || s.status === 'finished').length,
    [scans]
  );
  const totalActive = useMemo(
    () =>
      scans.filter(
        (s) => s.status === 'running' || s.status === 'queued' || s.status === 'initializing'
      ),
    [scans]
  );
  const totalFindingsFound = useMemo(
    () => scans.reduce((acc, s) => acc + s.findingsCount.total, 0),
    [scans]
  );

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

      {/* Header */}
      <motion.div
        variants={itemVariants}
        className="flex flex-col sm:flex-row sm:items-start justify-between gap-4"
      >
        <div className="flex-1">
          <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
            Scan History
          </h2>
          <p className="text-xs sm:text-sm text-zinc-400 mt-1">
            Historical archive of penetration tests, target assessments, and verified findings
          </p>
        </div>

        <button
          onClick={() => navigate('/new-scan')}
          className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-zinc-100 text-zinc-900 font-medium text-xs tracking-wide hover:bg-zinc-200 transition-colors shadow-sm self-start sm:self-auto"
        >
          <ShieldPlus size={14} />
          <span>New Pentest</span>
        </button>
      </motion.div>

      {/* Metrics Overview */}
      <motion.div variants={itemVariants}>
        <div className="bg-[#121214] border border-zinc-800 rounded-2xl p-4 shadow-xl">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-6">
              <div className="text-center">
                <div className="text-2xl font-bold font-mono text-white">{scans.length}</div>
                <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-mono">Total Scans</div>
              </div>
              <div className="h-10 w-px bg-zinc-800" />
              <div className="flex gap-4 text-xs font-mono">
                <div className="text-center">
                  <div className="font-bold text-emerald-400">{totalCompleted}</div>
                  <div className="text-[10px] text-zinc-400">Completed</div>
                </div>
                <div className="text-center">
                  <div className="font-bold text-cyan-400">{totalActive.length}</div>
                  <div className="text-[10px] text-zinc-400">Active</div>
                </div>
                <div className="text-center">
                  <div className="font-bold text-red-400">{totalFindingsFound}</div>
                  <div className="text-[10px] text-zinc-400">Findings</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </motion.div>

      {/* Main Table Card */}
      <motion.div variants={itemVariants}>
        <Card noPadding>
          {/* Filters Header */}
          <div className="p-4 border-b border-zinc-800 bg-[#121214] flex flex-col md:flex-row items-center justify-between gap-3">
            {/* Search */}
            <div className="relative w-full md:w-80">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by target, scan ID, or goal..."
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

            {/* Filters */}
            <div className="flex items-center gap-2.5 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
              <div className="flex items-center gap-1.5 shrink-0">
                <span className="text-[11px] text-zinc-500 font-mono">Status:</span>
                <select
                  value={selectedStatus}
                  onChange={(e) => setSelectedStatus(e.target.value)}
                  className="px-2.5 py-1.5 rounded-lg bg-[#18181B] border border-zinc-800 text-xs text-zinc-200 focus:outline-none focus:border-zinc-600 transition-all font-mono"
                >
                  <option value="all">All Statuses</option>
                  <option value="queued">Queued</option>
                  <option value="initializing">Initializing</option>
                  <option value="running">Running</option>
                  <option value="completed">Completed</option>
                  <option value="cancelling">Cancelling</option>
                  <option value="cancelled">Stopped</option>
                  <option value="failed">Failed</option>
                </select>
              </div>

              <div className="flex items-center gap-1.5 shrink-0">
                <span className="text-[11px] text-zinc-500 font-mono">Profile:</span>
                <select
                  value={selectedProfile}
                  onChange={(e) => setSelectedProfile(e.target.value)}
                  className="px-2.5 py-1.5 rounded-lg bg-[#18181B] border border-zinc-800 text-xs text-zinc-200 focus:outline-none focus:border-zinc-600 transition-all font-mono"
                >
                  <option value="all">All Profiles</option>
                  <option value="recon">Reconnaissance</option>
                  <option value="web">Web Assessment</option>
                  <option value="full">Full Assessment</option>
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
                onClick: resetFilters,
              }}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-zinc-300">
                <thead className="bg-[#18181B] text-zinc-400 uppercase tracking-wider font-mono text-[10px] border-b border-zinc-800">
                  <tr>
                    <th scope="col" className="px-5 py-3 font-semibold">Target & Scan ID</th>
                    <th scope="col" className="px-4 py-3 font-semibold">Profile</th>
                    <th scope="col" className="px-4 py-3 font-semibold">Status</th>
                    <th scope="col" className="px-4 py-3 font-semibold">Timeline & Duration</th>
                    <th scope="col" className="px-4 py-3 font-semibold">Findings Severity</th>
                    <th scope="col" className="px-5 py-3 text-right font-semibold">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800 bg-[#121214]">
                  {filteredScans.map((scan) => {
                    const profile = SCAN_PROFILES[scan.profile] || { name: scan.profile };
                    const durationFormatted = formatDuration(scan);

                    return (
                      <tr
                        key={scan.id}
                        onClick={() => handleScanClick(scan.id)}
                        className="hover:bg-zinc-800/50 cursor-pointer transition-colors group"
                      >
                        <td className="px-5 py-3.5">
                          <div className="space-y-0.5">
                            <code className="text-white font-mono font-medium group-hover:text-zinc-200 transition-colors block">
                              {scan.target}
                            </code>
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] text-zinc-500 font-mono">{scan.id.slice(0, 8)}</span>
                              <span
                                className={`text-[10px] font-mono ${
                                  scan.isSimulated ? 'text-amber-400' : 'text-emerald-400'
                                }`}
                              >
                                {scan.isSimulated ? 'Simulated' : 'REST v1'}
                              </span>
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-3.5 font-medium text-zinc-200">
                          <span className="px-2 py-0.5 rounded bg-[#18181B] border border-zinc-800 font-mono text-[11px] text-zinc-300">
                            {profile.name}
                          </span>
                        </td>
                        <td className="px-4 py-3.5 whitespace-nowrap">
                          <StatusBadge status={scan.status} size="sm" />
                        </td>
                        <td className="px-4 py-3.5 whitespace-nowrap text-zinc-400 font-mono">
                          <div className="space-y-0.5">
                            <span className="text-zinc-200 block">
                              {new Date(scan.startedAt).toLocaleDateString()} {new Date(scan.startedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                            </span>
                            <span className="text-[10px] text-zinc-500 block">
                              Duration: {durationFormatted}
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-3.5 whitespace-nowrap">
                          <div className="flex items-center gap-1.5 font-mono">
                            {scan.findingsCount.total === 0 ? (
                              <span className="text-zinc-500 text-xs">0 findings</span>
                            ) : (
                              <>
                                {scan.findingsCount.critical > 0 && (
                                  <span className="px-1.5 py-0.5 rounded bg-red-950/60 border border-red-800 text-red-300 text-[11px] font-bold">
                                    {scan.findingsCount.critical} Crit
                                  </span>
                                )}
                                {scan.findingsCount.high > 0 && (
                                  <span className="px-1.5 py-0.5 rounded bg-amber-950/60 border border-amber-800 text-amber-300 text-[11px] font-bold">
                                    {scan.findingsCount.high} High
                                  </span>
                                )}
                                {scan.findingsCount.medium > 0 && (
                                  <span className="px-1.5 py-0.5 rounded bg-yellow-950/60 border border-yellow-800 text-yellow-300 text-[11px]">
                                    {scan.findingsCount.medium} Med
                                  </span>
                                )}
                                {scan.findingsCount.low > 0 && (
                                  <span className="px-1.5 py-0.5 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-300 text-[11px]">
                                    {scan.findingsCount.low} Low
                                  </span>
                                )}
                                {scan.findingsCount.info > 0 && (
                                  <span className="px-1.5 py-0.5 rounded bg-zinc-800 border border-zinc-700 text-zinc-300 text-[11px]">
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
                                handleScanClick(scan.id);
                              }}
                              className="text-zinc-400 hover:text-white flex items-center gap-1 transition-colors"
                            >
                              <span>View</span>
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
      </motion.div>
    </motion.div>
  );
};
