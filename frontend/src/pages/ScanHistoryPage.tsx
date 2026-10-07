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
          <h2 className="text-xl sm:text-2xl font-bold text-[#0B1220] tracking-tight">
            Scan History
          </h2>
          <p className="text-xs sm:text-sm text-[#475569] mt-1">
            Historical archive of penetration tests and security assessments
          </p>
        </div>

        <button
          onClick={() => navigate('/new-scan')}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#1D4ED8] text-white font-semibold text-xs tracking-wide hover:bg-[#1E40AF] transition-colors shadow-sm self-start sm:self-auto"
        >
          <ShieldPlus size={14} />
          <span>New Pentest</span>
        </button>
      </motion.div>

      {/* Metrics Overview */}
      <motion.div variants={itemVariants}>
        <div className="bg-white/90 backdrop-blur-md border border-slate-200/80 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-6">
              <div className="text-center">
                <div className="text-2xl font-bold font-mono text-[#0B1220]">{scans.length}</div>
                <div className="text-[10px] text-[#64748B] uppercase tracking-wider">Total Scans</div>
              </div>
              <div className="h-10 w-px bg-[#D8E1EB]" />
              <div className="flex gap-4 text-xs">
                <div className="text-center">
                  <div className="font-mono font-bold text-[#059669]">{totalCompleted}</div>
                  <div className="text-[10px] text-[#64748B]">Completed</div>
                </div>
                <div className="text-center">
                  <div className="font-mono font-bold text-[#1D4ED8]">{totalActive.length}</div>
                  <div className="text-[10px] text-[#64748B]">Active</div>
                </div>
                <div className="text-center">
                  <div className="font-mono font-bold text-[#DC2626]">{totalFindingsFound}</div>
                  <div className="text-[10px] text-[#64748B]">Findings</div>
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
          <div className="p-4 border-b border-slate-200/70 bg-white/90 backdrop-blur-md flex flex-col md:flex-row items-center justify-between gap-3">
            {/* Search */}
            <div className="relative w-full md:w-80">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search by target, scan ID, or goal..."
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

            {/* Filters */}
            <div className="flex items-center gap-2.5 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
              <div className="flex items-center gap-1.5 shrink-0">
                <span className="text-[11px] text-[#64748B]">Status:</span>
                <select
                  value={selectedStatus}
                  onChange={(e) => setSelectedStatus(e.target.value)}
                  className="px-2.5 py-1.5 rounded-lg bg-[#F4F7FB] border border-[#D8E1EB] text-xs text-[#0B1220] focus:outline-none focus:border-[#1D4ED8] focus:ring-2 focus:ring-[#1D4ED8]/25 transition-all"
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
                <span className="text-[11px] text-[#64748B]">Profile:</span>
                <select
                  value={selectedProfile}
                  onChange={(e) => setSelectedProfile(e.target.value)}
                  className="px-2.5 py-1.5 rounded-lg bg-[#F4F7FB] border border-[#D8E1EB] text-xs text-[#0B1220] focus:outline-none focus:border-[#1D4ED8] focus:ring-2 focus:ring-[#1D4ED8]/25 transition-all"
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
              <table className="w-full text-left text-xs text-[#475569]">
                <thead className="bg-slate-50/80 text-[#475569] uppercase tracking-wider font-mono text-[10px] border-b border-slate-200/80">
                  <tr>
                    <th scope="col" className="px-5 py-3 font-semibold">Target & Scan ID</th>
                    <th scope="col" className="px-4 py-3 font-semibold">Profile</th>
                    <th scope="col" className="px-4 py-3 font-semibold">Status</th>
                    <th scope="col" className="px-4 py-3 font-semibold">Timeline & Duration</th>
                    <th scope="col" className="px-4 py-3 font-semibold">Findings Severity</th>
                    <th scope="col" className="px-5 py-3 text-right font-semibold">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200/70 bg-white">
                  {filteredScans.map((scan) => {
                    const profile = SCAN_PROFILES[scan.profile] || { name: scan.profile };
                    const durationFormatted = formatDuration(scan);

                    return (
                      <tr
                        key={scan.id}
                        onClick={() => handleScanClick(scan.id)}
                        className="hover:bg-slate-50/80 cursor-pointer transition-colors group"
                      >
                        <td className="px-5 py-3.5">
                          <div className="space-y-0.5">
                            <code className="text-[#0B1220] font-mono font-medium group-hover:text-[#1D4ED8] transition-colors block">
                              {scan.target}
                            </code>
                            <div className="flex items-center gap-2">
                              <span className="text-[10px] text-[#64748B] font-mono">{scan.id.slice(0, 8)}</span>
                              <span
                                className={`text-[10px] font-mono ${
                                  scan.isSimulated ? 'text-[#D97706]' : 'text-[#059669]'
                                }`}
                              >
                                {scan.isSimulated ? 'Simulated' : 'REST v1'}
                              </span>
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-3.5 font-medium text-[#0B1220]">
                          <span className="px-2 py-0.5 rounded bg-slate-100 border border-slate-200 font-mono text-[11px]">
                            {profile.name}
                          </span>
                        </td>
                        <td className="px-4 py-3.5 whitespace-nowrap">
                          <StatusBadge status={scan.status} size="sm" />
                        </td>
                        <td className="px-4 py-3.5 whitespace-nowrap text-[#64748B] font-mono">
                          <div className="space-y-0.5">
                            <span className="text-[#0B1220] block">
                              {new Date(scan.startedAt).toLocaleDateString()} {new Date(scan.startedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                            </span>
                            <span className="text-[10px] text-[#64748B] block">
                              Duration: {durationFormatted}
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-3.5 whitespace-nowrap">
                          <div className="flex items-center gap-1.5 font-mono">
                            {scan.findingsCount.total === 0 ? (
                              <span className="text-[#64748B] text-xs">0 findings</span>
                            ) : (
                              <>
                                {scan.findingsCount.critical > 0 && (
                                  <span className="px-1.5 py-0.5 rounded bg-rose-50 border border-rose-200 text-[#DC2626] text-[11px] font-bold">
                                    {scan.findingsCount.critical} Crit
                                  </span>
                                )}
                                {scan.findingsCount.high > 0 && (
                                  <span className="px-1.5 py-0.5 rounded bg-amber-50 border border-amber-200 text-[#D97706] text-[11px] font-bold">
                                    {scan.findingsCount.high} High
                                  </span>
                                )}
                                {scan.findingsCount.medium > 0 && (
                                  <span className="px-1.5 py-0.5 rounded bg-yellow-50 border border-yellow-200 text-[#CA8A04] text-[11px]">
                                    {scan.findingsCount.medium} Med
                                  </span>
                                )}
                                {scan.findingsCount.low > 0 && (
                                  <span className="px-1.5 py-0.5 rounded bg-emerald-50 border border-emerald-200 text-[#059669] text-[11px]">
                                    {scan.findingsCount.low} Low
                                  </span>
                                )}
                                {scan.findingsCount.info > 0 && (
                                  <span className="px-1.5 py-0.5 rounded bg-slate-100 border border-slate-200 text-[#475569] text-[11px]">
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
                              className="text-[#1D4ED8] hover:underline flex items-center gap-1"
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
