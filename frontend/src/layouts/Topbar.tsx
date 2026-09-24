import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  Menu,
  ShieldPlus,
  RotateCcw,
  Check,
  Radio,
  ExternalLink,
} from 'lucide-react';
import { useScans } from '../context/ScanContext';

interface TopbarProps {
  onToggleSidebar: () => void;
}

export const Topbar: React.FC<TopbarProps> = ({ onToggleSidebar }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { scans, resetDemoData } = useScans();
  const [resetting, setResetting] = useState(false);
  const [showResetSuccess, setShowResetSuccess] = useState(false);

  const runningCount = scans.filter((s) => s.status === 'running').length;

  const getPageInfo = () => {
    const path = location.pathname;
    if (path === '/') {
      return { title: 'Operations Dashboard', subtitle: 'Real-time telemetry, threat overview, and recent assessments' };
    }
    if (path === '/new-scan') {
      return { title: 'New Penetration Test', subtitle: 'Target specification, assessment profile selection, and ethical authorization' };
    }
    if (path.startsWith('/agent')) {
      return { title: 'Live AI Agent Telemetry', subtitle: 'Autonomous execution loop, decision tracing, and tool activity' };
    }
    if (path === '/findings') {
      return { title: 'Vulnerability Findings', subtitle: 'Verified security weaknesses, evidence logs, and remediation guidance' };
    }
    if (path === '/history') {
      return { title: 'Scan History & Audits', subtitle: 'Comprehensive archive of historical penetration testing runs' };
    }
    return { title: 'Sentinel AI', subtitle: 'AI-Assisted Penetration Testing Platform' };
  };

  const pageInfo = getPageInfo();

  const handleReset = async () => {
    if (window.confirm('Reset all scans and findings back to initial demo seeds?')) {
      setResetting(true);
      await resetDemoData();
      setResetting(false);
      setShowResetSuccess(true);
      setTimeout(() => setShowResetSuccess(false), 2500);
    }
  };

  return (
    <header className="h-16 px-4 sm:px-6 bg-sentinel-surface/80 border-b border-sentinel-border flex items-center justify-between sticky top-0 z-30 backdrop-blur-md">
      {/* Left: Mobile hamburger + Page Title */}
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleSidebar}
          className="p-2 rounded-lg text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-elevated lg:hidden transition-colors"
          aria-label="Toggle navigation menu"
        >
          <Menu size={20} />
        </button>

        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-sm sm:text-base font-bold text-sentinel-text tracking-tight">
              {pageInfo.title}
            </h1>
            {runningCount > 0 && (
              <span className="hidden sm:inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-mono bg-cyan-950/80 border border-cyan-700 text-cyan-300">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
                <span>{runningCount} Running</span>
              </span>
            )}
          </div>
          <p className="hidden md:block text-[11px] text-sentinel-muted">
            {pageInfo.subtitle}
          </p>
        </div>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-2.5">
        {/* Reset Demo Data */}
        <button
          onClick={handleReset}
          disabled={resetting}
          title="Reset to default mock dataset"
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-sentinel-border text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-elevated text-xs transition-colors"
        >
          {showResetSuccess ? (
            <>
              <Check size={13} className="text-emerald-400" />
              <span className="hidden sm:inline text-emerald-400">Reset</span>
            </>
          ) : (
            <>
              <RotateCcw size={13} className={resetting ? 'animate-spin' : ''} />
              <span className="hidden sm:inline">Reset Demo</span>
            </>
          )}
        </button>

        {/* Primary CTA */}
        {location.pathname !== '/new-scan' && (
          <button
            onClick={() => navigate('/new-scan')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sentinel-cyan text-sentinel-bg font-semibold text-xs tracking-wide hover:bg-sentinel-cyan-hover transition-colors shadow-sm"
          >
            <ShieldPlus size={14} />
            <span>Start Pentest</span>
          </button>
        )}
      </div>
    </header>
  );
};
