import React, { useState, useMemo, useCallback } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
  Menu,
  PanelLeft,
  ShieldPlus,
  RotateCcw,
  Check,
  LogOut,
  User,
  Radio,
  Wifi,
  Sparkles,
} from 'lucide-react';
import { useScans } from '../context/ScanContext';
import { useAuth } from '../context/AuthContext';

interface TopbarProps {
  onToggleSidebar: () => void;
}

export const Topbar: React.FC<TopbarProps> = ({ onToggleSidebar }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { scans, resetDemoData, isDemo, toggleDemoMode } = useScans();
  const { user, isAuthenticated, logout } = useAuth();
  const [resetting, setResetting] = useState(false);
  const [showResetSuccess, setShowResetSuccess] = useState(false);

  const runningCount = scans.filter(
    (s) => s.status === 'running' || s.status === 'queued' || s.status === 'initializing'
  ).length;

  const pageInfo = useMemo(() => {
    const path = location.pathname;
    if (path === '/') {
      return { title: 'Operations Dashboard', subtitle: 'Real-time telemetry, threat overview, and recent assessments' };
    }
    if (path === '/new-scan') {
      return { title: 'New Penetration Test', subtitle: 'Target specification, assessment profile selection, and ethical authorization' };
    }
    if (path.startsWith('/agent')) {
      return { title: 'Live AI Agent', subtitle: 'Autonomous execution loop, decision tracing, and tool activity' };
    }
    if (path === '/findings') {
      return { title: 'Vulnerabilities', subtitle: 'Verified security weaknesses, evidence logs, and remediation guidance' };
    }
    if (path === '/history') {
      return { title: 'Scan History', subtitle: 'Comprehensive archive of historical penetration testing runs' };
    }
    return { title: 'Sentinel AI', subtitle: 'Autonomous Penetration Testing Platform' };
  }, [location.pathname]);

  const handleReset = useCallback(async () => {
    if (window.confirm('Reset all scans and findings back to initial demo seeds?')) {
      setResetting(true);
      await resetDemoData();
      setResetting(false);
      setShowResetSuccess(true);
      setTimeout(() => setShowResetSuccess(false), 2500);
    }
  }, [resetDemoData]);

  const handleLogout = useCallback(() => {
    logout();
    navigate('/login');
  }, [logout, navigate]);

  return (
    <header className="h-16 px-4 sm:px-6 bg-[#09090B]/90 border-b border-zinc-800 flex items-center justify-between sticky top-0 z-30 backdrop-blur-md">
      {/* Left: Sidebar toggle (Mobile hamburger / Desktop PanelLeft) + Page Title */}
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleSidebar}
          className="p-2 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-600"
          aria-label="Toggle navigation menu"
          title="Toggle Sidebar (Ctrl+B)"
        >
          <Menu size={20} className="lg:hidden" />
          <PanelLeft size={18} className="hidden lg:block" />
        </button>

        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-sm sm:text-base font-semibold text-white tracking-tight">
              {pageInfo.title}
            </h1>
            {runningCount > 0 && (
              <span className="hidden sm:inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-[11px] font-mono bg-emerald-950/60 border border-emerald-800 text-emerald-300">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                <span>{runningCount} Active</span>
              </span>
            )}
            {isDemo ? (
              <span className="hidden md:inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono bg-zinc-800 border border-zinc-700 text-amber-400">
                <Radio size={10} className="text-amber-400" />
                <span>DEMO MODE</span>
              </span>
            ) : (
              <span className="hidden md:inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-mono bg-zinc-800 border border-zinc-700 text-emerald-400">
                <Wifi size={10} className="text-emerald-400" />
                <span>API v1</span>
              </span>
            )}
          </div>
          <p className="hidden md:block text-[11px] text-zinc-400">
            {pageInfo.subtitle}
          </p>
        </div>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-2.5">
        {/* Demo Mode Actions */}
        {isDemo ? (
          <>
            <button
              onClick={handleReset}
              disabled={resetting}
              title="Reset to default mock dataset"
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-zinc-800 bg-[#18181B] text-zinc-300 hover:text-white hover:bg-zinc-800 text-xs transition-colors"
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

            <button
              onClick={() => toggleDemoMode(false)}
              title="Switch to Real Backend API mode"
              className="hidden sm:flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-zinc-700 bg-zinc-800 text-zinc-200 hover:bg-zinc-700 text-xs font-mono transition-colors"
            >
              <Sparkles size={12} className="text-zinc-300" />
              <span>Use Real API</span>
            </button>
          </>
        ) : (
          /* Real API Mode Actions */
          isAuthenticated && user && (
            <div className="flex items-center gap-2">
              <div className="hidden sm:flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-[#18181B] border border-zinc-800 text-xs font-mono">
                <User size={13} className="text-zinc-400" />
                <span className="text-zinc-200 font-medium truncate max-w-[140px]">
                  {user.display_name || user.email.split('@')[0]}
                </span>
                <span className="text-[10px] uppercase px-1 rounded bg-zinc-800 text-zinc-300 border border-zinc-700">
                  {user.role}
                </span>
              </div>

              <button
                onClick={handleLogout}
                title="Sign out of Sentinel AI"
                className="p-2 rounded-lg border border-zinc-800 bg-[#18181B] text-zinc-400 hover:text-red-400 hover:bg-red-950/20 text-xs transition-colors"
                aria-label="Logout"
              >
                <LogOut size={15} />
              </button>
            </div>
          )
        )}

        {/* Primary CTA */}
        {location.pathname !== '/new-scan' && (
          <button
            onClick={() => navigate('/new-scan')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-100 text-zinc-900 font-medium text-xs hover:bg-zinc-200 transition-colors shadow-sm"
          >
            <ShieldPlus size={14} />
            <span>Start Pentest</span>
          </button>
        )}
      </div>
    </header>
  );
};
