import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldPlus,
  Radio,
  Bug,
  History,
  Shield,
  Activity,
  X,
} from 'lucide-react';
import { useScans } from '../context/ScanContext';

interface SidebarProps {
  isOpen: boolean;
  onClose: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen, onClose }) => {
  const { scans, isDemo } = useScans();
  const location = useLocation();

  const activeScans = scans.filter(
    (s) => s.status === 'running' || s.status === 'queued' || s.status === 'initializing'
  );
  const activeScan = activeScans[0] || scans[0];

  const navItems = [
    {
      to: '/',
      label: 'Dashboard',
      icon: LayoutDashboard,
      badge: null,
    },
    {
      to: '/new-scan',
      label: 'New Pentest',
      icon: ShieldPlus,
      badge: null,
    },
    {
      to: activeScan ? `/agent/${activeScan.id}` : '/agent/demo',
      label: 'Live AI Agent',
      icon: Radio,
      badge: activeScans.length > 0 ? `${activeScans.length} active` : null,
      pulse: activeScans.length > 0,
    },
    {
      to: '/findings',
      label: 'Vulnerabilities',
      icon: Bug,
      badge: null,
    },
    {
      to: '/history',
      label: 'Scan History',
      icon: History,
      badge: scans.length.toString(),
    },
  ];

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm lg:hidden"
          onClick={onClose}
          aria-hidden="true"
        />
      )}

      {/* Sidebar Panel */}
      <aside
        className={`fixed top-0 bottom-0 left-0 z-40 w-64 bg-sentinel-surface/95 border-r border-sentinel-border flex flex-col transition-transform duration-300 ease-in-out backdrop-blur-lg lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand Header */}
        <div className="h-16 px-5 border-b border-sentinel-border flex items-center justify-between">
          <NavLink to="/" className="flex items-center gap-2.5 group" onClick={onClose}>
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500/20 to-purple-600/20 border border-cyan-500/30 flex items-center justify-center text-sentinel-cyan group-hover:border-cyan-400 transition-colors shadow-sm">
              <Shield size={20} className="stroke-[2.2]" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-bold text-base tracking-tight text-sentinel-text">Sentinel</span>
                <span className="text-xs px-1.5 py-0.2 rounded font-mono font-semibold bg-cyan-950/80 text-sentinel-cyan border border-cyan-800/60">
                  AI
                </span>
              </div>
              <p className="text-[10px] text-sentinel-dim font-mono tracking-wider">AUTONOMOUS PENTEST</p>
            </div>
          </NavLink>

          <button
            onClick={onClose}
            className="p-1.5 rounded-md text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-elevated lg:hidden"
            aria-label="Close navigation"
          >
            <X size={18} />
          </button>
        </div>

        {/* Navigation */}
        <div className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          <div className="px-3 pb-2 text-[10px] font-bold uppercase tracking-wider text-sentinel-dim font-mono">
            Platform Workflow
          </div>

          {navItems.map((item) => {
            const Icon = item.icon;
            // Check active state, matching agent path prefix
            const isAgentRoute = item.to.startsWith('/agent') && location.pathname.startsWith('/agent');
            const isDirectActive = location.pathname === item.to || (item.to === '/' && location.pathname === '/');
            const isActive = isAgentRoute || (item.to !== '/' && location.pathname.startsWith(item.to)) || isDirectActive;

            return (
              <NavLink
                key={item.to}
                to={item.to}
                onClick={onClose}
                className={`flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all group ${
                  isActive
                    ? 'bg-sentinel-cyan/10 text-sentinel-cyan border border-sentinel-cyan/30 shadow-sm'
                    : 'text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-elevated/70'
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon
                    size={17}
                    className={`transition-colors ${
                      isActive ? 'text-sentinel-cyan' : 'text-sentinel-dim group-hover:text-sentinel-text'
                    }`}
                  />
                  <span>{item.label}</span>
                </div>

                {item.badge && (
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded-full flex items-center gap-1.5 ${
                      item.pulse
                        ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/80 font-semibold'
                        : 'bg-sentinel-elevated text-sentinel-dim border border-sentinel-border'
                    }`}
                  >
                    {item.pulse && <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />}
                    <span>{item.badge}</span>
                  </span>
                )}
              </NavLink>
            );
          })}
        </div>

        {/* Status / Engine Card at bottom */}
        <div className="p-3 border-t border-sentinel-border bg-sentinel-bg/50">
          <div className="p-3 rounded-lg border border-sentinel-border bg-sentinel-surface space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-medium text-sentinel-muted flex items-center gap-1.5">
                <Activity size={12} className="text-emerald-400" />
                <span>Engine Status</span>
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-300">
                ACTIVE
              </span>
            </div>
            <div className="text-[10px] text-sentinel-dim font-mono space-y-0.5">
              <div className="flex justify-between">
                <span>Mode:</span>
                <span className={isDemo ? 'text-amber-400' : 'text-emerald-400'}>
                  {isDemo ? 'Offline Demo' : 'REST v1 API'}
                </span>
              </div>
              <div className="flex justify-between">
                <span>Target Mode:</span>
                <span className="text-cyan-400">Strict Scope</span>
              </div>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
};
