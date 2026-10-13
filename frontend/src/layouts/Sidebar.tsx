import React, { useMemo, useCallback } from 'react';
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
import {
  Sidebar as SidebarPrimitive,
  SidebarHeader,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarMenuBadge,
  SidebarRail,
  useSidebar,
} from '../components/ui/sidebar';
import { Tooltip, TooltipTrigger, TooltipContent } from '../components/ui/tooltip';

interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ onClose }) => {
  const { scans, isDemo } = useScans();
  const location = useLocation();
  const { isMobile, setOpenMobile, state } = useSidebar();
  const isCollapsed = state === 'collapsed' && !isMobile;

  const activeScans = useMemo(
    () =>
      scans.filter(
        (s) => s.status === 'running' || s.status === 'queued' || s.status === 'initializing'
      ),
    [scans]
  );
  const activeScan = useMemo(() => activeScans[0] || scans[0], [activeScans, scans]);

  const navItems = useMemo(
    () => [
      {
        to: '/',
        label: 'Dashboard',
        icon: LayoutDashboard,
        badge: null,
        pulse: false,
      },
      {
        to: '/new-scan',
        label: 'New Pentest',
        icon: ShieldPlus,
        badge: null,
        pulse: false,
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
        pulse: false,
      },
      {
        to: '/history',
        label: 'Scan History',
        icon: History,
        badge: scans.length.toString(),
        pulse: false,
      },
    ],
    [activeScan, activeScans.length, scans.length]
  );

  const handleNavClick = useCallback(() => {
    if (isMobile) {
      setOpenMobile(false);
    }
    onClose?.();
  }, [isMobile, setOpenMobile, onClose]);

  return (
    <SidebarPrimitive collapsible="icon">
      {/* Brand Header */}
      <SidebarHeader className="h-16 px-3.5 border-b border-zinc-800 flex flex-row items-center justify-between group-data-[collapsible=icon]:px-2 group-data-[collapsible=icon]:justify-center">
        <NavLink
          to="/"
          className="flex items-center gap-2.5 group overflow-hidden focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-600 rounded-xl"
          onClick={handleNavClick}
          aria-label="Sentinel AI Home"
        >
          <div className="w-9 h-9 shrink-0 rounded-xl bg-zinc-100 flex items-center justify-center text-zinc-900 shadow-sm transition-transform duration-200 group-hover:scale-105">
            <Shield size={20} className="stroke-[2.2]" />
          </div>
          <div className="flex flex-col min-w-0 transition-opacity duration-200 group-data-[collapsible=icon]:hidden">
            <div className="flex items-center gap-1.5">
              <span className="font-semibold text-base tracking-tight text-white">Sentinel</span>
              <span className="font-semibold text-base tracking-tight text-zinc-400">AI</span>
              <span className="text-[10px] px-1.5 py-0.2 rounded font-mono font-semibold bg-zinc-800 text-zinc-300 border border-zinc-700">
                v1.0
              </span>
            </div>
            <p className="text-[9px] text-zinc-500 font-mono tracking-wider uppercase truncate">
              Autonomous Pentest
            </p>
          </div>
        </NavLink>

        {/* Mobile close button */}
        {isMobile && (
          <button
            onClick={() => setOpenMobile(false)}
            className="p-1.5 rounded-lg text-zinc-400 hover:text-white hover:bg-zinc-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-zinc-600"
            aria-label="Close navigation"
          >
            <X size={18} />
          </button>
        )}
      </SidebarHeader>

      {/* Main Navigation Scroll Area */}
      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Platform Workflow</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {navItems.map((item) => {
                const Icon = item.icon;
                const isAgentRoute =
                  item.to.startsWith('/agent') && location.pathname.startsWith('/agent');
                const isDirectActive =
                  location.pathname === item.to || (item.to === '/' && location.pathname === '/');
                const isActive =
                  isAgentRoute ||
                  (item.to !== '/' && location.pathname.startsWith(item.to)) ||
                  isDirectActive;

                return (
                  <SidebarMenuItem key={item.label}>
                    <SidebarMenuButton
                      asChild
                      isActive={isActive}
                      tooltip={item.label}
                      size="default"
                    >
                      <NavLink
                        to={item.to}
                        onClick={handleNavClick}
                        className={({ isActive: directActive }) =>
                          `flex items-center w-full transition-colors ${
                            isActive || directActive
                              ? 'text-white'
                              : 'text-zinc-400 hover:text-zinc-100'
                          }`
                        }
                      >
                        <div className="flex items-center gap-3 min-w-0 group-data-[collapsible=icon]:justify-center group-data-[collapsible=icon]:w-full">
                          <Icon
                            size={18}
                            className={`shrink-0 transition-colors ${
                              isActive ? 'text-white' : 'text-zinc-500 group-hover:text-zinc-300'
                            }`}
                          />
                          <span className="truncate group-data-[collapsible=icon]:hidden">
                            {item.label}
                          </span>
                        </div>

                        {item.badge && (
                          <SidebarMenuBadge>
                            <span
                              className={`text-[10px] font-mono px-2 py-0.5 rounded-md flex items-center gap-1.5 ${
                                item.pulse
                                  ? 'bg-emerald-950/70 text-emerald-300 border border-emerald-800/80 font-semibold'
                                  : 'bg-zinc-800 text-zinc-400 border border-zinc-700'
                              }`}
                            >
                              {item.pulse && (
                                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                              )}
                              <span>{item.badge}</span>
                            </span>
                          </SidebarMenuBadge>
                        )}
                      </NavLink>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      {/* Status / Engine Card at Footer */}
      <SidebarFooter className="p-3 border-t border-zinc-800 bg-[#09090B] group-data-[collapsible=icon]:p-2">
        {/* Expanded state */}
        <div className="p-3 rounded-xl border border-zinc-800 bg-[#121214] space-y-2 group-data-[collapsible=icon]:hidden">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium text-zinc-400 flex items-center gap-1.5">
              <Activity size={12} className="text-emerald-400" />
              <span>Engine Status</span>
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-950/60 border border-emerald-800 text-emerald-300 font-semibold">
              ACTIVE
            </span>
          </div>
          <div className="text-[10px] text-zinc-400 font-mono space-y-0.5">
            <div className="flex justify-between">
              <span>Mode:</span>
              <span className={isDemo ? 'text-amber-400 font-medium' : 'text-emerald-400 font-medium'}>
                {isDemo ? 'Offline Demo' : 'REST v1 API'}
              </span>
            </div>
            <div className="flex justify-between">
              <span>Target Mode:</span>
              <span className="text-zinc-300">Strict Scope</span>
            </div>
          </div>
        </div>

        {/* Collapsed icon state */}
        {isCollapsed && (
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="flex items-center justify-center h-10 w-10 mx-auto rounded-xl border border-zinc-800 bg-[#121214] text-emerald-400 cursor-default">
                <span className="relative flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
                </span>
              </div>
            </TooltipTrigger>
            <TooltipContent side="right" align="center">
              <div className="font-mono text-[11px]">
                <div className="font-semibold text-emerald-400">ENGINE: ACTIVE</div>
                <div className="text-zinc-400">{isDemo ? 'Offline Demo' : 'REST API v1'}</div>
              </div>
            </TooltipContent>
          </Tooltip>
        )}
      </SidebarFooter>

      {/* Rail toggle interaction on desktop edge */}
      <SidebarRail />
    </SidebarPrimitive>
  );
};
