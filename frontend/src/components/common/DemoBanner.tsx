import React from 'react';
import { Info } from 'lucide-react';
import { isDemoMode } from '../../services/config';

interface DemoBannerProps {
  className?: string;
  variant?: 'prominent' | 'compact';
}

export const DemoBanner: React.FC<DemoBannerProps> = ({
  className = '',
  variant = 'prominent',
}) => {
  const isDemo = isDemoMode();

  if (!isDemo) {
    if (variant === 'compact') {
      return (
        <div
          className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-medium bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 font-mono ${className}`}
        >
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          <span>CONNECTED: REST v1 API (AUTHORIZED LABS ONLY)</span>
        </div>
      );
    }
    return null;
  }

  if (variant === 'compact') {
    return (
      <div
        className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-medium bg-amber-950/40 border border-amber-800/60 text-amber-300 font-mono ${className}`}
      >
        <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
        <span>SIMULATED ENVIRONMENT / DEMO DATA (OFFLINE)</span>
      </div>
    );
  }

  return (
    <div
      className={`bg-sentinel-surface/90 border border-amber-900/50 rounded-lg p-3.5 flex items-start gap-3 shadow-md ${className}`}
      role="region"
      aria-label="Simulation notice"
    >
      <div className="p-1.5 rounded bg-amber-950/70 border border-amber-800/80 text-amber-400 mt-0.5 shrink-0">
        <Info size={16} aria-hidden="true" />
      </div>
      <div className="text-xs space-y-1">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-amber-300 uppercase tracking-wider font-mono">
            Demo & Simulation Notice
          </span>
          <span className="px-1.5 py-0.5 text-[10px] rounded bg-sentinel-elevated border border-sentinel-border text-sentinel-muted font-mono">
            Offline Mode
          </span>
        </div>
        <p className="text-sentinel-muted leading-relaxed">
          You are currently viewing <strong>simulated mock telemetry</strong>. No live offensive operations
          or unauthorized penetration testing against external networks are executed in this mode.
        </p>
      </div>
    </div>
  );
};
