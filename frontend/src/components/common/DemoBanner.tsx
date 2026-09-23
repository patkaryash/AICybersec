import React from 'react';
import { ShieldCheck, Info } from 'lucide-react';

interface DemoBannerProps {
  className?: string;
  variant?: 'prominent' | 'compact';
}

export const DemoBanner: React.FC<DemoBannerProps> = ({
  className = '',
  variant = 'prominent',
}) => {
  if (variant === 'compact') {
    return (
      <div
        className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-medium bg-cyan-950/40 border border-cyan-800/60 text-cyan-300 font-mono ${className}`}
      >
        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
        <span>SIMULATED ENVIRONMENT / DEMO DATA</span>
      </div>
    );
  }

  return (
    <div
      className={`bg-sentinel-surface/90 border border-cyan-900/50 rounded-lg p-3.5 flex items-start gap-3 shadow-md ${className}`}
      role="region"
      aria-label="Simulation notice"
    >
      <div className="p-1.5 rounded bg-cyan-950/70 border border-cyan-800/80 text-cyan-400 mt-0.5 shrink-0">
        <Info size={16} aria-hidden="true" />
      </div>
      <div className="text-xs space-y-1">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-cyan-300 uppercase tracking-wider font-mono">
            Demo & Simulation Notice
          </span>
          <span className="px-1.5 py-0.5 text-[10px] rounded bg-sentinel-elevated border border-sentinel-border text-sentinel-muted font-mono">
            Academic Demonstration
          </span>
        </div>
        <p className="text-sentinel-muted leading-relaxed">
          All scan executions, targets, event logs, and vulnerability findings displayed in Sentinel AI are
          <strong> strictly simulated mock telemetry</strong>. No live offensive operations or unauthorized
          penetration testing against external networks are executed by this interface.
        </p>
      </div>
    </div>
  );
};
