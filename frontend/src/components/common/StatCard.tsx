import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  accentColor?: 'cyan' | 'purple' | 'rose' | 'amber' | 'emerald';
  badge?: {
    text: string;
    variant?: 'default' | 'success' | 'warning' | 'danger';
  };
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  accentColor = 'cyan',
  badge,
}) => {
  const accentStyles = {
    cyan: {
      iconBg: 'bg-cyan-950/60 border-cyan-800/60 text-cyan-400',
      borderHover: 'hover:border-cyan-500/40',
    },
    purple: {
      iconBg: 'bg-purple-950/60 border-purple-800/60 text-purple-400',
      borderHover: 'hover:border-purple-500/40',
    },
    rose: {
      iconBg: 'bg-rose-950/60 border-rose-800/60 text-rose-400',
      borderHover: 'hover:border-rose-500/40',
    },
    amber: {
      iconBg: 'bg-amber-950/60 border-amber-800/60 text-amber-400',
      borderHover: 'hover:border-amber-500/40',
    },
    emerald: {
      iconBg: 'bg-emerald-950/60 border-emerald-800/60 text-emerald-400',
      borderHover: 'hover:border-emerald-500/40',
    },
  }[accentColor];

  const badgeStyles = {
    default: 'border-sentinel-border bg-sentinel-elevated text-sentinel-muted',
    success: 'border-emerald-800/60 bg-emerald-950/50 text-emerald-300',
    warning: 'border-amber-800/60 bg-amber-950/50 text-amber-300',
    danger: 'border-rose-800/60 bg-rose-950/50 text-rose-300',
  }[(badge?.variant ?? 'default') as 'default' | 'success' | 'warning' | 'danger'];

  return (
    <div
      className={`bg-sentinel-surface border border-sentinel-border rounded-xl p-5 shadow-sm transition-all duration-200 ${accentStyles.borderHover} hover:shadow-md hover:-translate-y-px flex flex-col justify-between`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-[0.08em] text-sentinel-muted">{title}</span>
        <div className={`p-2.5 rounded-xl border ${accentStyles.iconBg}`}>
          <Icon size={17} aria-hidden="true" />
        </div>
      </div>

      <div className="mt-4 flex items-baseline justify-between gap-2">
        <span className="text-[32px] leading-none font-bold tracking-tight tabular-nums text-sentinel-text">{value}</span>
        {badge && (
          <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full border ${badgeStyles}`}>
            {badge.text}
          </span>
        )}
      </div>

      {subtitle && <p className="text-xs text-sentinel-dim mt-2">{subtitle}</p>}
    </div>
  );
};
