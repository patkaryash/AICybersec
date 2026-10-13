import React from 'react';
import { LucideIcon } from 'lucide-react';

export interface StatCardProps {
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
      iconBg: 'bg-[#18181B] border-zinc-800 text-zinc-200',
    },
    purple: {
      iconBg: 'bg-[#18181B] border-zinc-800 text-zinc-200',
    },
    rose: {
      iconBg: 'bg-red-950/40 border-red-900/60 text-red-400',
    },
    amber: {
      iconBg: 'bg-amber-950/40 border-amber-900/60 text-amber-400',
    },
    emerald: {
      iconBg: 'bg-emerald-950/40 border-emerald-900/60 text-emerald-400',
    },
  }[accentColor];

  const badgeStyles = {
    default: 'border-zinc-700 bg-zinc-800 text-zinc-300',
    success: 'border-emerald-850 bg-emerald-950/60 border border-emerald-800/80 text-emerald-400',
    warning: 'border-amber-850 bg-amber-950/60 border border-amber-800/80 text-amber-400',
    danger: 'border-red-850 bg-red-950/60 border border-red-800/80 text-red-400',
  }[(badge?.variant ?? 'default') as 'default' | 'success' | 'warning' | 'danger'];

  return (
    <div className="bg-[#121214] border border-zinc-800 rounded-2xl p-5 shadow-xl hover:border-zinc-700 transition-all duration-200 flex flex-col justify-between group">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-zinc-400">
          {title}
        </span>
        <div className={`p-2.5 rounded-xl border ${accentStyles.iconBg} transition-transform duration-200 group-hover:scale-105 shadow-sm`}>
          <Icon size={17} aria-hidden="true" />
        </div>
      </div>

      <div className="mt-4 flex items-baseline justify-between gap-2">
        <span className={`text-3xl font-bold tracking-tight text-white font-mono ${
          typeof value === 'number' ? 'tabular-nums' : ''
        }`}>
          {value}
        </span>
        {badge && (
          <span className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded-md border ${badgeStyles}`}>
            {badge.text}
          </span>
        )}
      </div>

      {subtitle && (
        <p className="text-xs text-zinc-400 mt-2">
          {subtitle}
        </p>
      )}
    </div>
  );
};
