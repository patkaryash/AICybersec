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
      iconBg: 'bg-blue-50 border-blue-200 text-[#1D4ED8]',
    },
    purple: {
      iconBg: 'bg-indigo-50 border-indigo-200 text-[#4F46E5]',
    },
    rose: {
      iconBg: 'bg-rose-50 border-rose-200 text-[#DC2626]',
    },
    amber: {
      iconBg: 'bg-amber-50 border-amber-200 text-[#D97706]',
    },
    emerald: {
      iconBg: 'bg-emerald-50 border-emerald-200 text-[#059669]',
    },
  }[accentColor];

  const badgeStyles = {
    default: 'border-[#D8E1EB] bg-[#EEF3F8] text-[#475569]',
    success: 'border-emerald-200 bg-emerald-50 text-[#059669]',
    warning: 'border-amber-200 bg-amber-50 text-[#D97706]',
    danger: 'border-rose-200 bg-rose-50 text-[#DC2626]',
  }[(badge?.variant ?? 'default') as 'default' | 'success' | 'warning' | 'danger'];

  return (
    <div className="bg-white/90 backdrop-blur-md border border-slate-200/80 rounded-xl p-5 shadow-sm hover:shadow-md hover:border-slate-300/90 transition-all duration-200 flex flex-col justify-between group">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-bold uppercase tracking-wider text-[#475569] font-mono">
          {title}
        </span>
        <div className={`p-2.5 rounded-lg border ${accentStyles.iconBg} transition-transform duration-200 group-hover:scale-105 shadow-2xs`}>
          <Icon size={17} aria-hidden="true" />
        </div>
      </div>

      <div className="mt-4 flex items-baseline justify-between gap-2">
        <span className={`text-3xl font-bold tracking-tight text-[#0B1220] ${
          typeof value === 'number' ? 'font-mono tabular-nums' : ''
        }`}>
          {value}
        </span>
        {badge && (
          <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full border ${badgeStyles}`}>
            {badge.text}
          </span>
        )}
      </div>

      {subtitle && (
        <p className="text-xs text-[#64748B] mt-2">
          {subtitle}
        </p>
      )}
    </div>
  );
};

