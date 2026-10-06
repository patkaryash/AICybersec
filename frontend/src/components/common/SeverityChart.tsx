import React from 'react';
import { SeverityCount } from '../../types/finding';

interface SeverityChartProps {
  stats: SeverityCount;
}

export const SeverityChart: React.FC<SeverityChartProps> = ({ stats }) => {
  const total = stats.total || 0;

  const tiers = [
    { key: 'critical', label: 'Critical', count: stats.critical, color: 'bg-[#DC2626]', text: 'text-[#DC2626]', bg: 'bg-rose-50/70', border: 'border-rose-200/80' },
    { key: 'high', label: 'High', count: stats.high, color: 'bg-[#D97706]', text: 'text-[#D97706]', bg: 'bg-amber-50/70', border: 'border-amber-200/80' },
    { key: 'medium', label: 'Medium', count: stats.medium, color: 'bg-[#CA8A04]', text: 'text-[#CA8A04]', bg: 'bg-yellow-50/70', border: 'border-yellow-200/80' },
    { key: 'low', label: 'Low', count: stats.low, color: 'bg-[#059669]', text: 'text-[#059669]', bg: 'bg-emerald-50/70', border: 'border-emerald-200/80' },
    { key: 'info', label: 'Info', count: stats.info, color: 'bg-[#64748B]', text: 'text-[#64748B]', bg: 'bg-slate-50/70', border: 'border-slate-200/80' },
  ];

  const getPercentage = (count: number) => {
    if (total === 0) return 0;
    return Math.min(100, Math.round((count / total) * 100));
  };

  const barWidth = (count: number) => {
    if (total === 0) return 0;
    return Math.min(100, (count / total) * 100);
  };

  return (
    <div className="space-y-4">
      {/* Segmented Distribution Bar */}
      <div>
        <div className="flex justify-between items-baseline text-xs text-slate-500 mb-2 font-mono">
          <span className="font-semibold uppercase tracking-wider text-[11px] text-slate-600">Exposure Spectrum</span>
          <span className="text-slate-900 font-bold tabular-nums">{total} Verified Findings</span>
        </div>

        {total === 0 ? (
          <div className="h-2.5 w-full bg-slate-100 rounded-full overflow-hidden border border-slate-200 flex items-center justify-center">
            <span className="text-[10px] text-slate-400 font-mono">No vulnerabilities detected</span>
          </div>
        ) : (
          <div className="h-2.5 w-full bg-slate-100 rounded-full overflow-hidden border border-slate-200 flex shadow-inner">
            {tiers.map((tier) => {
              const pct = barWidth(tier.count);
              if (pct === 0) return null;
              return (
                <div
                  key={tier.key}
                  style={{ width: `${pct}%` }}
                  className={`${tier.color} transition-all duration-500 hover:opacity-90 relative group`}
                  title={`${tier.label}: ${tier.count} (${Math.round(pct)}%)`}
                />
              );
            })}
          </div>
        )}
      </div>

      {/* Counts Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5 pt-1">
        {tiers.map((tier) => (
          <div
            key={tier.key}
            className={`p-3 rounded-xl border ${tier.border} ${tier.bg} flex flex-col justify-between transition-all hover:shadow-sm`}
          >
            <div className="flex items-center justify-between">
              <span className={`text-xs font-semibold ${tier.text}`}>{tier.label}</span>
              <span className="text-[11px] text-slate-500 font-mono tabular-nums">{getPercentage(tier.count)}%</span>
            </div>
            <div className="mt-2 flex items-baseline">
              <span className="text-2xl leading-none font-bold tabular-nums text-slate-900 tracking-tight">{tier.count}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
