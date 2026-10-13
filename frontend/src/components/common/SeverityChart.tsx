import React from 'react';
import { SeverityCount } from '../../types/finding';

interface SeverityChartProps {
  stats: SeverityCount;
}

export const SeverityChart: React.FC<SeverityChartProps> = ({ stats }) => {
  const total = stats.total || 0;

  const tiers = [
    { key: 'critical', label: 'Critical', count: stats.critical, color: 'bg-[#EF4444]', text: 'text-red-400', bg: 'bg-red-950/40', border: 'border-red-900/60' },
    { key: 'high', label: 'High', count: stats.high, color: 'bg-[#F59E0B]', text: 'text-amber-400', bg: 'bg-amber-950/40', border: 'border-amber-900/60' },
    { key: 'medium', label: 'Medium', count: stats.medium, color: 'bg-[#EAB308]', text: 'text-yellow-400', bg: 'bg-yellow-950/40', border: 'border-yellow-900/60' },
    { key: 'low', label: 'Low', count: stats.low, color: 'bg-[#10B981]', text: 'text-emerald-400', bg: 'bg-emerald-950/40', border: 'border-emerald-900/60' },
    { key: 'info', label: 'Info', count: stats.info, color: 'bg-[#71717A]', text: 'text-zinc-400', bg: 'bg-zinc-800/40', border: 'border-zinc-700/60' },
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
        <div className="flex justify-between items-baseline text-xs text-zinc-400 mb-2 font-mono">
          <span className="font-semibold uppercase tracking-wider text-[11px] text-zinc-400">Exposure Spectrum</span>
          <span className="text-white font-bold tabular-nums">{total} Verified Findings</span>
        </div>

        {total === 0 ? (
          <div className="h-2.5 w-full bg-[#18181B] rounded-full overflow-hidden border border-zinc-800 flex items-center justify-center">
            <span className="text-[10px] text-zinc-500 font-mono">No vulnerabilities detected</span>
          </div>
        ) : (
          <div className="h-2.5 w-full bg-[#18181B] rounded-full overflow-hidden border border-zinc-800 flex shadow-inner">
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
            className={`p-3 rounded-xl border ${tier.border} ${tier.bg} flex flex-col justify-between transition-all hover:border-zinc-600`}
          >
            <div className="flex items-center justify-between">
              <span className={`text-xs font-semibold ${tier.text}`}>{tier.label}</span>
              <span className="text-[11px] text-zinc-400 font-mono tabular-nums">{getPercentage(tier.count)}%</span>
            </div>
            <div className="mt-2 flex items-baseline">
              <span className="text-2xl leading-none font-bold tabular-nums text-white tracking-tight font-mono">{tier.count}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
