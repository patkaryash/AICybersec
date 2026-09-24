import React from 'react';
import { SeverityCount } from '../../types/finding';

interface SeverityChartProps {
  stats: SeverityCount;
}

export const SeverityChart: React.FC<SeverityChartProps> = ({ stats }) => {
  const total = stats.total || 0;

  const tiers = [
    { key: 'critical', label: 'Critical', count: stats.critical, color: 'bg-rose-500', text: 'text-rose-400', bg: 'bg-rose-950/40', border: 'border-rose-800/50' },
    { key: 'high', label: 'High', count: stats.high, color: 'bg-orange-500', text: 'text-orange-400', bg: 'bg-orange-950/40', border: 'border-orange-800/50' },
    { key: 'medium', label: 'Medium', count: stats.medium, color: 'bg-amber-500', text: 'text-amber-400', bg: 'bg-amber-950/40', border: 'border-amber-800/50' },
    { key: 'low', label: 'Low', count: stats.low, color: 'bg-sky-500', text: 'text-sky-400', bg: 'bg-sky-950/40', border: 'border-sky-800/50' },
    { key: 'info', label: 'Info', count: stats.info, color: 'bg-indigo-500', text: 'text-indigo-400', bg: 'bg-indigo-950/40', border: 'border-indigo-800/50' },
  ];

  const getPercentage = (count: number) => {
    if (total === 0) return 0;
    return Math.round((count / total) * 100);
  };

  return (
    <div className="space-y-4">
      {/* Segmented Distribution Bar */}
      <div>
        <div className="flex justify-between text-xs text-sentinel-muted mb-2">
          <span>Threat Exposure Distribution</span>
          <span className="font-mono text-sentinel-text">{total} Recorded Findings</span>
        </div>

        {total === 0 ? (
          <div className="h-3 w-full bg-sentinel-elevated rounded-full overflow-hidden border border-sentinel-border flex items-center justify-center">
            <span className="text-[10px] text-sentinel-dim">No vulnerabilities detected</span>
          </div>
        ) : (
          <div className="h-3 w-full bg-sentinel-elevated rounded-full overflow-hidden border border-sentinel-border flex">
            {tiers.map((tier) => {
              const pct = (tier.count / total) * 100;
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
            className={`p-3 rounded-lg border ${tier.border} ${tier.bg} flex flex-col justify-between transition-colors`}
          >
            <div className="flex items-center justify-between">
              <span className={`text-xs font-semibold ${tier.text}`}>{tier.label}</span>
              <span className="text-[10px] text-sentinel-dim font-mono">{getPercentage(tier.count)}%</span>
            </div>
            <div className="mt-1 flex items-baseline">
              <span className="text-xl font-bold font-mono text-sentinel-text">{tier.count}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
