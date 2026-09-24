import React from 'react';
import { LucideIcon } from 'lucide-react';

interface EmptyStateProps {
  icon: LucideIcon;
  title: string;
  description: string;
  action?: {
    label: string;
    onClick: () => void;
    icon?: LucideIcon;
  };
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon: Icon,
  title,
  description,
  action,
}) => {
  const ActionIcon = action?.icon;

  return (
    <div className="py-12 px-6 flex flex-col items-center justify-center text-center max-w-md mx-auto">
      <div className="w-12 h-12 rounded-xl bg-sentinel-elevated border border-sentinel-border flex items-center justify-center text-sentinel-muted mb-4 shadow-inner">
        <Icon size={24} />
      </div>
      <h4 className="text-base font-semibold text-sentinel-text mb-1.5">{title}</h4>
      <p className="text-xs text-sentinel-muted leading-relaxed mb-6">{description}</p>
      {action && (
        <button
          onClick={action.onClick}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-sentinel-cyan text-sentinel-bg font-semibold text-xs tracking-wide hover:bg-sentinel-cyan-hover transition-colors shadow-sm"
        >
          {ActionIcon && <ActionIcon size={14} />}
          <span>{action.label}</span>
        </button>
      )}
    </div>
  );
};
