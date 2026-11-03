import React from 'react';
import { Severity } from '../../types/finding';
import { ShieldAlert, AlertTriangle, AlertCircle, Info, HelpCircle } from 'lucide-react';

interface SeverityBadgeProps {
  severity: Severity;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({
  severity,
  size = 'md',
  showIcon = true,
}) => {
  const config = {
    critical: {
      label: 'Critical',
      icon: ShieldAlert,
      classes: 'bg-red-950/60 border-red-800/80 text-red-400',
      iconClass: 'text-red-400',
      isPulse: true,
    },
    high: {
      label: 'High',
      icon: AlertTriangle,
      classes: 'bg-amber-950/60 border-amber-800/80 text-amber-400',
      iconClass: 'text-amber-400',
      isPulse: false,
    },
    medium: {
      label: 'Medium',
      icon: AlertCircle,
      classes: 'bg-yellow-950/60 border-yellow-800/80 text-yellow-400',
      iconClass: 'text-yellow-400',
      isPulse: false,
    },
    low: {
      label: 'Low',
      icon: Info,
      classes: 'bg-emerald-950/60 border-emerald-800/80 text-emerald-400',
      iconClass: 'text-emerald-400',
      isPulse: false,
    },
    info: {
      label: 'Info',
      icon: HelpCircle,
      classes: 'bg-zinc-800/80 border-zinc-700/80 text-zinc-300',
      iconClass: 'text-zinc-400',
      isPulse: false,
    },
  }[severity] || {
    label: severity,
    icon: Info,
    classes: 'bg-zinc-800/80 border-zinc-700/80 text-zinc-300',
    iconClass: 'text-zinc-400',
    isPulse: false,
  };

  const sizeClasses = {
    sm: 'text-[10px] px-2 py-0.5 gap-1 font-semibold',
    md: 'text-xs px-2.5 py-1 gap-1.5 font-semibold',
    lg: 'text-sm px-3 py-1.5 gap-2 font-semibold',
  }[size];

  const iconSizes = {
    sm: 12,
    md: 14,
    lg: 16,
  }[size];

  const IconComponent = config.icon;

  return (
    <span
      className={`inline-flex items-center rounded-md border uppercase tracking-wider font-mono ${config.classes} ${sizeClasses} ${config.isPulse ? 'animate-pulse' : ''}`}
      role="status"
      aria-label={`Severity level: ${config.label}`}
    >
      {showIcon && <IconComponent size={iconSizes} className={config.iconClass} aria-hidden="true" />}
      <span>{config.label}</span>
    </span>
  );
};
