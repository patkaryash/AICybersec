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
      classes: 'bg-rose-950/70 border-rose-700/80 text-rose-300 shadow-[0_0_12px_rgba(244,63,94,0.15)]',
      iconClass: 'text-rose-400',
    },
    high: {
      label: 'High',
      icon: AlertTriangle,
      classes: 'bg-orange-950/70 border-orange-700/80 text-orange-300 shadow-[0_0_12px_rgba(249,115,22,0.15)]',
      iconClass: 'text-orange-400',
    },
    medium: {
      label: 'Medium',
      icon: AlertCircle,
      classes: 'bg-amber-950/60 border-amber-700/80 text-amber-300',
      iconClass: 'text-amber-400',
    },
    low: {
      label: 'Low',
      icon: Info,
      classes: 'bg-sky-950/60 border-sky-700/80 text-sky-300',
      iconClass: 'text-sky-400',
    },
    info: {
      label: 'Info',
      icon: HelpCircle,
      classes: 'bg-indigo-950/60 border-indigo-700/80 text-indigo-300',
      iconClass: 'text-indigo-400',
    },
  }[severity] || {
    label: severity,
    icon: Info,
    classes: 'bg-slate-900 border-slate-700 text-slate-300',
    iconClass: 'text-slate-400',
  };

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 gap-1',
    md: 'text-xs px-2.5 py-1 gap-1.5 font-medium',
    lg: 'text-sm px-3 py-1.5 gap-2 font-medium',
  }[size];

  const iconSizes = {
    sm: 12,
    md: 14,
    lg: 16,
  }[size];

  const IconComponent = config.icon;

  return (
    <span
      className={`inline-flex items-center rounded-md border uppercase tracking-wider font-mono ${config.classes} ${sizeClasses}`}
      role="status"
      aria-label={`Severity level: ${config.label}`}
    >
      {showIcon && <IconComponent size={iconSizes} className={config.iconClass} aria-hidden="true" />}
      <span>{config.label}</span>
    </span>
  );
};
