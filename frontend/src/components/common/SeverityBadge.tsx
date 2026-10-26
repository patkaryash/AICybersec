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
      classes: 'bg-rose-50/90 border-rose-200/90 text-[#DC2626]',
      iconClass: 'text-[#DC2626] animate-pulse',
      isPulse: true,
    },
    high: {
      label: 'High',
      icon: AlertTriangle,
      classes: 'bg-amber-50/90 border-amber-200/90 text-[#D97706]',
      iconClass: 'text-[#D97706]',
      isPulse: false,
    },
    medium: {
      label: 'Medium',
      icon: AlertCircle,
      classes: 'bg-yellow-50/90 border-yellow-200/90 text-[#CA8A04]',
      iconClass: 'text-[#CA8A04]',
      isPulse: false,
    },
    low: {
      label: 'Low',
      icon: Info,
      classes: 'bg-emerald-50/90 border-emerald-200/90 text-[#059669]',
      iconClass: 'text-[#059669]',
      isPulse: false,
    },
    info: {
      label: 'Info',
      icon: HelpCircle,
      classes: 'bg-slate-100 border-slate-200 text-[#64748B]',
      iconClass: 'text-[#64748B]',
      isPulse: false,
    },
  }[severity] || {
    label: severity,
    icon: Info,
    classes: 'bg-slate-100 border-slate-200 text-[#64748B]',
    iconClass: 'text-[#64748B]',
    isPulse: false,
  };

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5 gap-1 font-semibold',
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
