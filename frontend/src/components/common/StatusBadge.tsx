import React from 'react';
import { ScanStatus } from '../../types/scan';
import { CheckCircle2, AlertOctagon, Ban, Loader2 } from 'lucide-react';

interface StatusBadgeProps {
  status: ScanStatus;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'md' }) => {
  const config = {
    running: {
      label: 'Running',
      icon: Loader2,
      classes: 'bg-cyan-950/60 border-cyan-700/80 text-cyan-300',
      iconClass: 'animate-spin text-cyan-400',
      dotClass: 'bg-cyan-400 animate-ping',
    },
    finished: {
      label: 'Completed',
      icon: CheckCircle2,
      classes: 'bg-emerald-950/60 border-emerald-700/80 text-emerald-300',
      iconClass: 'text-emerald-400',
      dotClass: 'bg-emerald-400',
    },
    cancelled: {
      label: 'Stopped',
      icon: Ban,
      classes: 'bg-slate-800/80 border-slate-600 text-slate-300',
      iconClass: 'text-slate-400',
      dotClass: 'bg-slate-400',
    },
    failed: {
      label: 'Failed',
      icon: AlertOctagon,
      classes: 'bg-rose-950/60 border-rose-800 text-rose-300',
      iconClass: 'text-rose-400',
      dotClass: 'bg-rose-400',
    },
  }[status] || {
    label: status,
    icon: CheckCircle2,
    classes: 'bg-slate-800 border-slate-700 text-slate-300',
    iconClass: 'text-slate-400',
    dotClass: 'bg-slate-400',
  };

  const sizeClasses = size === 'sm' ? 'text-xs px-2 py-0.5 gap-1.5' : 'text-xs px-2.5 py-1 gap-2 font-medium';
  const Icon = config.icon;

  return (
    <span
      className={`inline-flex items-center rounded-full border ${config.classes} ${sizeClasses}`}
      role="status"
      aria-label={`Scan status: ${config.label}`}
    >
      <Icon size={size === 'sm' ? 12 : 14} className={config.iconClass} aria-hidden="true" />
      <span>{config.label}</span>
    </span>
  );
};
