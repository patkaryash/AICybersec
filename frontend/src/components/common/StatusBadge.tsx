import React from 'react';
import { ScanStatus } from '../../types/scan';
import { CheckCircle2, AlertOctagon, Ban, Loader2, Clock, Sparkles } from 'lucide-react';

interface StatusBadgeProps {
  status: ScanStatus;
  size?: 'sm' | 'md';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, size = 'md' }) => {
  const config = {
    queued: {
      label: 'Queued',
      icon: Clock,
      classes: 'bg-zinc-800/80 border-zinc-700 text-zinc-300',
      iconClass: 'text-zinc-400',
      dotClass: 'bg-zinc-400',
    },
    initializing: {
      label: 'Initializing',
      icon: Sparkles,
      classes: 'bg-sky-950/60 border-sky-800/80 text-sky-300',
      iconClass: 'text-sky-400 animate-pulse',
      dotClass: 'bg-sky-400 animate-ping',
    },
    running: {
      label: 'Running',
      icon: Loader2,
      classes: 'bg-cyan-950/60 border-cyan-800/80 text-cyan-300',
      iconClass: 'animate-spin text-cyan-400',
      dotClass: 'bg-cyan-400 animate-ping',
    },
    cancelling: {
      label: 'Cancelling',
      icon: Loader2,
      classes: 'bg-amber-950/60 border-amber-800/80 text-amber-300',
      iconClass: 'animate-spin text-amber-400',
      dotClass: 'bg-amber-400',
    },
    completed: {
      label: 'Completed',
      icon: CheckCircle2,
      classes: 'bg-emerald-950/60 border-emerald-800/80 text-emerald-300',
      iconClass: 'text-emerald-400',
      dotClass: 'bg-emerald-400',
    },
    finished: {
      label: 'Completed',
      icon: CheckCircle2,
      classes: 'bg-emerald-950/60 border-emerald-800/80 text-emerald-300',
      iconClass: 'text-emerald-400',
      dotClass: 'bg-emerald-400',
    },
    cancelled: {
      label: 'Stopped',
      icon: Ban,
      classes: 'bg-zinc-800/80 border-zinc-700 text-zinc-400',
      iconClass: 'text-zinc-500',
      dotClass: 'bg-zinc-500',
    },
    failed: {
      label: 'Failed',
      icon: AlertOctagon,
      classes: 'bg-red-950/60 border-red-800/80 text-red-300',
      iconClass: 'text-red-400',
      dotClass: 'bg-red-400',
    },
  }[status] || {
    label: status,
    icon: CheckCircle2,
    classes: 'bg-zinc-800 border-zinc-700 text-zinc-300',
    iconClass: 'text-zinc-400',
    dotClass: 'bg-zinc-400',
  };

  const sizeClasses = size === 'sm' ? 'text-[11px] px-2 py-0.5 gap-1.5 font-mono' : 'text-xs px-2.5 py-1 gap-2 font-mono font-medium';
  const Icon = config.icon;

  return (
    <span
      className={`inline-flex items-center rounded-md border ${config.classes} ${sizeClasses}`}
      role="status"
      aria-label={`Scan status: ${config.label}`}
    >
      <Icon size={size === 'sm' ? 12 : 14} className={config.iconClass} aria-hidden="true" />
      <span>{config.label}</span>
    </span>
  );
};
