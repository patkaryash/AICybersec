import React from 'react';
import { cn } from '@/lib/utils';

export interface MovingBorderButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  children: React.ReactNode;
  duration?: number;
  className?: string;
  containerClassName?: string;
  borderRadius?: string;
}

export const MovingBorderButton: React.FC<MovingBorderButtonProps> = ({
  children,
  duration = 6000,
  className = '',
  containerClassName = '',
  borderRadius = '0.75rem',
  ...props
}) => {
  return (
    <button
      className={cn(
        'relative p-[1.5px] overflow-hidden group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400 focus-visible:ring-offset-2 focus-visible:ring-offset-sentinel-bg transition-transform duration-200 active:scale-[0.98]',
        containerClassName
      )}
      style={{ borderRadius }}
      {...props}
    >
      {/* 1. Animated Conic Moving Border Beam */}
      <div
        className="pointer-events-none absolute inset-[-150%] aspect-square bg-[conic-gradient(from_0deg_at_50%_50%,transparent_0deg,transparent_310deg,#06B6D4_345deg,#8B5CF6_360deg)] animate-spin-slow"
        style={{ animationDuration: `${duration}ms` }}
        aria-hidden="true"
      />

      {/* 2. Core Button Surface */}
      <div
        className={cn(
          'relative bg-sentinel-cyan text-sentinel-bg font-semibold text-xs tracking-wide px-5 py-2.5 flex items-center justify-center gap-2 hover:bg-sentinel-cyan-hover transition-colors shadow-lg shadow-cyan-950/40',
          className
        )}
        style={{ borderRadius: `calc(${borderRadius} - 1.5px)` }}
      >
        {children}
      </div>
    </button>
  );
};
