import React from 'react';
import { cn } from '@/lib/utils';

export interface GridPatternProps {
  className?: string;
  size?: number;
}

export const GridPattern: React.FC<GridPatternProps> = ({
  className,
  size = 28,
}) => {
  return (
    <div
      className={cn(
        'pointer-events-none absolute inset-0 z-0 overflow-hidden',
        className
      )}
      aria-hidden="true"
    >
      {/* Precision SOC coordinate grid lines */}
      <div
        className="w-full h-full"
        style={{
          backgroundImage: `linear-gradient(to right, rgba(30, 41, 59, 0.45) 1px, transparent 1px), linear-gradient(to bottom, rgba(30, 41, 59, 0.45) 1px, transparent 1px)`,
          backgroundSize: `${size}px ${size}px`,
          maskImage: 'radial-gradient(ellipse 85% 75% at 50% 45%, black 45%, transparent 95%)',
          WebkitMaskImage: 'radial-gradient(ellipse 85% 75% at 50% 45%, black 45%, transparent 95%)',
        }}
      />
    </div>
  );
};
