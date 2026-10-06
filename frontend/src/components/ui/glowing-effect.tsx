import React, { useRef, useCallback } from 'react';
import { cn } from '@/lib/utils';

export interface GlowingEffectCardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  accentColor?: 'cyan' | 'purple' | 'rose' | 'amber' | 'emerald';
  className?: string;
  glowSpread?: number;
}

export const GlowingEffectCard: React.FC<GlowingEffectCardProps> = ({
  children,
  accentColor = 'cyan',
  className = '',
  glowSpread = 200,
  ...props
}) => {
  const cardRef = useRef<HTMLDivElement>(null);

  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    if (!cardRef.current) return;
    const rect = cardRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    cardRef.current.style.setProperty('--glow-x', `${x}px`);
    cardRef.current.style.setProperty('--glow-y', `${y}px`);
  }, []);

  const accents = {
    cyan: {
      borderGlow: '#22D3EE',
      ambientGlow: 'rgba(6, 182, 212, 0.16)',
      cardShadow: 'rgba(6, 182, 212, 0.22)',
      hoverBorder: 'hover:border-cyan-500/50',
    },
    purple: {
      borderGlow: '#A78BFA',
      ambientGlow: 'rgba(139, 92, 246, 0.16)',
      cardShadow: 'rgba(139, 92, 246, 0.22)',
      hoverBorder: 'hover:border-purple-500/50',
    },
    rose: {
      borderGlow: '#FB7185',
      ambientGlow: 'rgba(244, 63, 94, 0.16)',
      cardShadow: 'rgba(244, 63, 94, 0.22)',
      hoverBorder: 'hover:border-rose-500/50',
    },
    amber: {
      borderGlow: '#FBBF24',
      ambientGlow: 'rgba(245, 158, 11, 0.16)',
      cardShadow: 'rgba(245, 158, 11, 0.22)',
      hoverBorder: 'hover:border-amber-500/50',
    },
    emerald: {
      borderGlow: '#34D399',
      ambientGlow: 'rgba(16, 185, 129, 0.16)',
      cardShadow: 'rgba(16, 185, 129, 0.22)',
      hoverBorder: 'hover:border-emerald-500/50',
    },
  }[accentColor];

  return (
    <div
      ref={cardRef}
      onMouseMove={handleMouseMove}
      className={cn(
        'group/glowing relative rounded-xl border border-sentinel-border bg-gradient-to-b from-[#111928] via-[#0E1523] to-[#0A0F1A] transition-all duration-300 ease-out shadow-md shadow-black/40 hover:-translate-y-1 hover:shadow-2xl overflow-hidden',
        accents.hoverBorder,
        className
      )}
      style={{
        boxShadow: `0 4px 20px -2px rgba(0, 0, 0, 0.5)`,
      }}
      {...props}
    >
      {/* 1. Specular Top Glass Rim Highlight */}
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-white/10 to-transparent z-20" aria-hidden="true" />

      {/* 2. Aceternity Glowing Effect: Mouse-Following Perimeter Border Glow */}
      <div
        className="pointer-events-none absolute -inset-[1px] rounded-xl transition-opacity duration-300 opacity-0 group-hover/glowing:opacity-100 z-10"
        style={{
          background: `radial-gradient(${glowSpread}px circle at var(--glow-x, -200px) var(--glow-y, -200px), ${accents.borderGlow}, transparent 70%)`,
          mask: 'linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)',
          maskComposite: 'exclude',
          WebkitMask: 'linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)',
          WebkitMaskComposite: 'xor',
          padding: '1.5px',
        }}
        aria-hidden="true"
      />

      {/* 3. Soft Ambient Internal Radiance under the cursor */}
      <div
        className="pointer-events-none absolute inset-0 rounded-xl transition-opacity duration-300 opacity-0 group-hover/glowing:opacity-100 z-0"
        style={{
          background: `radial-gradient(${glowSpread * 1.2}px circle at var(--glow-x, -200px) var(--glow-y, -200px), ${accents.ambientGlow}, transparent 70%)`,
        }}
        aria-hidden="true"
      />

      {/* 4. Subtle Micro Cyber Texture */}
      <div
        className="pointer-events-none absolute inset-0 z-0 opacity-0 group-hover/glowing:opacity-20 transition-opacity duration-300"
        style={{
          backgroundImage: 'radial-gradient(rgba(255, 255, 255, 0.4) 1px, transparent 1px)',
          backgroundSize: '16px 16px',
          maskImage: 'radial-gradient(180px circle at var(--glow-x, -200px) var(--glow-y, -200px), black 30%, transparent 80%)',
          WebkitMaskImage: 'radial-gradient(180px circle at var(--glow-x, -200px) var(--glow-y, -200px), black 30%, transparent 80%)',
        }}
        aria-hidden="true"
      />

      {/* 5. Card Content */}
      <div className="relative z-20 h-full flex flex-col justify-between">
        {children}
      </div>
    </div>
  );
};
