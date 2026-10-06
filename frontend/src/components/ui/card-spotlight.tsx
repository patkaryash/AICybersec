import React, { useRef, useState, useCallback } from 'react';
import { cn } from '@/lib/utils';

export interface CardSpotlightProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  radius?: number;
  color?: string;
  borderColor?: string;
  className?: string;
}

export const CardSpotlight: React.FC<CardSpotlightProps> = ({
  children,
  radius = 240,
  color = 'rgba(29, 78, 216, 0.06)',
  borderColor = 'rgba(29, 78, 216, 0.25)',
  className = '',
  ...props
}) => {
  const cardRef = useRef<HTMLDivElement>(null);
  const [isHovered, setIsHovered] = useState(false);
  const [mousePos, setMousePos] = useState<{ x: number; y: number }>({ x: 0, y: 0 });

  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLDivElement>) => {
    if (!cardRef.current) return;
    const rect = cardRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    setMousePos({ x, y });
  }, []);

  const handleMouseEnter = useCallback(() => {
    setIsHovered(true);
  }, []);

  const handleMouseLeave = useCallback(() => {
    setIsHovered(false);
  }, []);

  return (
    <div
      ref={cardRef}
      onMouseMove={handleMouseMove}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      className={cn(
        'group/spotlight relative rounded-xl border border-[#D8E1EB] bg-white transition-all duration-300 overflow-hidden shadow-card hover:shadow-card-hover',
        className
      )}
      {...props}
    >
      {/* 1. Dynamic Radial Spotlight Gradient Layer */}
      <div
        className="pointer-events-none absolute -inset-px rounded-xl transition-opacity duration-300 z-0"
        style={{
          opacity: isHovered ? 1 : 0,
          background: `radial-gradient(${radius}px circle at ${mousePos.x}px ${mousePos.y}px, ${color}, transparent 80%)`,
        }}
        aria-hidden="true"
      />

      {/* 2. Interactive Illuminated Border Highlight */}
      <div
        className="pointer-events-none absolute -inset-px rounded-xl transition-opacity duration-300 z-0"
        style={{
          opacity: isHovered ? 1 : 0,
          border: `1px solid ${borderColor}`,
          maskImage: `radial-gradient(${radius * 0.75}px circle at ${mousePos.x}px ${mousePos.y}px, black 30%, transparent 100%)`,
          WebkitMaskImage: `radial-gradient(${radius * 0.75}px circle at ${mousePos.x}px ${mousePos.y}px, black 30%, transparent 100%)`,
        }}
        aria-hidden="true"
      />

      {/* 3. Subtle Cyber Matrix Dot Texture revealed under spotlight */}
      <div
        className="pointer-events-none absolute inset-0 transition-opacity duration-300 z-0 opacity-0 group-hover/spotlight:opacity-20"
        style={{
          backgroundImage: `radial-gradient(rgba(255, 255, 255, 0.4) 1px, transparent 1px)`,
          backgroundSize: '16px 16px',
          maskImage: `radial-gradient(${radius * 0.9}px circle at ${mousePos.x}px ${mousePos.y}px, black 20%, transparent 80%)`,
          WebkitMaskImage: `radial-gradient(${radius * 0.9}px circle at ${mousePos.x}px ${mousePos.y}px, black 20%, transparent 80%)`,
        }}
        aria-hidden="true"
      />

      {/* 4. Card Content (Always interactive, above effects) */}
      <div className="relative z-10 h-full flex flex-col justify-between">
        {children}
      </div>
    </div>
  );
};
