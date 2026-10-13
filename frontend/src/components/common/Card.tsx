import React from 'react';

interface CardProps {
  children: React.ReactNode;
  className?: string;
  header?: React.ReactNode;
  subtitle?: React.ReactNode;
  action?: React.ReactNode;
  noPadding?: boolean;
}

export const Card: React.FC<CardProps> = ({
  children,
  className = '',
  header,
  subtitle,
  action,
  noPadding = false,
}) => {
  return (
    <div
      className={`bg-[#121214] border border-zinc-800 rounded-2xl shadow-xl relative overflow-hidden transition-all duration-200 ${className}`}
    >
      {(header || action) && (
        <div className="px-5 py-4 border-b border-zinc-800 flex items-center justify-between gap-4">
          <div>
            {typeof header === 'string' ? (
              <h3 className="text-base font-semibold text-white tracking-tight">{header}</h3>
            ) : (
              header
            )}
            {subtitle && <p className="text-xs text-zinc-400 mt-0.5">{subtitle}</p>}
          </div>
          {action && <div className="flex items-center gap-2">{action}</div>}
        </div>
      )}
      <div className={noPadding ? '' : 'p-5'}>{children}</div>
    </div>
  );
};
