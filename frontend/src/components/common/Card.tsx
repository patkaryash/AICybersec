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
      className={`bg-sentinel-surface border border-sentinel-border rounded-xl shadow-lg relative overflow-hidden transition-all duration-200 ${className}`}
    >
      {(header || action) && (
        <div className="px-5 py-4 border-b border-sentinel-border flex items-center justify-between gap-4">
          <div>
            {typeof header === 'string' ? (
              <h3 className="text-base font-semibold text-sentinel-text tracking-tight">{header}</h3>
            ) : (
              header
            )}
            {subtitle && <p className="text-xs text-sentinel-muted mt-0.5">{subtitle}</p>}
          </div>
          {action && <div className="flex items-center gap-2">{action}</div>}
        </div>
      )}
      <div className={noPadding ? '' : 'p-5'}>{children}</div>
    </div>
  );
};
