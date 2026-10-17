import React from 'react';

interface VerdictChipProps {
  verdict: string;
  size?: 'sm' | 'md';
}

export const VerdictChip: React.FC<VerdictChipProps> = ({ verdict, size = 'sm' }) => {
  const norm = verdict.toLowerCase().replace('-', '_');

  let label = 'Deprioritize';
  let colorVar = 'var(--color-p3)';
  let bgVar = 'var(--color-p3-bg)';

  if (norm.includes('patch') || norm.includes('immediate') || norm === 'critical') {
    label = 'Patch immediately';
    colorVar = 'var(--color-p1)';
    bgVar = 'var(--color-p1-bg)';
  } else if (norm.includes('schedule') || norm.includes('maintenance') || norm === 'high') {
    label = 'Schedule maintenance';
    colorVar = 'var(--color-p2)';
    bgVar = 'var(--color-p2-bg)';
  } else {
    label = 'Deprioritize';
    colorVar = 'var(--color-p3)';
    bgVar = 'var(--color-p3-bg)';
  }

  const isSmall = size === 'sm';

  return (
    <span
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        padding: isSmall ? '1px 6px' : '3px 8px',
        fontSize: isSmall ? 'var(--text-micro)' : 'var(--text-small)',
        fontWeight: 500,
        borderRadius: 'var(--radius-sm)',
        color: colorVar,
        backgroundColor: bgVar,
        border: `1px solid ${colorVar}`,
        whiteSpace: 'nowrap',
        lineHeight: 1.3,
      }}
    >
      {label}
    </span>
  );
};
