import React from 'react';
import { DEFAULT_WHAT_IF_PARAMS, type WhatIfParams } from '../lib/formula';

interface WhatIfControlsProps {
  params: WhatIfParams;
  onChange: (updated: WhatIfParams) => void;
}

export const WhatIfControls: React.FC<WhatIfControlsProps> = ({ params, onChange }) => {
  const isModified =
    params.exposureFloor !== DEFAULT_WHAT_IF_PARAMS.exposureFloor ||
    params.sensitivityWeight !== DEFAULT_WHAT_IF_PARAMS.sensitivityWeight ||
    params.blastWeight !== DEFAULT_WHAT_IF_PARAMS.blastWeight ||
    params.includeKev !== DEFAULT_WHAT_IF_PARAMS.includeKev;

  const handleReset = () => {
    onChange(DEFAULT_WHAT_IF_PARAMS);
  };

  return (
    <div
      style={{
        border: '1px solid var(--color-hairline)',
        borderRadius: 'var(--radius-lg)',
        padding: 'var(--space-5)',
        backgroundColor: 'var(--color-paper-elevated)',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 'var(--space-4)',
          borderBottom: '1px solid var(--color-hairline)',
          paddingBottom: 'var(--space-3)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
          <span style={{ fontSize: 'var(--text-small)', fontWeight: 600, color: 'var(--color-ink)' }}>
            What-if live recalibration
          </span>
          <span
            style={{
              fontSize: 'var(--text-micro)',
              color: 'var(--color-muted)',
              fontStyle: 'italic',
            }}
          >
            what-if; server score unchanged
          </span>
        </div>
        {isModified && (
          <button
            type="button"
            onClick={handleReset}
            style={{
              fontSize: 'var(--text-micro)',
              color: 'var(--color-muted)',
              background: 'none',
              border: '1px solid var(--color-hairline)',
              borderRadius: 'var(--radius-sm)',
              padding: '2px 8px',
              cursor: 'pointer',
              transition: 'var(--transition-fast)',
            }}
            onMouseOver={(e) => {
              e.currentTarget.style.color = 'var(--color-ink)';
              e.currentTarget.style.borderColor = 'var(--color-ink)';
            }}
            onMouseOut={(e) => {
              e.currentTarget.style.color = 'var(--color-muted)';
              e.currentTarget.style.borderColor = 'var(--color-hairline)';
            }}
          >
            Reset
          </button>
        )}
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: 'var(--space-5)',
          alignItems: 'center',
        }}
      >
        {/* Exposure Floor Slider */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 'var(--space-1)' }}>
            <label htmlFor="exposure-floor-input" style={{ fontSize: 'var(--text-small)', color: 'var(--color-ink)' }}>
              Exposure floor
            </label>
            <span className="tnum mono" style={{ fontSize: 'var(--text-small)', color: 'var(--color-muted)' }}>
              {params.exposureFloor.toFixed(2)}
            </span>
          </div>
          <input
            id="exposure-floor-input"
            type="range"
            min="0.0"
            max="0.50"
            step="0.05"
            value={params.exposureFloor}
            onChange={(e) => onChange({ ...params, exposureFloor: parseFloat(e.target.value) })}
            aria-label="Exposure floor slider"
            style={{ width: '100%', accentColor: 'var(--color-ink)', cursor: 'pointer' }}
          />
        </div>

        {/* Sensitivity Weight Slider */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 'var(--space-1)' }}>
            <label htmlFor="sensitivity-weight-input" style={{ fontSize: 'var(--text-small)', color: 'var(--color-ink)' }}>
              Sensitivity weight
            </label>
            <span className="tnum mono" style={{ fontSize: 'var(--text-small)', color: 'var(--color-muted)' }}>
              {params.sensitivityWeight.toFixed(2)}x
            </span>
          </div>
          <input
            id="sensitivity-weight-input"
            type="range"
            min="0.5"
            max="2.0"
            step="0.1"
            value={params.sensitivityWeight}
            onChange={(e) => onChange({ ...params, sensitivityWeight: parseFloat(e.target.value) })}
            aria-label="Sensitivity weight slider"
            style={{ width: '100%', accentColor: 'var(--color-ink)', cursor: 'pointer' }}
          />
        </div>

        {/* Blast-radius Weight Slider */}
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 'var(--space-1)' }}>
            <label htmlFor="blast-weight-input" style={{ fontSize: 'var(--text-small)', color: 'var(--color-ink)' }}>
              Blast-radius weight
            </label>
            <span className="tnum mono" style={{ fontSize: 'var(--text-small)', color: 'var(--color-muted)' }}>
              {params.blastWeight.toFixed(2)}x
            </span>
          </div>
          <input
            id="blast-weight-input"
            type="range"
            min="0.5"
            max="2.0"
            step="0.1"
            value={params.blastWeight}
            onChange={(e) => onChange({ ...params, blastWeight: parseFloat(e.target.value) })}
            aria-label="Blast-radius weight slider"
            style={{ width: '100%', accentColor: 'var(--color-ink)', cursor: 'pointer' }}
          />
        </div>

        {/* Include KEV Toggle */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', paddingTop: '14px' }}>
          <input
            id="include-kev-checkbox"
            type="checkbox"
            checked={params.includeKev}
            onChange={(e) => onChange({ ...params, includeKev: e.target.checked })}
            style={{ width: '16px', height: '16px', accentColor: 'var(--color-ink)', cursor: 'pointer' }}
          />
          <label htmlFor="include-kev-checkbox" style={{ fontSize: 'var(--text-small)', color: 'var(--color-ink)', cursor: 'pointer' }}>
            Include KEV
          </label>
        </div>
      </div>
    </div>
  );
};
