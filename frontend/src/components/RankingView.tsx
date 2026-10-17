import React, { useState, useEffect, useRef, useMemo } from 'react';
import { motion } from 'motion/react';
import type { Finding } from '../api/types';
import { computeClientRisk, getVerdictFromScore, type WhatIfParams } from '../lib/formula';
import { VerdictChip } from './VerdictChip';

interface RankingViewProps {
  findings: Finding[];
  whatIfParams: WhatIfParams;
  selectedVulnId: string | null;
  onSelectFinding: (vulnId: string) => void;
}

interface RankedItem {
  finding: Finding;
  score: number;
  rank: number;
  verdict: string;
}

export const RankingView: React.FC<RankingViewProps> = ({
  findings,
  whatIfParams,
  selectedVulnId,
  onSelectFinding,
}) => {
  const [hoveredVulnId, setHoveredVulnId] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const leftRowsRef = useRef<Map<string, HTMLDivElement>>(new Map());
  const rightRowsRef = useRef<Map<string, HTMLDivElement>>(new Map());
  const [connectors, setConnectors] = useState<Array<{ id: string; y1: number; y2: number; delta: number }>>([]);

  // Virtualization threshold: if > 100 rows, cap at 100
  const isVirtual = findings.length > 100;
  const activeFindings = useMemo(() => {
    return isVirtual ? findings.slice(0, 100) : findings;
  }, [findings, isVirtual]);

  // 1. Column 1: "CVSS only" (sorted by CVSS descending)
  const cvssRanked: RankedItem[] = useMemo(() => {
    const sorted = [...activeFindings].sort((a, b) => {
      if (b.cvss !== a.cvss) return b.cvss - a.cvss;
      return a.id.localeCompare(b.id);
    });
    return sorted.map((finding, idx) => {
      const naiveVerdict =
        finding.cvss >= 9.0 ? 'patch_immediately' : finding.cvss >= 7.0 ? 'schedule_maintenance' : 'deprioritize';
      return {
        finding,
        score: finding.cvss,
        rank: idx + 1,
        verdict: naiveVerdict,
      };
    });
  }, [activeFindings]);

  // 2. Column 2: "Graph-aware" (sorted by live what-if reweighted score descending)
  const graphRanked: RankedItem[] = useMemo(() => {
    const withScores = activeFindings.map((finding) => {
      const score = computeClientRisk(finding.components, whatIfParams, finding.is_kev);
      const verdict = getVerdictFromScore(score);
      return { finding, score, verdict };
    });

    const sorted = withScores.sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      if (b.finding.cvss !== a.finding.cvss) return b.finding.cvss - a.finding.cvss;
      return a.finding.id.localeCompare(b.finding.id);
    });

    return sorted.map((item, idx) => ({
      finding: item.finding,
      score: item.score,
      rank: idx + 1,
      verdict: item.verdict,
    }));
  }, [activeFindings, whatIfParams]);

  // Map finding ID to ranks for delta calculation
  const rankDeltaMap = useMemo(() => {
    const cvssMap = new Map<string, number>();
    cvssRanked.forEach((r) => cvssMap.set(r.finding.id, r.rank));

    const deltaMap = new Map<string, { cvssRank: number; graphRank: number; delta: number }>();
    graphRanked.forEach((g) => {
      const cRank = cvssMap.get(g.finding.id) ?? g.rank;
      // delta = cvssRank - graphRank
      // positive: elevated priority (e.g. from #6 to #1 -> +5)
      // negative: lowered priority (e.g. from #1 to #4 -> -3)
      const delta = cRank - g.rank;
      deltaMap.set(g.finding.id, { cvssRank: cRank, graphRank: g.rank, delta });
    });
    return deltaMap;
  }, [cvssRanked, graphRanked]);

  // Measure row coordinates to draw connecting SVG lines
  useEffect(() => {
    const updateConnectors = () => {
      if (!containerRef.current) return;
      const containerRect = containerRef.current.getBoundingClientRect();
      const lines: Array<{ id: string; y1: number; y2: number; delta: number }> = [];

      graphRanked.forEach((item) => {
        const id = item.finding.id;
        const leftEl = leftRowsRef.current.get(id);
        const rightEl = rightRowsRef.current.get(id);
        const deltaInfo = rankDeltaMap.get(id);

        if (leftEl && rightEl) {
          const leftRect = leftEl.getBoundingClientRect();
          const rightRect = rightEl.getBoundingClientRect();
          const y1 = leftRect.top - containerRect.top + leftRect.height / 2;
          const y2 = rightRect.top - containerRect.top + rightRect.height / 2;
          lines.push({
            id,
            y1,
            y2,
            delta: deltaInfo?.delta ?? 0,
          });
        }
      });
      setConnectors(lines);
    };

    // Update on render and window resize
    const timeout = setTimeout(updateConnectors, 40);
    window.addEventListener('resize', updateConnectors);
    return () => {
      clearTimeout(timeout);
      window.removeEventListener('resize', updateConnectors);
    };
  }, [cvssRanked, graphRanked, rankDeltaMap]);

  return (
    <section id="ranking" style={{ marginBottom: 'var(--space-16)' }}>
      {/* Section Header */}
      <div style={{ marginBottom: 'var(--space-6)' }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-3)' }}>
          <h2 style={{ fontSize: 'var(--text-title)', fontWeight: 500, letterSpacing: '-0.01em' }}>
            Vulnerability Prioritization
          </h2>
          <span style={{ fontSize: 'var(--text-small)', color: 'var(--color-muted)' }}>
            Comparing naive CVSS ranking against FalkorDB graph-grounded exploitability.
          </span>
        </div>
        {isVirtual && (
          <div style={{ fontSize: 'var(--text-micro)', color: 'var(--color-muted)', marginTop: 'var(--space-1)' }}>
            Showing top 100 rows (virtualized)
          </div>
        )}
      </div>

      {/* Dual Column Layout with Connecting SVG Bridge */}
      <div
        ref={containerRef}
        style={{
          position: 'relative',
          display: 'grid',
          gridTemplateColumns: 'minmax(320px, 1fr) 56px minmax(320px, 1fr)',
          gap: 0,
          border: '1px solid var(--color-hairline)',
          borderRadius: 'var(--radius-lg)',
          backgroundColor: 'var(--color-paper-elevated)',
          overflow: 'hidden',
        }}
      >
        {/* SVG Connector Overlay Bridge */}
        <div
          aria-hidden="true"
          style={{
            gridColumn: '2',
            position: 'relative',
            width: '56px',
            pointerEvents: 'none',
          }}
        >
          <svg
            style={{
              position: 'absolute',
              top: 0,
              left: 0,
              width: '100%',
              height: '100%',
              overflow: 'visible',
            }}
          >
            {connectors.map((c) => {
              const isHighlighted = hoveredVulnId === c.id || selectedVulnId === c.id;
              const isPromoted = c.delta > 0;
              const isDemoted = c.delta < 0;

              // Color based on status and hover
              let strokeColor = 'var(--color-hairline-strong)';
              let strokeWidth = 1;
              let strokeOpacity = 0.5;

              if (isHighlighted) {
                strokeColor = isPromoted ? 'var(--color-p1)' : isDemoted ? 'var(--color-p3)' : 'var(--color-ink)';
                strokeWidth = 2;
                strokeOpacity = 1;
              }

              // Cubic bezier curve across the 56px channel
              const pathD = `M 0,${c.y1} C 28,${c.y1} 28,${c.y2} 56,${c.y2}`;

              return (
                <path
                  key={`line-${c.id}`}
                  d={pathD}
                  fill="none"
                  stroke={strokeColor}
                  strokeWidth={strokeWidth}
                  strokeOpacity={strokeOpacity}
                  style={{
                    transition: 'stroke 150ms ease, stroke-width 150ms ease, stroke-opacity 150ms ease',
                  }}
                />
              );
            })}
          </svg>
        </div>

        {/* COLUMN 1: CVSS ONLY */}
        <div style={{ gridColumn: '1', borderRight: '1px solid var(--color-hairline)' }}>
          {/* Column Header */}
          <div
            style={{
              padding: 'var(--space-3) var(--space-4)',
              borderBottom: '1px solid var(--color-hairline)',
              backgroundColor: 'var(--color-paper-subtle)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <span style={{ fontSize: 'var(--text-small)', fontWeight: 600 }}>CVSS only</span>
              <span style={{ fontSize: 'var(--text-micro)', color: 'var(--color-muted)', marginLeft: '6px' }}>
                (Traditional Scanner)
              </span>
            </div>
            <span style={{ fontSize: 'var(--text-micro)', color: 'var(--color-muted)' }}>Score</span>
          </div>

          {/* Rows List */}
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {cvssRanked.map((item) => {
              const id = item.finding.id;
              const isHovered = hoveredVulnId === id;
              const isSelected = selectedVulnId === id;

              return (
                <div
                  key={`cvss-${id}`}
                  ref={(el) => {
                    if (el) leftRowsRef.current.set(id, el);
                    else leftRowsRef.current.delete(id);
                  }}
                  role="button"
                  tabIndex={0}
                  aria-pressed={isSelected}
                  onClick={() => onSelectFinding(id)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onSelectFinding(id);
                    }
                  }}
                  onMouseEnter={() => setHoveredVulnId(id)}
                  onMouseLeave={() => setHoveredVulnId(null)}
                  style={{
                    padding: 'var(--space-3) var(--space-4)',
                    borderBottom: '1px solid var(--color-hairline)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    cursor: 'pointer',
                    backgroundColor: isSelected
                      ? 'var(--color-paper-subtle)'
                      : isHovered
                      ? 'var(--color-paper)'
                      : 'transparent',
                    outline: 'none',
                    transition: 'background-color var(--duration-fast) ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', minWidth: 0 }}>
                    <span
                      className="tnum mono"
                      style={{
                        fontSize: 'var(--text-micro)',
                        color: 'var(--color-muted)',
                        width: '20px',
                        textAlign: 'right',
                        flexShrink: 0,
                      }}
                    >
                      #{item.rank}
                    </span>

                    <div style={{ minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <code
                          style={{
                            fontSize: 'var(--text-small)',
                            fontWeight: isSelected ? 600 : 400,
                            color: 'var(--color-ink)',
                          }}
                        >
                          {id}
                        </code>
                        {item.finding.is_sleeper && (
                          <span
                            style={{
                              fontSize: '10px',
                              padding: '0 4px',
                              borderRadius: '2px',
                              backgroundColor: 'var(--color-p1-bg)',
                              color: 'var(--color-p1)',
                            }}
                          >
                            sleeper
                          </span>
                        )}
                        {item.finding.is_decoy && (
                          <span
                            style={{
                              fontSize: '10px',
                              padding: '0 4px',
                              borderRadius: '2px',
                              backgroundColor: 'var(--color-p3-bg)',
                              color: 'var(--color-p3)',
                            }}
                          >
                            decoy
                          </span>
                        )}
                      </div>
                      <div
                        style={{
                          fontSize: 'var(--text-micro)',
                          color: 'var(--color-muted)',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          marginTop: '2px',
                        }}
                      >
                        {item.finding.package} • {item.finding.service}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexShrink: 0 }}>
                    <span
                      className="tnum mono"
                      style={{
                        fontSize: 'var(--text-small)',
                        fontWeight: 600,
                        color: 'var(--color-ink)',
                      }}
                    >
                      {item.score.toFixed(1)}
                    </span>
                    <VerdictChip verdict={item.verdict} size="sm" />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* COLUMN 2: GRAPH-AWARE (Spring animated reordering) */}
        <div style={{ gridColumn: '3', borderLeft: '1px solid var(--color-hairline)' }}>
          {/* Column Header */}
          <div
            style={{
              padding: 'var(--space-3) var(--space-4)',
              borderBottom: '1px solid var(--color-hairline)',
              backgroundColor: 'var(--color-paper-subtle)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <div>
              <span style={{ fontSize: 'var(--text-small)', fontWeight: 600 }}>Graph-aware</span>
              <span style={{ fontSize: 'var(--text-micro)', color: 'var(--color-muted)', marginLeft: '6px' }}>
                (VulnGraph Triage)
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)' }}>
              <span style={{ fontSize: 'var(--text-micro)', color: 'var(--color-muted)' }}>Delta</span>
              <span style={{ fontSize: 'var(--text-micro)', color: 'var(--color-muted)' }}>Score</span>
            </div>
          </div>

          {/* Rows List with Spring Animation */}
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {graphRanked.map((item) => {
              const id = item.finding.id;
              const isHovered = hoveredVulnId === id;
              const isSelected = selectedVulnId === id;
              const deltaInfo = rankDeltaMap.get(id);
              const delta = deltaInfo?.delta ?? 0;

              return (
                <motion.div
                  key={`graph-${id}`}
                  layout="position"
                  transition={{
                    type: 'spring',
                    stiffness: 350,
                    damping: 28,
                    mass: 0.8,
                  }}
                  ref={(el) => {
                    if (el) rightRowsRef.current.set(id, el);
                    else rightRowsRef.current.delete(id);
                  }}
                  role="button"
                  tabIndex={0}
                  aria-pressed={isSelected}
                  onClick={() => onSelectFinding(id)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onSelectFinding(id);
                    }
                  }}
                  onMouseEnter={() => setHoveredVulnId(id)}
                  onMouseLeave={() => setHoveredVulnId(null)}
                  style={{
                    padding: 'var(--space-3) var(--space-4)',
                    borderBottom: '1px solid var(--color-hairline)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    cursor: 'pointer',
                    backgroundColor: isSelected
                      ? 'var(--color-paper-subtle)'
                      : isHovered
                      ? 'var(--color-paper)'
                      : 'transparent',
                    outline: 'none',
                    transition: 'background-color var(--duration-fast) ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', minWidth: 0 }}>
                    <span
                      className="tnum mono"
                      style={{
                        fontSize: 'var(--text-micro)',
                        color: 'var(--color-muted)',
                        width: '20px',
                        textAlign: 'right',
                        flexShrink: 0,
                      }}
                    >
                      #{item.rank}
                    </span>

                    <div style={{ minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                        <code
                          style={{
                            fontSize: 'var(--text-small)',
                            fontWeight: isSelected ? 600 : 400,
                            color: 'var(--color-ink)',
                          }}
                        >
                          {id}
                        </code>
                        {item.finding.is_sleeper && (
                          <span
                            style={{
                              fontSize: '10px',
                              padding: '0 4px',
                              borderRadius: '2px',
                              backgroundColor: 'var(--color-p1-bg)',
                              color: 'var(--color-p1)',
                            }}
                          >
                            Crown Jewel
                          </span>
                        )}
                        {item.finding.is_decoy && (
                          <span
                            style={{
                              fontSize: '10px',
                              padding: '0 4px',
                              borderRadius: '2px',
                              backgroundColor: 'var(--color-p3-bg)',
                              color: 'var(--color-p3)',
                            }}
                          >
                            Isolated
                          </span>
                        )}
                      </div>
                      <div
                        style={{
                          fontSize: 'var(--text-micro)',
                          color: 'var(--color-muted)',
                          whiteSpace: 'nowrap',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          marginTop: '2px',
                        }}
                      >
                        {item.finding.package} • {item.finding.service}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexShrink: 0 }}>
                    {/* Rank Delta Badge */}
                    <span
                      className="tnum mono"
                      style={{
                        fontSize: 'var(--text-micro)',
                        fontWeight: 600,
                        width: '38px',
                        textAlign: 'right',
                        color:
                          delta > 0
                            ? 'var(--color-p1)'
                            : delta < 0
                            ? 'var(--color-p3)'
                            : 'var(--color-muted)',
                      }}
                    >
                      {delta > 0 ? `+${delta}` : delta === 0 ? '0' : `${delta}`}
                    </span>

                    {/* Calculated Graph Score */}
                    <span
                      className="tnum mono"
                      style={{
                        fontSize: 'var(--text-small)',
                        fontWeight: 600,
                        width: '40px',
                        textAlign: 'right',
                        color:
                          item.score >= 7.0
                            ? 'var(--color-p1)'
                            : item.score >= 4.0
                            ? 'var(--color-p2)'
                            : 'var(--color-p3)',
                      }}
                    >
                      {item.score.toFixed(2)}
                    </span>

                    <VerdictChip verdict={item.verdict} size="sm" />
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>
      </div>
    </section>
  );
};
