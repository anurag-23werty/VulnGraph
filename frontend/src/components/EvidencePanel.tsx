import React, { useState, useRef, useEffect, useMemo } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { useQuery } from '@tanstack/react-query';
import { getGraphPath, getTrace } from '../api/client';
import type { Finding } from '../api/types';
import { VerdictChip } from './VerdictChip';

interface EvidencePanelProps {
  vulnId: string;
  finding?: Finding | null;
}

export const EvidencePanel: React.FC<EvidencePanelProps> = ({ vulnId, finding }) => {
  const [activeTab, setActiveTab] = useState<'summary' | 'cypher' | 'json'>('summary');
  const [copiedTab, setCopiedTab] = useState<string | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);
  const [graphDimensions, setGraphDimensions] = useState<{ width: number; height: number }>({
    width: 540,
    height: 480,
  });

  // Fetch graph topology and execution trace for the selected finding
  const graphQuery = useQuery({
    queryKey: ['graph', vulnId],
    queryFn: () => getGraphPath(vulnId),
    enabled: !!vulnId,
  });

  const traceQuery = useQuery({
    queryKey: ['trace', vulnId],
    queryFn: () => getTrace(vulnId),
    enabled: !!vulnId,
  });

  // Track container dimensions via ResizeObserver
  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (entry) {
        setGraphDimensions({
          width: Math.max(300, Math.floor(entry.contentRect.width)),
          height: 480,
        });
      }
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  // Format graph data for react-force-graph-2d
  const graphData = useMemo(() => {
    if (!graphQuery.data) return { nodes: [], links: [] };
    return {
      nodes: graphQuery.data.nodes.map((n) => ({ ...n })),
      links: graphQuery.data.links.map((l) => ({ ...l })),
    };
  }, [graphQuery.data]);

  // Aggregate authentic Cypher queries from trace
  const cypherQueriesText = useMemo(() => {
    if (!traceQuery.data?.steps) return '// No cypher queries found for this finding.';
    const lines: string[] = [];
    traceQuery.data.steps.forEach((s) => {
      if (s.cypher) {
        lines.push(`// --- Step ${s.step}: ${s.name} ---`);
        lines.push(s.cypher.trim());
        lines.push('');
      }
    });
    return lines.join('\n');
  }, [traceQuery.data]);

  // Raw JSON dump combining finding, graph, and trace
  const rawJsonText = useMemo(() => {
    return JSON.stringify(
      {
        finding: finding ?? null,
        graphSummary: {
          vuln_id: vulnId,
          highlighted_node_count: graphQuery.data?.highlighted_node_count ?? 0,
          nodes_count: graphQuery.data?.nodes.length ?? 0,
          links_count: graphQuery.data?.links.length ?? 0,
        },
        trace: traceQuery.data ?? null,
      },
      null,
      2
    );
  }, [finding, vulnId, graphQuery.data, traceQuery.data]);

  // Copy handler with visual feedback
  const handleCopy = (text: string, tabKey: string) => {
    navigator.clipboard.writeText(text);
    setCopiedTab(tabKey);
    setTimeout(() => setCopiedTab(null), 1800);
  };

  return (
    <section id="evidence" style={{ marginBottom: 'var(--space-16)' }}>
      {/* Section Header */}
      <div style={{ marginBottom: 'var(--space-6)' }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-3)' }}>
          <h2 style={{ fontSize: 'var(--text-title)', fontWeight: 500, letterSpacing: '-0.01em' }}>
            Evidence & Attack Path
          </h2>
          <span style={{ fontSize: 'var(--text-small)', color: 'var(--color-muted)' }}>
            Selected finding: <code style={{ color: 'var(--color-ink)' }}>{vulnId}</code>
          </span>
        </div>
      </div>

      {/* Two-Pane Evidence Card */}
      <div
        style={{
          border: '1px solid var(--color-hairline)',
          borderRadius: 'var(--radius-lg)',
          backgroundColor: 'var(--color-paper-elevated)',
          display: 'grid',
          gridTemplateColumns: 'minmax(320px, 1.15fr) minmax(320px, 1fr)',
          overflow: 'hidden',
        }}
      >
        {/* LEFT PANE: Interactive Force Graph */}
        <div
          ref={containerRef}
          style={{
            position: 'relative',
            borderRight: '1px solid var(--color-hairline)',
            backgroundColor: 'var(--color-paper-subtle)',
            minHeight: '480px',
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          {/* Graph Header / Legend */}
          <div
            style={{
              padding: 'var(--space-3) var(--space-4)',
              borderBottom: '1px solid var(--color-hairline)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              backgroundColor: 'var(--color-paper)',
              fontSize: 'var(--text-micro)',
              color: 'var(--color-muted)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: 'var(--color-p1)' }} />
                Attack Path
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#06b6d4' }} />
                Service Ingress
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: '#f59e0b' }} />
                DataStore
              </span>
            </div>
            <span>
              {graphQuery.isLoading
                ? 'Loading graph...'
                : `${graphQuery.data?.highlighted_node_count ?? 0} highlighted path nodes`}
            </span>
          </div>

          {/* Canvas Rendering */}
          <div style={{ flex: 1, position: 'relative' }}>
            {graphQuery.isLoading ? (
              <div
                style={{
                  position: 'absolute',
                  inset: 0,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--color-muted)',
                  fontSize: 'var(--text-small)',
                }}
              >
                Rendering attack path topology...
              </div>
            ) : graphData.nodes.length === 0 ? (
              <div
                style={{
                  position: 'absolute',
                  inset: 0,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: 'var(--color-muted)',
                  fontSize: 'var(--text-small)',
                }}
              >
                No graph topology data found for {vulnId}.
              </div>
            ) : (
              <ForceGraph2D
                width={graphDimensions.width}
                height={graphDimensions.height}
                graphData={graphData}
                nodeRelSize={6}
                nodeCanvasObject={(node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
                  const isHl = Boolean(node.highlight);
                  const isVuln = node.label === 'Vuln';
                  const isDataStore = node.label === 'DataStore';

                  const radius = isHl ? (isVuln || isDataStore ? 8 : 6.5) : 4.5;
                  const label = node.name || String(node.id);

                  // Colors: Highlighted vs Dimmed
                  let fillColor = '#6B6A66';
                  let strokeColor = '#E4E2DC';

                  if (isHl) {
                    if (isVuln) {
                      fillColor = '#B3261E'; // P1
                      strokeColor = '#141413';
                    } else if (isDataStore) {
                      fillColor = '#9A6700'; // Crown jewel
                      strokeColor = '#141413';
                    } else if (node.internet_facing) {
                      fillColor = '#06b6d4'; // Ingress
                      strokeColor = '#141413';
                    } else {
                      fillColor = '#1F6F43'; // Internal
                      strokeColor = '#141413';
                    }
                  } else {
                    fillColor = 'rgba(107, 106, 102, 0.28)'; // Dimmed
                    strokeColor = 'rgba(228, 226, 220, 0.4)';
                  }

                  // Draw Node Circle
                  ctx.beginPath();
                  ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI, false);
                  ctx.fillStyle = fillColor;
                  ctx.fill();
                  ctx.lineWidth = isHl ? 1.5 : 0.8;
                  ctx.strokeStyle = strokeColor;
                  ctx.stroke();

                  // Text Label for highlighted nodes or close zoom
                  if (isHl || globalScale > 1.8) {
                    const fontSize = Math.max(9, Math.min(12, 11 / globalScale));
                    ctx.font = `${isHl ? '600' : '400'} ${fontSize}px Geist Variable, sans-serif`;
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'top';
                    ctx.fillStyle = isHl ? '#141413' : '#6B6A66';
                    ctx.fillText(label, node.x, node.y + radius + 3);
                  }
                }}
                linkColor={(link: any) =>
                  link.highlight ? '#B3261E' : 'rgba(209, 206, 191, 0.45)'
                }
                linkWidth={(link: any) => (link.highlight ? 2 : 0.8)}
                linkDirectionalArrowLength={link => link.highlight ? 4 : 2}
                linkDirectionalArrowRelPos={1}
                cooldownTicks={60}
                onEngineStop={() => {
                  // zoom to fit once stabilized
                }}
              />
            )}
          </div>
        </div>

        {/* RIGHT PANE: Steps, Details & Tabs */}
        <div style={{ display: 'flex', flexDirection: 'column', backgroundColor: 'var(--color-paper-elevated)' }}>
          {/* Tab Navigation Header */}
          <div
            style={{
              padding: 'var(--space-2) var(--space-4)',
              borderBottom: '1px solid var(--color-hairline)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              backgroundColor: 'var(--color-paper)',
            }}
          >
            <div role="tablist" aria-label="Evidence tabs" style={{ display: 'flex', gap: 'var(--space-2)' }}>
              {(['summary', 'cypher', 'json'] as const).map((tab) => {
                const isActive = activeTab === tab;
                const title = tab === 'summary' ? 'Summary' : tab === 'cypher' ? 'Cypher' : 'Raw JSON';
                return (
                  <button
                    key={tab}
                    role="tab"
                    id={`tab-${tab}`}
                    aria-selected={isActive}
                    aria-controls={`panel-${tab}`}
                    type="button"
                    onClick={() => setActiveTab(tab)}
                    style={{
                      background: 'none',
                      border: 0,
                      borderBottom: isActive ? '2px solid var(--color-ink)' : '2px solid transparent',
                      padding: 'var(--space-2) var(--space-3)',
                      fontSize: 'var(--text-small)',
                      fontWeight: isActive ? 600 : 400,
                      color: isActive ? 'var(--color-ink)' : 'var(--color-muted)',
                      cursor: 'pointer',
                      transition: 'color var(--duration-fast) ease',
                    }}
                  >
                    {title}
                  </button>
                );
              })}
            </div>

            {/* Quick Copy Button */}
            <button
              type="button"
              onClick={() => {
                const textToCopy =
                  activeTab === 'summary'
                    ? finding
                      ? `${finding.id} (${finding.package}): Risk ${finding.risk}/10, Verdict: ${finding.verdict}`
                      : vulnId
                    : activeTab === 'cypher'
                    ? cypherQueriesText
                    : rawJsonText;
                handleCopy(textToCopy, activeTab);
              }}
              style={{
                fontSize: 'var(--text-micro)',
                color: 'var(--color-muted)',
                background: 'none',
                border: '1px solid var(--color-hairline)',
                borderRadius: 'var(--radius-sm)',
                padding: '2px 8px',
                cursor: 'pointer',
              }}
            >
              {copiedTab === activeTab ? '✓ Copied' : 'Copy'}
            </button>
          </div>

          {/* Tab Content Panel */}
          <div style={{ padding: 'var(--space-5)', flex: 1, overflowY: 'auto', maxHeight: '430px' }}>
            {/* TAB 1: SUMMARY & STEP LIST */}
            {activeTab === 'summary' && (
              <div role="tabpanel" id="panel-summary" aria-labelledby="tab-summary">
                {finding ? (
                  <div style={{ marginBottom: 'var(--space-5)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-2)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                        <code style={{ fontSize: '1.0625rem', fontWeight: 600 }}>{finding.id}</code>
                        <VerdictChip verdict={finding.verdict} size="sm" />
                      </div>
                      <div className="tnum mono" style={{ fontSize: 'var(--text-small)' }}>
                        Score: <strong>{finding.risk.toFixed(2)}</strong> / 10.0 (CVSS: {finding.cvss.toFixed(1)})
                      </div>
                    </div>

                    <p style={{ fontSize: 'var(--text-small)', color: 'var(--color-muted)', lineHeight: 'var(--leading-normal)', marginBottom: 'var(--space-3)' }}>
                      {finding.summary || 'Vulnerability affects package dependency in production topology.'}
                    </p>

                    <div
                      style={{
                        display: 'grid',
                        gridTemplateColumns: '1fr 1fr',
                        gap: 'var(--space-2)',
                        fontSize: 'var(--text-micro)',
                        backgroundColor: 'var(--color-paper-subtle)',
                        padding: 'var(--space-3)',
                        borderRadius: 'var(--radius-md)',
                        marginBottom: 'var(--space-4)',
                      }}
                    >
                      <div><strong>Package:</strong> {finding.package}</div>
                      <div><strong>Service:</strong> {finding.service}</div>
                      <div><strong>Owner:</strong> {finding.owner}</div>
                      <div><strong>Fix version:</strong> {finding.fix_version || 'N/A'}</div>
                    </div>
                  </div>
                ) : (
                  <div style={{ fontSize: 'var(--text-small)', color: 'var(--color-muted)', marginBottom: 'var(--space-4)' }}>
                    Finding ID: <code>{vulnId}</code>
                  </div>
                )}

                {/* Ordered Step List */}
                <div>
                  <h4 style={{ fontSize: 'var(--text-small)', fontWeight: 600, marginBottom: 'var(--space-3)' }}>
                    Agent Execution Steps & Graph Traversals
                  </h4>

                  {traceQuery.isLoading ? (
                    <div style={{ fontSize: 'var(--text-micro)', color: 'var(--color-muted)' }}>
                      Loading verification trace...
                    </div>
                  ) : !traceQuery.data?.steps || traceQuery.data.steps.length === 0 ? (
                    <div style={{ fontSize: 'var(--text-micro)', color: 'var(--color-muted)' }}>
                      No trace steps recorded for {vulnId}.
                    </div>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
                      {traceQuery.data.steps.map((s) => (
                        <div
                          key={`step-${s.step}`}
                          style={{
                            border: '1px solid var(--color-hairline)',
                            borderRadius: 'var(--radius-md)',
                            padding: 'var(--space-3)',
                            fontSize: 'var(--text-small)',
                            backgroundColor: 'var(--color-paper)',
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-2)' }}>
                              <span className="tnum mono" style={{ fontSize: 'var(--text-micro)', color: 'var(--color-muted)', width: '20px' }}>
                                #{s.step}
                              </span>
                              <code style={{ fontSize: 'var(--text-small)', fontWeight: 600 }}>
                                {s.name}
                              </code>
                            </div>
                            <span className="tnum mono" style={{ fontSize: 'var(--text-micro)', color: 'var(--color-muted)' }}>
                              {s.duration_ms.toFixed(1)}ms
                            </span>
                          </div>
                          <div style={{ fontSize: 'var(--text-micro)', color: 'var(--color-muted)', marginTop: '2px', paddingLeft: '28px' }}>
                            {s.result_summary}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TAB 2: AUTHENTIC CYPHER QUERIES */}
            {activeTab === 'cypher' && (
              <div role="tabpanel" id="panel-cypher" aria-labelledby="tab-cypher">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-2)' }}>
                  <span style={{ fontSize: 'var(--text-micro)', color: 'var(--color-muted)' }}>
                    FalkorDB Cypher Traversals & PageRank Procedures
                  </span>
                </div>
                <pre
                  style={{
                    backgroundColor: 'var(--color-paper-subtle)',
                    padding: 'var(--space-4)',
                    borderRadius: 'var(--radius-md)',
                    overflowX: 'auto',
                    fontSize: 'var(--text-micro)',
                    lineHeight: 'var(--leading-snug)',
                    color: 'var(--color-ink)',
                    border: '1px solid var(--color-hairline)',
                  }}
                >
                  {cypherQueriesText}
                </pre>
              </div>
            )}

            {/* TAB 3: RAW JSON */}
            {activeTab === 'json' && (
              <div role="tabpanel" id="panel-json" aria-labelledby="tab-json">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 'var(--space-2)' }}>
                  <span style={{ fontSize: 'var(--text-micro)', color: 'var(--color-muted)' }}>
                    Validated API Data Payload
                  </span>
                </div>
                <pre
                  style={{
                    backgroundColor: 'var(--color-paper-subtle)',
                    padding: 'var(--space-4)',
                    borderRadius: 'var(--radius-md)',
                    overflowX: 'auto',
                    fontSize: 'var(--text-micro)',
                    lineHeight: 'var(--leading-snug)',
                    color: 'var(--color-ink)',
                    border: '1px solid var(--color-hairline)',
                  }}
                >
                  {rawJsonText}
                </pre>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
};
