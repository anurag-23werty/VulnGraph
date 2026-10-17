import { useState, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getFindings, getTools, getDecisions, getLatestEval } from './api/client';
import { DEFAULT_WHAT_IF_PARAMS, type WhatIfParams } from './lib/formula';
import { WhatIfControls } from './components/WhatIfControls';
import { RankingView } from './components/RankingView';
import { EvidencePanel } from './components/EvidencePanel';
import { ToolsReference } from './components/ToolsReference';
import { ActionsPanel } from './components/ActionsPanel';
import { MethodSection } from './components/MethodSection';

export default function App() {



  const [viewMode, setViewMode] = useState<'analyst' | 'trace'>('analyst');
  const [whatIfParams, setWhatIfParams] = useState<WhatIfParams>(DEFAULT_WHAT_IF_PARAMS);
  const [selectedVulnId, setSelectedVulnId] = useState<string | null>(null);

  // Queries using TanStack Query with runtime Zod response validation
  const findingsQuery = useQuery({
    queryKey: ['findings'],
    queryFn: () => getFindings(100),
  });

  const toolsQuery = useQuery({ queryKey: ['tools'], queryFn: getTools });
  const decisionsQuery = useQuery({ queryKey: ['decisions'], queryFn: () => getDecisions() });
  const evalQuery = useQuery({ queryKey: ['eval', 'latest'], queryFn: getLatestEval });

  const findings = useMemo(() => findingsQuery.data?.findings ?? [], [findingsQuery.data]);

  // Auto-select first sleeper if none selected
  const activeVulnId = selectedVulnId || (findings.length > 0 ? findings[0].id : null);
  const selectedFinding = useMemo(
    () => findings.find((f) => f.id === activeVulnId) || null,
    [findings, activeVulnId]
  );


  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* 0. Top Bar: Slim Sticky Nav with Scroll-Spy & Trace Toggle */}
      <header
        style={{
          position: 'sticky',
          top: 0,
          zIndex: 100,
          backgroundColor: 'var(--color-paper)',
          borderBottom: '1px solid var(--color-hairline)',
          height: '48px',
          display: 'flex',
          alignItems: 'center',
          padding: '0 var(--space-6)',
        }}
      >
        <div
          style={{
            maxWidth: 'var(--page-max-width)',
            width: '100%',
            margin: '0 auto',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            <span style={{ fontWeight: 600, fontSize: 'var(--text-body)', letterSpacing: '-0.01em' }}>
              VulnGraph
            </span>
            <span
              className="tnum mono"
              style={{
                fontSize: 'var(--text-micro)',
                color: 'var(--color-muted)',
                padding: '2px 6px',
                border: '1px solid var(--color-hairline)',
                borderRadius: 'var(--radius-sm)',
              }}
            >
              v1.2.0
            </span>
          </div>

          <nav style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)' }}>
            <a
              href="#hero"
              style={{ color: 'var(--color-muted)', textDecoration: 'none', fontSize: 'var(--text-small)' }}
            >
              Overview
            </a>
            <a
              href="#ranking"
              style={{ color: 'var(--color-ink)', fontWeight: 500, textDecoration: 'none', fontSize: 'var(--text-small)' }}
            >
              Ranking
            </a>
            <a
              href="#evidence"
              style={{ color: 'var(--color-muted)', textDecoration: 'none', fontSize: 'var(--text-small)' }}
            >
              Evidence
            </a>
            <a
              href="#tools"
              style={{ color: 'var(--color-muted)', textDecoration: 'none', fontSize: 'var(--text-small)' }}
            >
              Tools
            </a>
            <a
              href="#actions"
              style={{ color: 'var(--color-muted)', textDecoration: 'none', fontSize: 'var(--text-small)' }}
            >
              Actions
            </a>
            <a
              href="#method"
              style={{ color: 'var(--color-muted)', textDecoration: 'none', fontSize: 'var(--text-small)' }}
            >
              Method
            </a>
          </nav>

          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
            {/* Analyst / Trace Mode Toggle */}
            <div
              role="group"
              aria-label="View mode toggle"
              style={{
                display: 'inline-flex',
                border: '1px solid var(--color-hairline)',
                borderRadius: 'var(--radius-md)',
                padding: '2px',
                backgroundColor: 'var(--color-paper-subtle)',
              }}
            >
              <button
                type="button"
                onClick={() => setViewMode('analyst')}
                aria-pressed={viewMode === 'analyst'}
                style={{
                  padding: '3px 8px',
                  fontSize: 'var(--text-micro)',
                  fontWeight: viewMode === 'analyst' ? 600 : 400,
                  backgroundColor: viewMode === 'analyst' ? 'var(--color-paper-elevated)' : 'transparent',
                  color: viewMode === 'analyst' ? 'var(--color-ink)' : 'var(--color-muted)',
                  border: 0,
                  borderRadius: 'var(--radius-sm)',
                  cursor: 'pointer',
                  transition: 'background-color var(--duration-fast) ease',
                }}
              >
                Analyst
              </button>
              <button
                type="button"
                onClick={() => setViewMode('trace')}
                aria-pressed={viewMode === 'trace'}
                style={{
                  padding: '3px 8px',
                  fontSize: 'var(--text-micro)',
                  fontWeight: viewMode === 'trace' ? 600 : 400,
                  backgroundColor: viewMode === 'trace' ? 'var(--color-paper-elevated)' : 'transparent',
                  color: viewMode === 'trace' ? 'var(--color-ink)' : 'var(--color-muted)',
                  border: 0,
                  borderRadius: 'var(--radius-sm)',
                  cursor: 'pointer',
                  transition: 'background-color var(--duration-fast) ease',
                }}
              >
                Trace
              </button>
            </div>

            <a
              href="https://github.com/anurag-23werty/VulnGraph.git"
              target="_blank"
              rel="noreferrer"
              style={{
                fontSize: 'var(--text-small)',
                color: 'var(--color-muted)',
                textDecoration: 'none',
              }}
            >
              GitHub ↗
            </a>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main
        style={{
          maxWidth: 'var(--page-max-width)',
          width: '100%',
          margin: '0 auto',
          padding: 'var(--space-12) var(--space-6)',
          flex: 1,
        }}
      >
        {/* 1. Hero Section */}
        <section id="hero" style={{ marginBottom: 'var(--space-12)' }}>
          <h1
            style={{
              fontSize: 'var(--text-headline)',
              fontWeight: 300,
              lineHeight: 'var(--leading-tight)',
              letterSpacing: '-0.025em',
              color: 'var(--color-ink)',
              maxWidth: '850px',
              marginBottom: 'var(--space-4)',
            }}
          >
            Ranked by whether an attacker can reach sensitive data, not by CVSS alone.
          </h1>

          <p
            style={{
              fontSize: 'var(--text-body)',
              color: 'var(--color-muted)',
              maxWidth: '680px',
              marginBottom: 'var(--space-8)',
              lineHeight: 'var(--leading-normal)',
            }}
          >
            Traditional vulnerability management evaluates static CVSS severity. VulnGraph uses native FalkorDB graph algorithms to trace dependency paths from internet ingress down to crown-jewel datastores.
          </p>

          {/* Inline What-If Controls */}
          <WhatIfControls params={whatIfParams} onChange={setWhatIfParams} />
        </section>

        {/* 2. Ranking Section: CVSS Only vs Graph-Aware with Spring Reordering & SVG Connectors */}
        {findingsQuery.isLoading ? (
          <div
            style={{
              padding: 'var(--space-12)',
              textAlign: 'center',
              border: '1px solid var(--color-hairline)',
              borderRadius: 'var(--radius-lg)',
              color: 'var(--color-muted)',
              fontSize: 'var(--text-small)',
            }}
          >
            Loading vulnerability findings from FalkorDB graph...
          </div>
        ) : findingsQuery.isError ? (
          <div
            style={{
              padding: 'var(--space-8)',
              border: '1px solid var(--color-p1)',
              borderRadius: 'var(--radius-lg)',
              backgroundColor: 'var(--color-p1-bg)',
              color: 'var(--color-p1)',
              fontSize: 'var(--text-small)',
            }}
          >
            Failed to load findings: {(findingsQuery.error as Error).message}
          </div>
        ) : (
          <RankingView
            findings={findings}
            whatIfParams={whatIfParams}
            selectedVulnId={activeVulnId}
            onSelectFinding={(id) => {
              setSelectedVulnId(id);
              const el = document.getElementById('evidence');
              if (el) el.scrollIntoView({ behavior: 'smooth' });
            }}
          />
        )}

        {/* 3. Evidence Panel: Force Graph & Step Trace beside each other */}
        {activeVulnId && (
          <EvidencePanel vulnId={activeVulnId} finding={selectedFinding} />
        )}

        {/* 4. Tools Control Reference */}
        <ToolsReference />

        {/* 5. Actions: Decisions grouped by state with inline confirm */}
        <ActionsPanel
          onSelectFinding={(id) => {
            setSelectedVulnId(id);
            const el = document.getElementById('evidence');
            if (el) el.scrollIntoView({ behavior: 'smooth' });
          }}
        />

        {/* 6. Method: Ablation table, KEV validation, disclaimers */}
        <MethodSection />





        {/* Raw Trace Mode Drawer (Shows raw tool calls and JSON everywhere when Trace is active) */}
        {viewMode === 'trace' && (
          <section
            style={{
              marginTop: 'var(--space-8)',
              border: '1px solid var(--color-hairline)',
              borderRadius: 'var(--radius-lg)',
              padding: 'var(--space-6)',
              backgroundColor: 'var(--color-paper-elevated)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 'var(--space-3)' }}>
              <span style={{ fontSize: 'var(--text-small)', fontWeight: 600 }}>Raw Trace & Tool Inspection</span>
              <span className="mono tnum" style={{ fontSize: 'var(--text-micro)', color: 'var(--color-muted)' }}>
                Active Finding: {activeVulnId ?? 'None'}
              </span>
            </div>
            <pre
              style={{
                backgroundColor: 'var(--color-paper-subtle)',
                padding: 'var(--space-4)',
                borderRadius: 'var(--radius-md)',
                overflowX: 'auto',
                maxHeight: '300px',
                fontSize: 'var(--text-micro)',
              }}
            >
              {JSON.stringify(
                {
                  activeVulnId,
                  whatIfParams,
                  findingsTotal: findings.length,
                  toolsCatalog: toolsQuery.data?.tools?.map((t) => t.name),
                  decisionsSummary: decisionsQuery.data?.counts,
                  evalBenchmark: evalQuery.data?.planted_scenarios?.inversion_success,
                },
                null,
                2
              )}
            </pre>
          </section>
        )}
      </main>

      {/* Footer */}
      <footer
        style={{
          borderTop: '1px solid var(--color-hairline)',
          padding: 'var(--space-6)',
          backgroundColor: 'var(--color-paper)',
          fontSize: 'var(--text-micro)',
          color: 'var(--color-muted)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          maxWidth: 'var(--page-max-width)',
          width: '100%',
          margin: '0 auto',
        }}
      >
        <div>VulnGraph v1.2.0 • FalkorDB Graph Hacks Track 01</div>
        <div>Typographic design • Tabular figures • Contrast ≥ 4.5:1</div>
      </footer>
    </div>
  );
}
