import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { getTools, runTool } from '../api/client';
import type { Tool } from '../api/types';

interface ToolExecutionState {
  loading: boolean;
  durationMs?: number;
  result?: any;
  error?: string;
}

export const ToolsReference: React.FC = () => {
  const toolsQuery = useQuery({
    queryKey: ['tools'],
    queryFn: getTools,
  });

  const tools = toolsQuery.data?.tools ?? [];

  // Local state for arguments and execution result per tool
  const [toolArgs, setToolArgs] = useState<Record<string, Record<string, any>>>({});
  const [executionState, setExecutionState] = useState<Record<string, ToolExecutionState>>({});
  const [copiedCypher, setCopiedCypher] = useState<string | null>(null);

  // Initialize argument defaults
  const getArgsForTool = (tool: Tool) => {
    if (toolArgs[tool.name]) return toolArgs[tool.name];
    const initial: Record<string, any> = {};
    Object.entries(tool.parameters.properties).forEach(([key, prop]) => {
      initial[key] = prop.default !== undefined ? prop.default : '';
    });
    return initial;
  };

  const handleArgChange = (toolName: string, paramKey: string, value: any) => {
    setToolArgs((prev) => ({
      ...prev,
      [toolName]: {
        ...(prev[toolName] || {}),
        [paramKey]: value,
      },
    }));
  };

  const handleExecute = async (tool: Tool) => {
    const args = getArgsForTool(tool);
    setExecutionState((prev) => ({
      ...prev,
      [tool.name]: { loading: true, error: undefined },
    }));

    try {
      const resp = await runTool(tool.name, args);
      setExecutionState((prev) => ({
        ...prev,
        [tool.name]: {
          loading: false,
          durationMs: resp.duration_ms,
          result: resp.result,
        },
      }));
    } catch (err) {
      setExecutionState((prev) => ({
        ...prev,
        [tool.name]: {
          loading: false,
          error: (err as Error).message,
        },
      }));
    }
  };

  const handleCopyCypher = (toolName: string, cypher: string) => {
    navigator.clipboard.writeText(cypher);
    setCopiedCypher(toolName);
    setTimeout(() => setCopiedCypher(null), 1800);
  };

  return (
    <section id="tools" style={{ marginBottom: 'var(--space-16)' }}>
      {/* Section Header */}
      <div style={{ marginBottom: 'var(--space-6)' }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-3)' }}>
          <h2 style={{ fontSize: 'var(--text-title)', fontWeight: 500, letterSpacing: '-0.01em' }}>
            Control Reference: MCP Read Tools
          </h2>
          <span style={{ fontSize: 'var(--text-small)', color: 'var(--color-muted)' }}>
            Allowlisted read-only graph algorithms and Cypher queries. Staged mutations require human gate.
          </span>
        </div>
      </div>

      {toolsQuery.isLoading ? (
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
          Loading MCP read tools catalog...
        </div>
      ) : toolsQuery.isError ? (
        <div
          style={{
            padding: 'var(--space-6)',
            border: '1px solid var(--color-p1)',
            borderRadius: 'var(--radius-lg)',
            backgroundColor: 'var(--color-p1-bg)',
            color: 'var(--color-p1)',
            fontSize: 'var(--text-small)',
          }}
        >
          Failed to load tools: {(toolsQuery.error as Error).message}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-6)' }}>
          {tools.map((tool) => {
            const currentArgs = getArgsForTool(tool);
            const state = executionState[tool.name] || { loading: false };
            const isCopied = copiedCypher === tool.name;

            return (
              <div
                key={tool.name}
                style={{
                  border: '1px solid var(--color-hairline)',
                  borderRadius: 'var(--radius-lg)',
                  backgroundColor: 'var(--color-paper-elevated)',
                  overflow: 'hidden',
                }}
              >
                {/* Tool Header */}
                <div
                  style={{
                    padding: 'var(--space-4)',
                    borderBottom: '1px solid var(--color-hairline)',
                    backgroundColor: 'var(--color-paper)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                    <code style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--color-ink)' }}>
                      {tool.name}
                    </code>
                    <span
                      style={{
                        fontSize: 'var(--text-micro)',
                        color: 'var(--color-muted)',
                        padding: '1px 6px',
                        borderRadius: 'var(--radius-sm)',
                        border: '1px solid var(--color-hairline)',
                        backgroundColor: 'var(--color-paper-subtle)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.04em',
                      }}
                    >
                      READ ONLY
                    </span>
                  </div>
                  <span style={{ fontSize: 'var(--text-micro)', color: 'var(--color-muted)' }}>
                    FalkorDB ro_query
                  </span>
                </div>

                {/* Tool Body */}
                <div style={{ padding: 'var(--space-5)' }}>
                  <p
                    style={{
                      fontSize: 'var(--text-small)',
                      color: 'var(--color-muted)',
                      lineHeight: 'var(--leading-normal)',
                      marginBottom: 'var(--space-4)',
                    }}
                  >
                    {tool.description}
                  </p>

                  {/* Cypher Query Box */}
                  <div style={{ marginBottom: 'var(--space-4)' }}>
                    <div
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        marginBottom: 'var(--space-2)',
                      }}
                    >
                      <span style={{ fontSize: 'var(--text-micro)', fontWeight: 600, color: 'var(--color-muted)' }}>
                        Cypher Query Definition
                      </span>
                      <button
                        type="button"
                        onClick={() => handleCopyCypher(tool.name, tool.cypher)}
                        style={{
                          fontSize: 'var(--text-micro)',
                          color: 'var(--color-muted)',
                          background: 'none',
                          border: '1px solid var(--color-hairline)',
                          borderRadius: 'var(--radius-sm)',
                          padding: '1px 7px',
                          cursor: 'pointer',
                        }}
                      >
                        {isCopied ? '✓ Copied' : 'Copy Cypher'}
                      </button>
                    </div>
                    <pre
                      style={{
                        backgroundColor: 'var(--color-paper-subtle)',
                        padding: 'var(--space-3) var(--space-4)',
                        borderRadius: 'var(--radius-md)',
                        fontSize: 'var(--text-micro)',
                        lineHeight: 'var(--leading-snug)',
                        overflowX: 'auto',
                        color: 'var(--color-ink)',
                        border: '1px solid var(--color-hairline)',
                      }}
                    >
                      {tool.cypher}
                    </pre>
                  </div>

                  {/* Parameter Form & Run Action */}
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      handleExecute(tool);
                    }}
                    style={{
                      display: 'flex',
                      flexWrap: 'wrap',
                      alignItems: 'flex-end',
                      gap: 'var(--space-3)',
                      marginBottom: 'var(--space-4)',
                    }}
                  >
                    {Object.entries(tool.parameters.properties).map(([paramName, paramProp]) => (
                      <div key={paramName} style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-1)' }}>
                        <label
                          htmlFor={`${tool.name}-${paramName}`}
                          style={{ fontSize: 'var(--text-micro)', color: 'var(--color-muted)' }}
                        >
                          {paramName} {paramProp.description && `(${paramProp.description})`}
                        </label>
                        <input
                          id={`${tool.name}-${paramName}`}
                          type={paramProp.type === 'integer' ? 'number' : 'text'}
                          value={currentArgs[paramName] ?? ''}
                          onChange={(e) =>
                            handleArgChange(
                              tool.name,
                              paramName,
                              paramProp.type === 'integer' ? parseInt(e.target.value, 10) || 0 : e.target.value
                            )
                          }
                          style={{
                            padding: 'var(--space-2) var(--space-3)',
                            fontSize: 'var(--text-small)',
                            fontFamily: 'var(--font-mono)',
                            border: '1px solid var(--color-hairline)',
                            borderRadius: 'var(--radius-md)',
                            backgroundColor: 'var(--color-paper)',
                            color: 'var(--color-ink)',
                            minWidth: '220px',
                          }}
                        />
                      </div>
                    ))}

                    <button
                      type="submit"
                      disabled={state.loading}
                      style={{
                        padding: 'var(--space-2) var(--space-4)',
                        fontSize: 'var(--text-small)',
                        fontWeight: 500,
                        backgroundColor: 'var(--color-ink)',
                        color: 'var(--color-paper)',
                        border: 0,
                        borderRadius: 'var(--radius-md)',
                        cursor: state.loading ? 'wait' : 'pointer',
                        transition: 'opacity var(--duration-fast) ease',
                        opacity: state.loading ? 0.7 : 1,
                        height: '35px',
                      }}
                    >
                      {state.loading ? 'Running...' : 'Run tool'}
                    </button>
                  </form>

                  {/* Execution Result Area */}
                  {state.error ? (
                    <div
                      style={{
                        padding: 'var(--space-3)',
                        borderRadius: 'var(--radius-md)',
                        backgroundColor: 'var(--color-p1-bg)',
                        border: '1px solid var(--color-p1)',
                        color: 'var(--color-p1)',
                        fontSize: 'var(--text-small)',
                      }}
                    >
                      Execution failed: {state.error}
                    </div>
                  ) : state.result ? (
                    <div
                      style={{
                        border: '1px solid var(--color-hairline)',
                        borderRadius: 'var(--radius-md)',
                        backgroundColor: 'var(--color-paper-subtle)',
                        overflow: 'hidden',
                      }}
                    >
                      <div
                        style={{
                          padding: 'var(--space-2) var(--space-3)',
                          borderBottom: '1px solid var(--color-hairline)',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          fontSize: 'var(--text-micro)',
                          color: 'var(--color-muted)',
                        }}
                      >
                        <span>Output Result</span>
                        {state.durationMs !== undefined && (
                          <span className="tnum mono">Duration: {state.durationMs.toFixed(1)}ms</span>
                        )}
                      </div>
                      <pre
                        style={{
                          padding: 'var(--space-3) var(--space-4)',
                          fontSize: 'var(--text-micro)',
                          lineHeight: 'var(--leading-snug)',
                          color: 'var(--color-ink)',
                          overflowX: 'auto',
                          maxHeight: '240px',
                        }}
                      >
                        {JSON.stringify(state.result, null, 2)}
                      </pre>
                    </div>
                  ) : null}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
};
