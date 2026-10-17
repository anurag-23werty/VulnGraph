import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getDecisions, approveDecision, rejectDecision } from '../api/client';
import type { Decision, DecisionState } from '../api/types';
import { VerdictChip } from './VerdictChip';

interface ActionsPanelProps {
  onSelectFinding: (vulnId: string) => void;
}

export const ActionsPanel: React.FC<ActionsPanelProps> = ({ onSelectFinding }) => {
  const queryClient = useQueryClient();
  const [activeFilter, setActiveFilter] = useState<'all' | DecisionState>('all');

  // Inline approval / rejection states
  const [confirmApproveId, setConfirmApproveId] = useState<string | null>(null);
  const [rejectingId, setRejectingId] = useState<string | null>(null);
  const [rejectReason, setRejectReason] = useState<string>('');
  const [actionError, setActionError] = useState<{ id: string; message: string } | null>(null);

  // Fetch decisions from API
  const decisionsQuery = useQuery({
    queryKey: ['decisions'],
    queryFn: () => getDecisions(),
  });

  // Approval Mutation
  const approveMutation = useMutation({
    mutationFn: (id: string) => approveDecision(id),
    onSuccess: () => {
      setConfirmApproveId(null);
      setActionError(null);
      queryClient.invalidateQueries({ queryKey: ['decisions'] });
    },
    onError: (err: Error, id: string) => {
      setActionError({ id, message: err.message });
    },
  });

  // Rejection Mutation
  const rejectMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) => rejectDecision(id, reason),
    onSuccess: () => {
      setRejectingId(null);
      setRejectReason('');
      setActionError(null);
      queryClient.invalidateQueries({ queryKey: ['decisions'] });
    },
    onError: (err: Error, vars) => {
      setActionError({ id: vars.id, message: err.message });
    },

  });

  const decisions = decisionsQuery.data?.decisions ?? [];
  const counts = decisionsQuery.data?.counts ?? {};

  // Filtered decisions list
  const filteredDecisions = decisions.filter((d) => {
    if (activeFilter === 'all') return true;
    return d.status === activeFilter;
  });

  // Helper for rendering State Chip
  const renderStateChip = (status: DecisionState) => {
    let colorVar = 'var(--state-pending-text)';
    let bgVar = 'var(--state-pending-bg)';

    if (status === 'dispatched' || status === 'approved') {
      colorVar = 'var(--state-dispatched-text)';
      bgVar = 'var(--state-dispatched-bg)';
    } else if (status === 'failed') {
      colorVar = 'var(--state-failed-text)';
      bgVar = 'var(--state-failed-bg)';
    } else if (status === 'rejected') {
      colorVar = 'var(--state-rejected-text)';
      bgVar = 'var(--state-rejected-bg)';
    }

    return (
      <span
        style={{
          fontSize: 'var(--text-micro)',
          fontWeight: 600,
          padding: '2px 6px',
          borderRadius: 'var(--radius-sm)',
          color: colorVar,
          backgroundColor: bgVar,
          border: `1px solid ${colorVar}`,
          textTransform: 'uppercase',
          letterSpacing: '0.04em',
        }}
      >
        {status}
      </span>
    );
  };

  return (
    <section id="actions" style={{ marginBottom: 'var(--space-16)' }}>
      {/* Section Header */}
      <div style={{ marginBottom: 'var(--space-6)' }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 'var(--space-3)' }}>
          <h2 style={{ fontSize: 'var(--text-title)', fontWeight: 500, letterSpacing: '-0.01em' }}>
            Human-in-the-Loop Actions & Decisions
          </h2>
          <span style={{ fontSize: 'var(--text-small)', color: 'var(--color-muted)' }}>
            AI agents stage mitigation proposals; human security leads authorize or reject with feedback.
          </span>
        </div>
      </div>

      {/* State Filter Tabs */}
      <div
        role="tablist"
        aria-label="Filter decisions by state"
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 'var(--space-2)',
          marginBottom: 'var(--space-6)',
          borderBottom: '1px solid var(--color-hairline)',
          paddingBottom: 'var(--space-3)',
        }}
      >
        {(['all', 'pending', 'dispatched', 'rejected', 'failed'] as const).map((filter) => {
          const count =
            filter === 'all'
              ? decisionsQuery.data?.total ?? 0
              : counts[filter] ?? 0;
          const isActive = activeFilter === filter;

          return (
            <button
              key={filter}
              role="tab"
              aria-selected={isActive}
              type="button"
              onClick={() => {
                setActiveFilter(filter);
                setConfirmApproveId(null);
                setRejectingId(null);
                setActionError(null);
              }}
              style={{
                background: isActive ? 'var(--color-paper-elevated)' : 'transparent',
                border: isActive ? '1px solid var(--color-ink)' : '1px solid var(--color-hairline)',
                borderRadius: 'var(--radius-sm)',
                padding: 'var(--space-1) var(--space-3)',
                fontSize: 'var(--text-small)',
                color: isActive ? 'var(--color-ink)' : 'var(--color-muted)',
                fontWeight: isActive ? 600 : 400,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                transition: 'all var(--duration-fast) ease',
              }}
            >
              <span style={{ textTransform: 'capitalize' }}>{filter}</span>
              <span
                className="tnum mono"
                style={{
                  fontSize: 'var(--text-micro)',
                  padding: '1px 5px',
                  borderRadius: '10px',
                  backgroundColor: 'var(--color-paper-subtle)',
                }}
              >
                {count}
              </span>
            </button>
          );
        })}
      </div>

      {/* Decisions List Container */}
      {decisionsQuery.isLoading ? (
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
          Loading staged decisions from FalkorDB...
        </div>
      ) : decisionsQuery.isError ? (
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
          Failed to load decisions: {(decisionsQuery.error as Error).message}
        </div>
      ) : filteredDecisions.length === 0 ? (
        <div
          style={{
            padding: 'var(--space-12)',
            textAlign: 'center',
            border: '1px solid var(--color-hairline)',
            borderRadius: 'var(--radius-lg)',
            color: 'var(--color-muted)',
            fontSize: 'var(--text-small)',
            backgroundColor: 'var(--color-paper-elevated)',
          }}
        >
          No decisions found in state '{activeFilter}'.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-4)' }}>
          {filteredDecisions.slice(0, 30).map((d: Decision) => {
            const isApproving = confirmApproveId === d.id;
            const isRejecting = rejectingId === d.id;
            const hasError = actionError?.id === d.id;

            return (
              <div
                key={d.id}
                style={{
                  border: '1px solid var(--color-hairline)',
                  borderRadius: 'var(--radius-md)',
                  backgroundColor: 'var(--color-paper-elevated)',
                  padding: 'var(--space-4)',
                }}
              >
                {/* Decision Header */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    marginBottom: 'var(--space-3)',
                    flexWrap: 'wrap',
                    gap: 'var(--space-2)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                    <code style={{ fontSize: 'var(--text-small)', fontWeight: 600 }}>{d.id}</code>
                    {renderStateChip(d.status)}
                    <VerdictChip verdict={d.verdict} size="sm" />
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-3)' }}>
                    {/* Evidence Link */}
                    {d.vuln_id && (
                      <button
                        type="button"
                        onClick={() => onSelectFinding(d.vuln_id)}
                        style={{
                          fontSize: 'var(--text-micro)',
                          color: 'var(--color-muted)',
                          background: 'none',
                          border: '1px solid var(--color-hairline)',
                          borderRadius: 'var(--radius-sm)',
                          padding: '2px 6px',
                          cursor: 'pointer',
                        }}
                      >
                        Evidence: <code>{d.vuln_id}</code> ↗
                      </button>
                    )}
                    <span className="tnum mono" style={{ fontSize: 'var(--text-small)', fontWeight: 600 }}>
                      Risk: {d.risk.toFixed(2)}
                    </span>
                  </div>
                </div>

                {/* Metadata details */}
                <div
                  style={{
                    fontSize: 'var(--text-micro)',
                    color: 'var(--color-muted)',
                    marginBottom: 'var(--space-2)',
                  }}
                >
                  Team: <strong>{d.owning_team}</strong> • Service: <strong className="mono">{d.service}</strong>
                  {d.approved_by && ` • Approved by: ${d.approved_by}`}
                  {d.rejected_by && ` • Rejected by: ${d.rejected_by}`}
                  {d.ticket_id && (
                    <span>
                      {' '}• Ticket:{' '}
                      <a
                        href={d.ticket_link || '#'}
                        target="_blank"
                        rel="noreferrer"
                        style={{ color: 'var(--color-ink)', textDecoration: 'underline' }}
                      >
                        {d.ticket_id}
                      </a>
                    </span>
                  )}
                </div>

                {/* Rationale */}
                <p
                  style={{
                    fontSize: 'var(--text-small)',
                    color: 'var(--color-ink)',
                    lineHeight: 'var(--leading-normal)',
                    marginBottom: 'var(--space-3)',
                  }}
                >
                  {d.rationale || 'Decision staged by automated triage workflow.'}
                </p>

                {/* Rejection Reason if rejected */}
                {d.rejection_reason && (
                  <div
                    style={{
                      fontSize: 'var(--text-micro)',
                      color: 'var(--color-p3)',
                      backgroundColor: 'var(--color-paper-subtle)',
                      padding: 'var(--space-2) var(--space-3)',
                      borderRadius: 'var(--radius-sm)',
                      marginBottom: 'var(--space-3)',
                    }}
                  >
                    <strong>Rejection feedback:</strong> {d.rejection_reason}
                  </div>
                )}

                {/* API Error Message */}
                {hasError && (
                  <div
                    style={{
                      fontSize: 'var(--text-micro)',
                      color: 'var(--color-p1)',
                      backgroundColor: 'var(--color-p1-bg)',
                      border: '1px solid var(--color-p1)',
                      padding: 'var(--space-2) var(--space-3)',
                      borderRadius: 'var(--radius-sm)',
                      marginBottom: 'var(--space-3)',
                    }}
                  >
                    {actionError.message}
                  </div>
                )}

                {/* Inline Action Controls for PENDING decisions (No modals!) */}
                {d.status === 'pending' && (
                  <div
                    style={{
                      borderTop: '1px solid var(--color-hairline)',
                      paddingTop: 'var(--space-3)',
                      marginTop: 'var(--space-2)',
                    }}
                  >
                    {isApproving ? (
                      /* Inline Approve Confirmation */
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 'var(--space-3)',
                          backgroundColor: 'var(--color-paper-subtle)',
                          padding: 'var(--space-2) var(--space-3)',
                          borderRadius: 'var(--radius-sm)',
                        }}
                      >
                        <span style={{ fontSize: 'var(--text-small)' }}>
                          Approve ticket dispatch for team <strong>{d.owning_team}</strong>?
                        </span>
                        <button
                          type="button"
                          disabled={approveMutation.isPending}
                          onClick={() => approveMutation.mutate(d.id)}
                          style={{
                            padding: '3px 10px',
                            fontSize: 'var(--text-micro)',
                            fontWeight: 600,
                            backgroundColor: 'var(--color-success)',
                            color: '#FFFFFF',
                            border: 0,
                            borderRadius: 'var(--radius-sm)',
                            cursor: 'pointer',
                          }}
                        >
                          {approveMutation.isPending ? 'Dispatching...' : 'Confirm Approve'}
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setConfirmApproveId(null);
                            setActionError(null);
                          }}
                          style={{
                            padding: '3px 8px',
                            fontSize: 'var(--text-micro)',
                            backgroundColor: 'transparent',
                            color: 'var(--color-muted)',
                            border: '1px solid var(--color-hairline)',
                            borderRadius: 'var(--radius-sm)',
                            cursor: 'pointer',
                          }}
                        >
                          Cancel
                        </button>
                      </div>
                    ) : isRejecting ? (
                      /* Inline Reject Confirmation Form */
                      <div
                        style={{
                          display: 'flex',
                          flexDirection: 'column',
                          gap: 'var(--space-2)',
                          backgroundColor: 'var(--color-paper-subtle)',
                          padding: 'var(--space-3)',
                          borderRadius: 'var(--radius-sm)',
                        }}
                      >
                        <label
                          htmlFor={`reject-reason-${d.id}`}
                          style={{ fontSize: 'var(--text-micro)', color: 'var(--color-muted)' }}
                        >
                          Mandatory rejection reason (used for risk formula recalibration):
                        </label>
                        <input
                          id={`reject-reason-${d.id}`}
                          type="text"
                          placeholder="e.g. Compensating firewall control in place; lower priority"
                          value={rejectReason}
                          onChange={(e) => setRejectReason(e.target.value)}
                          style={{
                            padding: 'var(--space-2) var(--space-3)',
                            fontSize: 'var(--text-small)',
                            fontFamily: 'var(--font-sans)',
                            border: '1px solid var(--color-hairline)',
                            borderRadius: 'var(--radius-sm)',
                            backgroundColor: 'var(--color-paper)',
                            color: 'var(--color-ink)',
                          }}
                        />
                        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
                          <button
                            type="button"
                            disabled={rejectReason.trim().length < 3 || rejectMutation.isPending}
                            onClick={() => rejectMutation.mutate({ id: d.id, reason: rejectReason.trim() })}
                            style={{
                              padding: '3px 10px',
                              fontSize: 'var(--text-micro)',
                              fontWeight: 600,
                              backgroundColor: 'var(--color-ink)',
                              color: 'var(--color-paper)',
                              border: 0,
                              borderRadius: 'var(--radius-sm)',
                              cursor:
                                rejectReason.trim().length < 3 || rejectMutation.isPending
                                  ? 'not-allowed'
                                  : 'pointer',
                              opacity: rejectReason.trim().length < 3 ? 0.5 : 1,
                            }}
                          >
                            {rejectMutation.isPending ? 'Rejecting...' : 'Confirm Reject'}
                          </button>
                          <button
                            type="button"
                            onClick={() => {
                              setRejectingId(null);
                              setRejectReason('');
                              setActionError(null);
                            }}
                            style={{
                              padding: '3px 8px',
                              fontSize: 'var(--text-micro)',
                              backgroundColor: 'transparent',
                              color: 'var(--color-muted)',
                              border: '1px solid var(--color-hairline)',
                              borderRadius: 'var(--radius-sm)',
                              cursor: 'pointer',
                            }}
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    ) : (
                      /* Default Inline Action Buttons */
                      <div style={{ display: 'flex', gap: 'var(--space-3)' }}>
                        <button
                          type="button"
                          onClick={() => {
                            setConfirmApproveId(d.id);
                            setRejectingId(null);
                            setActionError(null);
                          }}
                          style={{
                            padding: '4px 12px',
                            fontSize: 'var(--text-small)',
                            fontWeight: 500,
                            backgroundColor: 'var(--color-paper-elevated)',
                            color: 'var(--color-success)',
                            border: '1px solid var(--color-success)',
                            borderRadius: 'var(--radius-sm)',
                            cursor: 'pointer',
                          }}
                        >
                          ✓ Approve
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setRejectingId(d.id);
                            setConfirmApproveId(null);
                            setActionError(null);
                          }}
                          style={{
                            padding: '4px 12px',
                            fontSize: 'var(--text-small)',
                            fontWeight: 500,
                            backgroundColor: 'var(--color-paper-elevated)',
                            color: 'var(--color-muted)',
                            border: '1px solid var(--color-hairline)',
                            borderRadius: 'var(--radius-sm)',
                            cursor: 'pointer',
                          }}
                        >
                          ✕ Reject
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
};
