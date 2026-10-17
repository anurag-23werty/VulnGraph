import {
  FindingsResponseSchema,
  GraphPathResponseSchema,
  TraceResponseSchema,
  ToolsResponseSchema,
  ToolRunResponseSchema,
  DecisionsResponseSchema,
  DecisionActionResponseSchema,
  EvalLatestResponseSchema,
  type FindingsResponse,
  type GraphPathResponse,
  type TraceResponse,
  type ToolsResponse,
  type ToolRunResponse,
  type DecisionsResponse,
  type DecisionActionResponse,
  type EvalLatestResponse,
} from './types';

export class ApiError extends Error {
  constructor(
    public status: number,
    public statusText: string,
    public detail: string,
    public requestId?: string
  ) {
    super(`API Error ${status} (${statusText}): ${detail}`);
    this.name = 'ApiError';
  }
}

async function requestJson<T>(
  url: string,
  options?: RequestInit,
  schema?: { parse: (val: unknown) => T }
): Promise<T> {
  const resp = await fetch(url, {
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    ...options,
  });

  const requestId = resp.headers.get('X-Request-ID') || undefined;

  if (!resp.ok) {
    let errorDetail = resp.statusText;
    try {
      const errJson = await resp.json();
      errorDetail = errJson.detail || errJson.error || JSON.stringify(errJson);
    } catch {
      // ignore json parse error
    }
    throw new ApiError(resp.status, resp.statusText, errorDetail, requestId);
  }

  const rawJson = await resp.json();

  if (schema) {
    try {
      return schema.parse(rawJson);
    } catch (zodErr) {
      console.error(`Zod validation failed for endpoint ${url}:`, zodErr);
      throw new Error(`Data validation failure from ${url}: ${(zodErr as Error).message}`);
    }
  }

  return rawJson as T;
}

// ==============================================================================
// Typed API Endpoints
// ==============================================================================

export async function getFindings(limit = 100): Promise<FindingsResponse> {
  return requestJson<FindingsResponse>(`/findings?limit=${limit}`, undefined, FindingsResponseSchema);
}

export async function getGraphPath(vulnId?: string): Promise<GraphPathResponse> {
  const query = vulnId ? `?vuln_id=${encodeURIComponent(vulnId)}` : '';
  return requestJson<GraphPathResponse>(`/graph/path${query}`, undefined, GraphPathResponseSchema);
}

export async function getTrace(vulnId: string): Promise<TraceResponse> {
  return requestJson<TraceResponse>(`/trace/${encodeURIComponent(vulnId)}`, undefined, TraceResponseSchema);
}

export async function getTools(): Promise<ToolsResponse> {
  return requestJson<ToolsResponse>('/tools', undefined, ToolsResponseSchema);
}

export async function runTool(name: string, args: Record<string, any>): Promise<ToolRunResponse> {
  return requestJson<ToolRunResponse>(
    `/tools/${encodeURIComponent(name)}/run`,
    {
      method: 'POST',
      body: JSON.stringify({ args }),
    },
    ToolRunResponseSchema
  );
}

export async function getDecisions(statusFilter?: string): Promise<DecisionsResponse> {
  const query = statusFilter ? `?status_filter=${encodeURIComponent(statusFilter)}` : '';
  return requestJson<DecisionsResponse>(`/decisions${query}`, undefined, DecisionsResponseSchema);
}

export async function approveDecision(decisionId: string): Promise<DecisionActionResponse> {
  return requestJson<DecisionActionResponse>(
    `/approve/${encodeURIComponent(decisionId)}`,
    {
      method: 'POST',
    },
    DecisionActionResponseSchema
  );
}

export async function rejectDecision(decisionId: string, reason: string): Promise<DecisionActionResponse> {
  return requestJson<DecisionActionResponse>(
    `/reject/${encodeURIComponent(decisionId)}`,
    {
      method: 'POST',
      body: JSON.stringify({ reason }),
    },
    DecisionActionResponseSchema
  );
}

export async function getLatestEval(): Promise<EvalLatestResponse> {
  return requestJson<EvalLatestResponse>('/eval/latest', undefined, EvalLatestResponseSchema);
}
