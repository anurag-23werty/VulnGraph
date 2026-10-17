import { z } from 'zod';

// ==============================================================================
// 1. Findings Schemas
// ==============================================================================

export const FindingComponentsSchema = z.object({
  cvss_norm: z.number(),
  exposure: z.number(),
  sensitivity: z.number(),
  blast: z.number(),
  effective_exposure: z.number().optional(),
  critical_path_multiplier: z.number().optional(),
});

export const FindingSchema = z.object({
  id: z.string(),
  vuln_id: z.string().optional(),
  package: z.string(),
  service: z.string(),
  services: z.array(z.string()).default([]),
  owner: z.string(),
  verdict: z.string(),
  risk: z.number(),
  confidence: z.number(),
  formula_version: z.string(),
  cvss: z.number(),
  summary: z.string().optional(),
  fix_version: z.string().nullable().optional(),
  category: z.string().optional(),
  is_sleeper: z.boolean().default(false),
  is_decoy: z.boolean().default(false),
  is_kev: z.boolean().default(false),
  components: FindingComponentsSchema,
});

export const FindingsResponseSchema = z.object({
  count: z.number(),
  findings: z.array(FindingSchema),
});

export type Finding = z.infer<typeof FindingSchema>;
export type FindingComponents = z.infer<typeof FindingComponentsSchema>;
export type FindingsResponse = z.infer<typeof FindingsResponseSchema>;

// ==============================================================================
// 2. Evidence Graph Schemas
// ==============================================================================

export const GraphNodeSchema = z.object({
  id: z.union([z.string(), z.number()]),
  label: z.string(),
  name: z.string(),
  group: z.string(),
  color: z.string().optional(),
  val: z.number().optional(),
  highlight: z.boolean().default(false),
  internet_facing: z.boolean().nullable().optional(),
  sensitivity: z.string().nullable().optional(),
  cvss: z.number().nullable().optional(),
});

export const GraphLinkSchema = z.object({
  source: z.union([z.string(), z.number(), z.record(z.any())]),
  target: z.union([z.string(), z.number(), z.record(z.any())]),
  type: z.string().optional(),
  highlight: z.boolean().default(false),
  color: z.string().optional(),
});

export const GraphPathResponseSchema = z.object({
  vuln_id: z.string().nullable().optional(),
  nodes: z.array(GraphNodeSchema),
  links: z.array(GraphLinkSchema),
  highlighted_node_count: z.number().default(0),
});

export type GraphNode = z.infer<typeof GraphNodeSchema>;
export type GraphLink = z.infer<typeof GraphLinkSchema>;
export type GraphPathResponse = z.infer<typeof GraphPathResponseSchema>;

// ==============================================================================
// 3. Execution Trace Schemas
// ==============================================================================

export const TraceStepSchema = z.object({
  step: z.number(),
  name: z.string(),
  args: z.record(z.any()),
  duration_ms: z.number(),
  result_summary: z.string(),
  cypher: z.string().optional(),
});

export const TraceResponseSchema = z.object({
  vuln_id: z.string(),
  total_steps: z.number(),
  steps: z.array(TraceStepSchema),
});

export type TraceStep = z.infer<typeof TraceStepSchema>;
export type TraceResponse = z.infer<typeof TraceResponseSchema>;

// ==============================================================================
// 4. Control Reference Tools Schemas
// ==============================================================================

export const ToolParameterPropertySchema = z.object({
  type: z.string(),
  description: z.string().optional(),
  default: z.any().optional(),
});

export const ToolParametersSchema = z.object({
  type: z.string(),
  properties: z.record(ToolParameterPropertySchema),
  required: z.array(z.string()).default([]),
});

export const ToolSchema = z.object({
  name: z.string(),
  description: z.string(),
  cypher: z.string(),
  parameters: ToolParametersSchema,
});

export const ToolsResponseSchema = z.object({
  count: z.number(),
  tools: z.array(ToolSchema),
});

export const ToolRunResponseSchema = z.object({
  tool: z.string(),
  args: z.record(z.any()),
  result: z.any(),
  duration_ms: z.number(),
});

export type Tool = z.infer<typeof ToolSchema>;
export type ToolsResponse = z.infer<typeof ToolsResponseSchema>;
export type ToolRunResponse = z.infer<typeof ToolRunResponseSchema>;

// ==============================================================================
// 5. Decisions / Human-in-the-Loop Schemas
// ==============================================================================

export const DecisionStateEnum = z.enum(['pending', 'dispatched', 'failed', 'rejected', 'approved']);
export type DecisionState = z.infer<typeof DecisionStateEnum>;

export const DecisionSchema = z.object({
  id: z.string(),
  status: DecisionStateEnum,
  verdict: z.string(),
  action_type: z.string().optional(),
  rationale: z.string().default(''),
  risk: z.number(),
  confidence: z.number(),
  approved_by: z.string().nullable().optional(),
  approved_at: z.number().nullable().optional(),
  ticket_id: z.string().nullable().optional(),
  ticket_link: z.string().nullable().optional(),
  rejected_by: z.string().nullable().optional(),
  rejected_at: z.number().nullable().optional(),
  rejection_reason: z.string().nullable().optional(),
  error: z.string().nullable().optional(),
  failed_at: z.number().nullable().optional(),
  timestamp: z.number(),
  vuln_id: z.string().default(''),
  service: z.string().default(''),
  owning_team: z.string().default('SecOps'),
});

export const DecisionsResponseSchema = z.object({
  total: z.number(),
  counts: z.record(z.number()),
  decisions: z.array(DecisionSchema),
});

export const DecisionActionResponseSchema = z.object({
  status: z.string(),
  decision_id: z.string(),
  message: z.string().optional(),
  ticket_id: z.string().optional(),
  ticket_link: z.string().optional(),
  approved_by: z.string().optional(),
  rejected_by: z.string().optional(),
  reason: z.string().optional(),
});

export type Decision = z.infer<typeof DecisionSchema>;
export type DecisionsResponse = z.infer<typeof DecisionsResponseSchema>;
export type DecisionActionResponse = z.infer<typeof DecisionActionResponseSchema>;

// ==============================================================================
// 6. Evaluation / Methodology Schemas
// ==============================================================================

export const AblationRowSchema = z.object({
  vuln_id: z.string(),
  category: z.string(),
  cvss_raw: z.number(),
  stage1_cvss: z.number(),
  stage2_exposure: z.number(),
  stage3_sensitivity: z.number(),
  stage4_full_graph: z.number(),
});

export const AblationDataSchema = z.object({
  rows: z.array(AblationRowSchema),
  margins: z.record(z.number()),
});

export const PlantedScenarioResultSchema = z.object({
  vuln_id: z.string(),
  category: z.string(),
  cvss: z.number(),
  graph_risk: z.number(),
  confidence: z.number().optional(),
  exposure: z.number().optional(),
  data_sensitivity: z.string().optional(),
  critical_path: z.boolean().optional(),
  action: z.string(),
  services: z.array(z.string()).default([]),
  cvss_rank: z.number(),
  graph_rank: z.number(),
  rank_delta: z.number(),
});

export const PlantedScenariosSchema = z.object({
  benchmark_results: z.array(PlantedScenarioResultSchema),
  sleeper_min_risk: z.number(),
  decoy_max_risk: z.number(),
  inversion_success: z.boolean(),
});

export const KevValidationMetricSchema = z.object({
  true_positives: z.number(),
  false_positives: z.number(),
  true_negatives: z.number(),
  false_negatives: z.number(),
  precision: z.number(),
  recall: z.number(),
  f1_score: z.number(),
  false_positive_rate: z.number(),
});

export const KevValidationSchema = z.object({
  status: z.string(),
  graph_aware: KevValidationMetricSchema,
  cvss_baseline: KevValidationMetricSchema,
  validation_summary: z.string(),
});

export const SensitivityAuditSchema = z.object({
  trials: z.number(),
  stable_trials: z.number(),
  stability_pct: z.number(),
  min_margin: z.number(),
  perturbation_range: z.string(),
  status: z.string(),
});

export const EvalLatestResponseSchema = z.object({
  status: z.string(),
  formula_version: z.string(),
  timestamp: z.number(),
  planted_scenarios: PlantedScenariosSchema,
  ablation: AblationDataSchema,
  kev_validation: KevValidationSchema,
  sensitivity: SensitivityAuditSchema,
  what_this_does_not_do: z.array(z.string()),
  data_sources: z.array(z.string()),
  assistant_disclosure: z.string(),
});

export type EvalLatestResponse = z.infer<typeof EvalLatestResponseSchema>;
