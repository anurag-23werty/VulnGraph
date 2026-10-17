// Migration 002: Decision Node Versioning & Topological Confidence Defaults
MATCH (d:Decision)
WHERE d.formula_version IS NULL
SET d.formula_version = 'v1.2.0', d.confidence = 0.90;
