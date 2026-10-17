# VulnGraph Cypher Query & Graph Algorithm Reference

This document lists every Cypher traversal and native graph algorithm used in **VulnGraph**, as required by the FalkorDB Hackathon Track 01 rules.

All ranking decisions in VulnGraph originate strictly from these Cypher traversals and graph algorithms.

---

## 1. Finding Context Query
**Function**: `get_finding_context(vuln_id)`  
**Purpose**: Retrieves vulnerability metadata, affected packages, and directly dependent services.  
**Execution Mode**: `ro_query` (Read-Only)  
**Cypher**:
```cypher
MATCH (v:Vuln {id: $vuln_id})-[:AFFECTS]->(p:Package)
OPTIONAL MATCH (s:Service)-[:DEPENDS_ON]->(p)
RETURN v.id AS vuln_id,
       v.cvss AS cvss,
       v.summary AS summary,
       v.fix_version AS fix_version,
       p.name AS package_name,
       p.version AS package_version,
       collect(DISTINCT s.name) AS direct_services
LIMIT 25;
```

---

## 2. Multi-Hop Blast Radius Query
**Function**: `blast_radius(vuln_id)`  
**Purpose**: Discovers multi-hop transitive dependencies ($1$ to $6$ hops) from Services down to vulnerable packages and flags whether any impacted service is exposed to the internet.  
**Execution Mode**: `ro_query` (Read-Only)  
**Cypher**:
```cypher
MATCH path = (s:Service)-[:DEPENDS_ON*1..6]->(p:Package)<-[:AFFECTS]-(v:Vuln {id: $vuln_id})
RETURN s.name AS service,
       s.internet_facing AS internet_facing,
       [n in nodes(path) | coalesce(n.name, n.id)] AS chain
LIMIT 25;
```

---

## 3. Exploit Path Query (Ingress to Sensitive Crown Jewels)
**Function**: `exploit_path(service)`  
**Purpose**: Determines if an internet-facing entry point can reach the service via `CALLS*0..5`, and if the service can reach high- or medium-sensitivity `DataStore` nodes via `READS`.  
**Execution Mode**: `ro_query` (Read-Only)  
**Cypher (Ingress)**:
```cypher
MATCH (ingress:Service {internet_facing: true}), (s:Service {name: $service})
WITH ingress, s, shortestPath((ingress)-[:CALLS*0..5]->(s)) AS p_in
WHERE p_in IS NOT NULL
RETURN [n in nodes(p_in) | n.name] AS ingress_path, ingress.name AS ingress_service
LIMIT 5;
```

**Cypher (Egress to Sensitive Data)**:
```cypher
MATCH (s:Service {name: $service}), (target:Service)-[:READS]->(d:DataStore)
WITH s, target, d, shortestPath((s)-[:CALLS*0..5]->(target)) AS p_out
WHERE p_out IS NOT NULL
RETURN [n in nodes(p_out) | n.name] AS call_path, d.name AS datastore, d.sensitivity AS sensitivity
ORDER BY CASE d.sensitivity WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END ASC
LIMIT 5;
```

---

## 4. Package Structural Criticality via PageRank
**Function**: `rank_critical_packages(limit=25)`  
**Purpose**: Executes FalkorDB's built-in PageRank algorithm over `(:Package)-[:DEPENDS_ON]->(:Package)` to score ecosystem dependency centrality.  
**Execution Mode**: `ro_query` (Read-Only)  
**Cypher**:
```cypher
CALL algo.pageRank('Package', 'DEPENDS_ON')
YIELD node, score
RETURN node.name AS package_name, node.version AS version, score
ORDER BY score DESC
LIMIT $limit;
```

---

## 5. Service Ownership Query
**Function**: `find_owner(service)`  
**Purpose**: Finds the engineering team that owns the service and all other microservices in their domain.  
**Execution Mode**: `ro_query` (Read-Only)  
**Cypher**:
```cypher
MATCH (t:Team)-[:OWNS]->(s:Service {name: $service})
OPTIONAL MATCH (t)-[:OWNS]->(other:Service)
RETURN t.name AS team_name, collect(DISTINCT other.name) AS all_owned_services
LIMIT 25;
```

---

## 6. Similar Past Triage Decisions Query
**Function**: `similar_past_decisions(vuln_id)`  
**Purpose**: Retrieves historical decisions associated directly with the vulnerability or past triage history on related microservices.  
**Execution Mode**: `ro_query` (Read-Only)  
**Cypher**:
```cypher
MATCH (d:Decision)-[:BASED_ON]->(v:Vuln {id: $vuln_id})
OPTIONAL MATCH (d)-[:ABOUT]->(s:Service)
RETURN d.id AS decision_id,
       d.verdict AS verdict,
       d.risk AS risk,
       d.status AS status,
       d.action_type AS action_type,
       d.rationale AS rationale,
       d.ts AS timestamp,
       s.name AS service
ORDER BY d.ts DESC
LIMIT 25;
```

---

## 7. Deterministic Risk Score
**Function**: `compute_risk(vuln_id)`  
**Formula**:
$$\text{Score} = 10.0 \times (\text{cvss\_norm} \times \text{exposure} \times \text{data\_sensitivity} \times \text{blast\_radius\_factor}) \times \text{critical\_path\_multiplier}$$
- $\text{cvss\_norm} \in [0.5, 1.0]$: Baseline severity normalized.
- $\text{exposure} \in \{1.0 \text{ (direct internet)}, 0.75 \text{ (ingress reachable)}, 0.20 \text{ (internal)}\}$.
- $\text{data\_sensitivity} \in \{1.0 \text{ (high PII/creds/payment)}, 0.60 \text{ (medium)}, 0.25 \text{ (low)}\}$.
- $\text{blast\_radius\_factor} \in [0.6, 1.0]$: Scaled by number of impacted services.
- $\text{critical\_path\_multiplier} = 1.6$: Boost applied when an internet-facing ingress service has an active exploit path to high-sensitivity crown-jewel data.

---

## 8. Staged Action Proposal (Human-in-the-Loop)
**Function**: `propose_action(vuln_id, action_type, rationale, evidence)`  
**Purpose**: Writes a `Decision` node with status strictly set to `"pending"`. Actions cannot be executed by the LLM without human approval via `POST /approve/{decision_id}`.  
**Execution Mode**: `query` (Read/Write)  
**Cypher**:
```cypher
MATCH (v:Vuln {id: $vuln_id})
CREATE (d:Decision {
    id: $id,
    verdict: $action_type,
    risk: $risk,
    ts: $ts,
    status: 'pending',
    action_type: $action_type,
    rationale: $rationale,
    evidence: $evidence
})
CREATE (d)-[:BASED_ON]->(v)
WITH d
OPTIONAL MATCH (s:Service {name: $service})
FOREACH (_ IN CASE WHEN s IS NOT NULL THEN [1] ELSE [] END |
    CREATE (d)-[:ABOUT]->(s)
)
RETURN d.id AS decision_id, d.status AS status;
```
