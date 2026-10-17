# VulnGraph: Hackathon Demo Video Script
**Track 01**: Agents That Act on Connected Data (Graph Hacks - FalkorDB)  
**Target Duration**: 3:00 - 3:30 Minutes  
**Presenters**: Solo Engineer or Team  

---

## Video Outline & Timestamps

| Timestamp | Screen / Visual | Narration & Action |
| :--- | :--- | :--- |
| **0:00 - 0:35** | Slide / Web UI Hero Header | **The Problem: The CVSS Alert Fatigue Crisis** |
| **0:35 - 1:15** | Architecture Diagram & FalkorDB Browser | **Why Graph? The Connected Topology in FalkorDB** |
| **1:15 - 2:05** | VulnGraph Live UI: Side-by-Side Comparison | **Live Demo: The Ground-Truth Reordering Proof** |
| **2:05 - 2:40** | Agent Tool Trace & Interactive Force Graph | **Autonomous Agent Traversal & Explainability** |
| **2:40 - 3:10** | Staged Decision & Human Approval Modal | **Human-in-the-Loop Safe Action Execution** |
| **3:10 - 3:30** | Terminal Test Suite (`pytest` & `eval.py`) | **Conclusion & Submission Wrap-up** |

---

## Detailed Step-by-Step Script

### 1. The Problem: The CVSS Alert Fatigue Crisis (0:00 - 0:35)
- **Visual**: Start on the VulnGraph Web UI (`http://localhost:8000`).
- **Narrator**:
  > *"Every security team faces the same nightmare: a wall of hundreds of 'Critical' and 'High' CVSS alerts from dependency scanners. In modern cloud microservices, traditional CVSS is blind to topology. It doesn't know if a package is deployed in an isolated dev tool or an internet-facing gateway. It doesn't know if a service has direct read access to your customer credit card database.*
  >
  > *This results in severe alert fatigue: security engineers burn hours patching harmless internal criticals, while subtle medium-severity flaws that lead straight to your crown jewels go completely unnoticed.*
  >
  > *Meet **VulnGraph**: an autonomous agent that acts on connected graph data in FalkorDB to replace naive CVSS with graph-grounded risk intelligence."*

---

### 2. The Connected Topology in FalkorDB (0:35 - 1:15)
- **Visual**: Switch to FalkorDB Browser (`http://localhost:3000`) or showcase the graph data model diagram. Run `MATCH (n) RETURN n LIMIT 50`.
- **Narrator**:
  > *"VulnGraph models the enterprise as a unified graph in **FalkorDB**:*
  > - *Vulnerabilities affect Packages.*
  > - *Packages form transitive dependency trees via `DEPENDS_ON`.*
  > - *Microservices depend on Packages and call other Microservices via `CALLS`.*
  > - *Services read sensitive `DataStore` nodes—from public caches to confidential PII and payment databases.*
  > - *And Engineering Teams own those Services.*
  >
  > *Crucially: **FalkorDB is the single source of truth**. Every single ranking decision and blast radius calculation is computed via native Cypher path traversals and FalkorDB algorithms like `algo.pageRank`. The LLM can never hallucinate a risk score on its own."*

---

### 3. Live Demo: The Ground-Truth Reordering Proof (1:15 - 2:05)
- **Visual**: Switch back to `http://localhost:8000`. Point mouse to the two columns: **"Traditional Scanner (CVSS Only)"** vs. **"VulnGraph (Graph-Aware Risk)"**.
- **Narrator**:
  > *"Here is the side-by-side proof.*
  >
  > *On the left is the standard industry baseline: ranked purely by CVSS severity. At the very top are three 'Critical' CVEs (`CVE-2021-DECOY-01`, `02`, `03`) with CVSS 9.8.*
  > *Buried down at the bottom are three 'Medium' CVEs (`CVE-2023-SLEEPER-01`, `02`, `03`) with CVSS 5.3 to 6.1.*
  >
  > *Now look at the right column: **VulnGraph completely inverts this list!***
  >
  > *Why? Because FalkorDB's Cypher traversal discovers that `CVE-2023-SLEEPER-03` is reachable from the public internet through `api-gateway` and leads directly through `payment-service` into our `payments-db` containing credit card data! Its graph risk score jumps from 6.1 to **7.73**—an immediate patch priority!*
  >
  > *Conversely, the 9.8 CVSS decoys sit in `analytics-worker`—an offline internal service with zero internet ingress and zero access to sensitive data. VulnGraph slashes their risk score down to **0.30**, safely saving the security team hundreds of wasted hours."*

---

### 4. Autonomous Agent Traversal & Interactive Graph (2:05 - 2:40)
- **Visual**: Click on `CVE-2023-SLEEPER-03`. Show the 2D Force-Graph canvas re-rendering. Zoom in on the highlighted red attack path nodes with animated particles flowing from `api-gateway` to `payments-db`. Click **"View Agent Trace"**.
- **Narrator**:
  > *"When we trigger triage, our autonomous Groq agent acts as an MCP client querying FalkorDB tools:*
  > - *It runs `blast_radius` across transitive `DEPENDS_ON` relationships.*
  > - *It calls `exploit_path` executing FalkorDB's `shortestPath` algorithm from ingress to high-sensitivity datastores.*
  > - *It runs `algo.pageRank` to inspect package ecosystem centrality.*
  > - *And it queries `find_owner` to pinpoint who owns the vulnerable service.*
  >
  > *In the UI, the exact exploit path is illuminated in real-time on our interactive canvas: from `api-gateway` down to `payments-db`."*

---

### 5. Staged Decision & Human-in-the-Loop Approval (2:40 - 3:10)
- **Visual**: Click the **"Approve Staged Ticket"** button. Show the green confirmation badge appear, and switch to the terminal or open `tickets.jsonl` to show the dispatched ticket.
- **Narrator**:
  > *"Safety is a core design principle: **the LLM is strictly prohibited from executing mutations directly**. Instead, it stages a pending `Decision` node in FalkorDB via `propose_action`.*
  >
  > *A human security analyst reviews the exact Cypher evidence path and clicks 'Approve Staged Ticket'. Once approved, the decision is locked in the graph, and the dispatch is logged to our ticketing system and team webhook."*

---

### 6. Terminal Test Suite & Conclusion (3:10 - 3:30)
- **Visual**: Show the terminal running:
  - `python eval.py`
  - `pytest tests/ -v`
- **Narrator**:
  > *"To ensure 100% reproducible results, we built an automated evaluation benchmark (`eval.py`) that tests our ground-truth separation margin, along with a full test suite of 37 unit and integration tests passing in under 2 seconds.*
  >
  > *VulnGraph proves what happens when autonomous agents are grounded in connected graph data: noise disappears, crown jewels are protected, and triage becomes actionable.*
  >
  > *Thank you, and happy graphing with FalkorDB!"*
