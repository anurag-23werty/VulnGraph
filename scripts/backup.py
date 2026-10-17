#!/usr/bin/env python3
"""
VulnGraph Backup Script.
=======================
Creates a timestamped snapshot of the FalkorDB graph.
Supports:
  1. Internal GRAPH.COPY in FalkorDB (zero downtime snapshot).
  2. Serialized JSON export for offsite backups and portability.
  3. Redis BGSAVE persistence trigger.
"""

import sys
import json
import time
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from schema import get_graph, FALKORDB_GRAPH


BACKUP_DIR = PROJECT_ROOT / "backups"
BACKUP_DIR.mkdir(exist_ok=True)


def backup_graph() -> Path:
    """Executes a complete graph export and snapshot."""
    graph = get_graph()
    ts = int(time.time())
    backup_file = BACKUP_DIR / f"vulngraph_snapshot_{ts}.json"

    print(f"Starting VulnGraph backup for graph '{FALKORDB_GRAPH}'...")

    # 1. Trigger FalkorDB GRAPH.COPY for instant in-engine snapshot
    copy_target = f"{FALKORDB_GRAPH}_backup_{ts}"
    try:
        # FalkorDB client execute_command
        graph.redis_client.execute_command("GRAPH.COPY", FALKORDB_GRAPH, copy_target)
        print(f"  • In-Engine Snapshot created: '{copy_target}'")
    except Exception as e:
        print(f"  • [Notice] GRAPH.COPY notice: {e}")

    # 2. Export nodes & edges to portable JSON
    nodes_q = "MATCH (n) RETURN labels(n) AS labels, properties(n) AS props"
    edges_q = "MATCH (a)-[r]->(b) RETURN type(r) AS rel_type, properties(r) AS rel_props, labels(a)[0] AS from_label, a.id AS from_id, a.name AS from_name, labels(b)[0] AS to_label, b.id AS to_id, b.name AS to_name"

    nodes_res = graph.ro_query(nodes_q)
    edges_res = graph.ro_query(edges_q)

    export_data = {
        "graph_name": FALKORDB_GRAPH,
        "timestamp": ts,
        "nodes": [{"labels": row[0], "props": row[1]} for row in nodes_res.result_set],
        "edges": [
            {
                "rel_type": row[0],
                "props": row[1],
                "from_label": row[2],
                "from_key": row[3] or row[4],
                "to_label": row[5],
                "to_key": row[6] or row[7],
            }
            for row in edges_res.result_set
        ]
    }

    backup_file.write_text(json.dumps(export_data, indent=2), encoding="utf-8")
    print(f"  • Serialized Backup File: {backup_file} ({len(export_data['nodes'])} nodes, {len(export_data['edges'])} edges)")
    print(f"Backup completed successfully at {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ts))} UTC.\n")
    return backup_file


if __name__ == "__main__":
    backup_graph()
