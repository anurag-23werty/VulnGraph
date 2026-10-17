#!/usr/bin/env python3
"""
VulnGraph Restore Script.
========================
Restores a FalkorDB graph from a serialized backup JSON snapshot.
"""

import sys
import json
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from schema import get_graph, init_schema, FALKORDB_GRAPH


BACKUP_DIR = PROJECT_ROOT / "backups"


def find_latest_backup() -> Path:
    """Finds the most recent snapshot in backups/."""
    files = sorted(BACKUP_DIR.glob("vulngraph_snapshot_*.json"))
    if not files:
        raise FileNotFoundError(f"No snapshot files found in {BACKUP_DIR}")
    return files[-1]


def restore_graph(backup_path: Path, reset_first: bool = False):
    """Restores graph state from snapshot file."""
    if not backup_path.exists():
        raise FileNotFoundError(f"Backup file not found: {backup_path}")

    print(f"Loading snapshot from {backup_path}...")
    data = json.loads(backup_path.read_text(encoding="utf-8"))
    nodes = data.get("nodes", [])
    edges = data.get("edges", [])

    graph = get_graph()

    if reset_first:
        print(f"Resetting existing graph '{FALKORDB_GRAPH}'...")
        try:
            graph.delete()
        except Exception:
            pass
        init_schema(graph)

    print(f"Restoring {len(nodes)} nodes and {len(edges)} edges into '{FALKORDB_GRAPH}'...")

    # Restore nodes
    for node in nodes:
        labels_str = ":".join(node["labels"])
        props = node["props"]
        cypher = f"MERGE (n:{labels_str} {{id: $id}}) SET n += $props" if "id" in props else f"MERGE (n:{labels_str} {{name: $name}}) SET n += $props"
        key_dict = {"id": props.get("id")} if "id" in props else {"name": props.get("name")}
        key_dict["props"] = props
        try:
            graph.query(cypher, key_dict)
        except Exception as e:
            print(f"  [Notice] Node restore notice: {e}")

    # Restore edges
    for edge in edges:
        from_label = edge["from_label"]
        to_label = edge["to_label"]
        rel_type = edge["rel_type"]
        from_key = edge["from_key"]
        to_key = edge["to_key"]
        cypher = f"""
        MATCH (a:{from_label}), (b:{to_label})
        WHERE (a.id = $from_key OR a.name = $from_key) AND (b.id = $to_key OR b.name = $to_key)
        MERGE (a)-[r:{rel_type}]->(b)
        """
        try:
            graph.query(cypher, {"from_key": from_key, "to_key": to_key})
        except Exception as e:
            print(f"  [Notice] Edge restore notice: {e}")

    print(f"[SUCCESS] Restore completed from {backup_path.name}.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnGraph Restore Utility")
    parser.add_argument("--file", type=str, default="", help="Path to JSON snapshot file")
    parser.add_argument("--reset", action="store_true", help="Delete existing graph before restoring")
    args = parser.parse_args()

    target_file = Path(args.file) if args.file else find_latest_backup()
    restore_graph(target_file, reset_first=args.reset)
