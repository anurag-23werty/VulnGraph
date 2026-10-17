"""
Database connection and schema definitions for FalkorDB graph.

Graph Data Model:
  (:Vuln {id, cvss, summary, fix_version})-[:AFFECTS]->(:Package {name, version})
  (:Package)-[:DEPENDS_ON]->(:Package)
  (:Service {name, internet_facing})-[:DEPENDS_ON]->(:Package)
  (:Service)-[:CALLS]->(:Service)
  (:Service)-[:READS]->(:DataStore {name, sensitivity})
  (:Team {name})-[:OWNS]->(:Service)
  (:Decision {id, verdict, risk, ts, status, action_type, rationale, evidence})-[:BASED_ON]->(:Vuln)
  (:Decision)-[:ABOUT]->(:Service)
"""

import os
from dotenv import load_dotenv
from falkordb import FalkorDB

load_dotenv()

FALKORDB_HOST = os.getenv("FALKORDB_HOST", "localhost")
FALKORDB_PORT = int(os.getenv("FALKORDB_PORT", "6379"))
FALKORDB_GRAPH = os.getenv("FALKORDB_GRAPH", "vulngraph")
FALKORDB_PASSWORD = os.getenv("FALKORDB_PASSWORD", None) or None


def get_graph(graph_name: str = FALKORDB_GRAPH):
    """
    Returns a connected FalkorDB graph client instance.
    """
    kwargs = {"host": FALKORDB_HOST, "port": FALKORDB_PORT}
    if FALKORDB_PASSWORD:
        kwargs["password"] = FALKORDB_PASSWORD
    client = FalkorDB(**kwargs)
    return client.select_graph(graph_name)


# Convenience alias
get_graph_client = get_graph


def init_schema(graph) -> None:
    """
    Initializes graph indexes for high-performance Cypher traversals.
    Safe to call multiple times (checks existing indexes first).
    """
    # Cypher syntax for FalkorDB range indexes: CREATE INDEX FOR (n:Label) ON (n.prop)
    index_queries = [
        "CREATE INDEX FOR (v:Vuln) ON (v.id)",
        "CREATE INDEX FOR (p:Package) ON (p.name)",
        "CREATE INDEX FOR (p:Package) ON (p.purl)",
        "CREATE INDEX FOR (s:Service) ON (s.name)",
        "CREATE INDEX FOR (d:Decision) ON (d.id)",
    ]

    for q in index_queries:
        try:
            graph.query(q)
        except Exception as e:
            # If index already exists or syntax notice, ignore gracefully
            msg = str(e).lower()
            if "already exists" in msg or "index on" in msg:
                pass
            else:
                print(f"[Schema] Index note on query '{q}': {e}")


def clear_graph(graph) -> None:
    """
    Completely resets the graph by deleting all nodes and relationships.
    """
    try:
        graph.delete()
    except Exception:
        # Fallback to cypher delete if graph.delete() throws on empty graph
        try:
            graph.query("MATCH (n) DETACH DELETE n")
        except Exception:
            pass


if __name__ == "__main__":
    g = get_graph()
    init_schema(g)
    print(f"Initialized schema and indexes on FalkorDB graph: '{FALKORDB_GRAPH}'")
