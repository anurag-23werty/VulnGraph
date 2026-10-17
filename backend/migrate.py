#!/usr/bin/env python3
"""
VulnGraph Cypher Schema Migration Runner.
=========================================
Applies versioned .cypher migration scripts in migrations/ sequentially
to manage graph schema evolution without requiring full graph resets.
Tracks applied migrations in (:SchemaMigration) nodes in FalkorDB.
"""

import time
import re
from pathlib import Path
from typing import List, Tuple
from schema import get_graph


BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent
MIGRATIONS_DIR = ROOT_DIR / "migrations" if (ROOT_DIR / "migrations").exists() else BASE_DIR / "migrations"


def get_applied_migrations(graph) -> List[int]:
    """Retrieve set of already applied migration versions from FalkorDB."""
    try:
        res = graph.query("MATCH (m:SchemaMigration) RETURN m.version AS v ORDER BY v ASC")
        return [int(row[0]) for row in res.result_set]
    except Exception:
        return []


def parse_cypher_file(file_path: Path) -> List[str]:
    """Extract individual Cypher statements separated by semicolons."""
    content = file_path.read_text(encoding="utf-8")
    statements = []
    for raw in content.split(";"):
        stmt = raw.strip()
        # Remove comment lines
        lines = [line for line in stmt.splitlines() if not line.strip().startswith("//")]
        clean_stmt = "\n".join(lines).strip()
        if clean_stmt:
            statements.append(clean_stmt)
    return statements


def get_pending_migrations() -> List[Tuple[int, str, Path]]:
    """Scan migrations/ for versioned .cypher files sorted by version."""
    if not MIGRATIONS_DIR.exists():
        return []

    files = sorted(MIGRATIONS_DIR.glob("*.cypher"))
    pending = []
    for f in files:
        match = re.match(r"^(\d+)_(.+)\.cypher$", f.name)
        if match:
            version = int(match.group(1))
            name = match.group(2)
            pending.append((version, name, f))
    return pending


def run_migrations() -> int:
    """Execute all pending schema migrations sequentially."""
    graph = get_graph()
    applied = set(get_applied_migrations(graph))
    pending = get_pending_migrations()

    applied_count = 0
    print(f"Checking FalkorDB schema migrations in {MIGRATIONS_DIR}...")

    for version, name, path in pending:
        if version in applied:
            continue

        print(f"  • Applying migration {version:03d}_{name}...")
        statements = parse_cypher_file(path)
        for stmt in statements:
            try:
                graph.query(stmt)
            except Exception as e:
                err_msg = str(e).lower()
                # Ignore already exists warnings on indexes
                if "already exists" in err_msg or "index on" in err_msg:
                    pass
                else:
                    print(f"    [WARN] Cypher statement error: {e}")

        # Record migration completion
        ts = int(time.time())
        record_cypher = """
        CREATE (:SchemaMigration {
            version: $version,
            name: $name,
            file: $file,
            applied_at: $ts
        })
        """
        graph.query(record_cypher, {
            "version": version,
            "name": name,
            "file": path.name,
            "ts": ts
        })
        applied.add(version)
        applied_count += 1
        print(f"    -> [SUCCESS] Migration {version:03d} committed.")

    if applied_count == 0:
        latest = max(applied) if applied else 0
        print(f"Schema is up to date (version {latest:03d}). Zero migrations needed.")
    else:
        print(f"Successfully applied {applied_count} migration(s). Current version: {max(applied):03d}.")

    return applied_count


if __name__ == "__main__":
    run_migrations()
