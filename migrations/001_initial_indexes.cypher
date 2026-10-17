// Migration 001: Initial Range Indexes for Fast Entity Traversal
CREATE INDEX FOR (v:Vuln) ON (v.id);
CREATE INDEX FOR (p:Package) ON (p.name);
CREATE INDEX FOR (p:Package) ON (p.purl);
CREATE INDEX FOR (s:Service) ON (s.name);
CREATE INDEX FOR (d:Decision) ON (d.id);
