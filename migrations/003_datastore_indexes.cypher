// Migration 003: DataStore & Team Range Indexes
CREATE INDEX FOR (ds:DataStore) ON (ds.name);
CREATE INDEX FOR (t:Team) ON (t.name);
