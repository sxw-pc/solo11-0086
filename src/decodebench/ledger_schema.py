"""SQLite 台账表结构。"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS batches (
    batch_id TEXT PRIMARY KEY,
    batch_key TEXT NOT NULL UNIQUE,
    input_root TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    config_fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    run_count INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    conflict_count INTEGER NOT NULL,
    transcoded_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    idempotency_key TEXT NOT NULL,
    rel_path TEXT NOT NULL,
    source_size INTEGER NOT NULL,
    source_sha256 TEXT NOT NULL,
    source_mtime TEXT NOT NULL,
    final_encoding TEXT NOT NULL,
    confidence REAL NOT NULL,
    method TEXT NOT NULL,
    conflict_count INTEGER NOT NULL,
    warning_count INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    transcode_success INTEGER NOT NULL,
    output_rel_path TEXT,
    output_sha256 TEXT,
    replacement_used INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(idempotency_key, rel_path)
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    source TEXT NOT NULL,
    declared TEXT,
    byte_offset INTEGER,
    line_number INTEGER,
    matches_decision INTEGER,
    note TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS decisions (
    file_id INTEGER PRIMARY KEY REFERENCES files(id) ON DELETE CASCADE,
    encoding TEXT NOT NULL,
    confidence REAL NOT NULL,
    method TEXT NOT NULL,
    reason TEXT NOT NULL,
    conflicts_json TEXT NOT NULL,
    error_codes_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS warnings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    line_number INTEGER,
    byte_offset INTEGER,
    snippet TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_batch ON files(batch_id, rel_path);
CREATE INDEX IF NOT EXISTS idx_evidence_file ON evidence(file_id, ordinal);
CREATE INDEX IF NOT EXISTS idx_warnings_file ON warnings(file_id, code);
"""

