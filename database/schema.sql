-- WhisperWard OSINT - Database Schema
-- Run: sqlite3 whisperward.db < schema.sql
-- All tables with indexes for performance

-- ============================================================
-- Cases
-- ============================================================
CREATE TABLE IF NOT EXISTS cases (
    case_id      TEXT PRIMARY KEY,
    case_name    TEXT NOT NULL,
    description  TEXT,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    analyst_name TEXT,
    status       TEXT DEFAULT 'open'
                 CHECK(status IN ('open', 'closed', 'archived'))
);

-- ============================================================
-- Targets
-- ============================================================
CREATE TABLE IF NOT EXISTS targets (
    target_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id          TEXT    NOT NULL,
    platform         TEXT    NOT NULL,
    username         TEXT    NOT NULL,
    platform_user_id TEXT,
    added_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
    notes            TEXT,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

-- ============================================================
-- Artifacts (raw evidence — immutable after intake)
-- ============================================================
CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id      INTEGER NOT NULL,
    module_name    TEXT    NOT NULL,
    artifact_type  TEXT    NOT NULL,
    raw_data       JSON,
    processed_data JSON,
    file_path      TEXT,
    sha256         TEXT    NOT NULL,
    collected_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(target_id) REFERENCES targets(target_id) ON DELETE CASCADE
);

-- ============================================================
-- Evidence Log (chain of custody)
-- ============================================================
CREATE TABLE IF NOT EXISTS evidence_log (
    log_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
    action      TEXT     NOT NULL,
    artifact_id INTEGER,
    target_id   INTEGER,
    analyst     TEXT,
    sha256      TEXT,
    notes       TEXT,
    FOREIGN KEY(artifact_id) REFERENCES artifacts(artifact_id)
);

-- ============================================================
-- Analysis Results
-- ============================================================
CREATE TABLE IF NOT EXISTS analysis_results (
    result_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id     INTEGER NOT NULL,
    analysis_type TEXT    NOT NULL,
    findings      JSON,
    risk_score    REAL,
    analyst_notes TEXT,
    analyzed_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(target_id) REFERENCES targets(target_id)
);

-- ============================================================
-- Performance Indexes
-- ============================================================
CREATE INDEX IF NOT EXISTS idx_target_case     ON targets(case_id);
CREATE INDEX IF NOT EXISTS idx_artifact_target ON artifacts(target_id);
CREATE INDEX IF NOT EXISTS idx_log_artifact    ON evidence_log(artifact_id);
CREATE INDEX IF NOT EXISTS idx_results_target  ON analysis_results(target_id);

-- ============================================================
-- Resolved Entities (Platform Phase 3)
-- An entity is an analyst-confirmed identity holding one or
-- more platform accounts. Promotion is a human decision; the
-- machine's justification travels with each membership.
-- ============================================================
CREATE TABLE IF NOT EXISTS entities (
    entity_id           TEXT PRIMARY KEY,
    case_id             TEXT NOT NULL,
    canonical_handle    TEXT NOT NULL,
    promoted_by         TEXT NOT NULL,
    promoted_at         DATETIME NOT NULL,
    source_candidate_id TEXT,
    analyst_note        TEXT,
    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS entity_members (
    member_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id     TEXT NOT NULL,
    profile_id    TEXT NOT NULL,
    platform      TEXT NOT NULL,
    username      TEXT NOT NULL,
    justification JSON,
    FOREIGN KEY(entity_id) REFERENCES entities(entity_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_entities_case   ON entities(case_id);
CREATE INDEX IF NOT EXISTS idx_members_entity  ON entity_members(entity_id);
