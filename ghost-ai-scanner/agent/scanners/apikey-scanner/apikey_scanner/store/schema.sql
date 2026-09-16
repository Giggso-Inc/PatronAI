-- PLAN.md section 8. DDL as data, not string-concatenated Python.
-- No column in `finding` may ever hold a secret value or a raw preview of one.

CREATE TABLE IF NOT EXISTS scan (
  scan_id         INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_timestamp  TEXT NOT NULL,
  tool_version    TEXT NOT NULL,
  catalog_version TEXT NOT NULL,
  host            TEXT,
  roots_json      TEXT NOT NULL,
  repos_scanned   INTEGER NOT NULL DEFAULT 0,
  files_scanned   INTEGER NOT NULL DEFAULT 0,
  files_skipped   INTEGER NOT NULL DEFAULT 0,
  findings_total  INTEGER NOT NULL DEFAULT 0,
  duration_ms     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS finding (
  finding_id            TEXT PRIMARY KEY,
  repo_id               TEXT NOT NULL,
  repo_path             TEXT NOT NULL,
  file_path             TEXT NOT NULL,
  line_number           INTEGER NOT NULL,
  column_start          INTEGER NOT NULL,
  match_length          INTEGER NOT NULL,
  matched_pattern_type  TEXT NOT NULL,
  pattern_id            TEXT NOT NULL,
  provider              TEXT NOT NULL,
  confidence            TEXT NOT NULL,
  detector              TEXT NOT NULL,
  entropy_bits          REAL,
  commit_sha            TEXT,
  author_name           TEXT,
  author_email          TEXT,
  author_timestamp      TEXT,
  provenance_state      TEXT NOT NULL,
  is_git_tracked        INTEGER NOT NULL,
  is_gitignored         INTEGER NOT NULL,
  in_test_path          INTEGER NOT NULL,
  first_seen_scan_id    INTEGER NOT NULL REFERENCES scan(scan_id),
  last_seen_scan_id     INTEGER NOT NULL REFERENCES scan(scan_id),
  status                TEXT NOT NULL,
  resolved_scan_id      INTEGER REFERENCES scan(scan_id),
  secret_fingerprint    TEXT
);

CREATE TABLE IF NOT EXISTS finding_observation (
  finding_id  TEXT NOT NULL REFERENCES finding(finding_id),
  scan_id     INTEGER NOT NULL REFERENCES scan(scan_id),
  line_number INTEGER NOT NULL,
  PRIMARY KEY (finding_id, scan_id)
);

CREATE TABLE IF NOT EXISTS allowlist (
  finding_id TEXT PRIMARY KEY,
  reason     TEXT NOT NULL,
  added_by   TEXT,
  added_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_finding_repo   ON finding(repo_id, status);
CREATE INDEX IF NOT EXISTS idx_finding_status ON finding(status, last_seen_scan_id);
