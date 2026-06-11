from __future__ import annotations

import sqlite3

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL,
  url TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_full_sync_at TEXT,
  last_incremental_sync_at TEXT,
  last_success_at TEXT,
  last_error TEXT,
  etag TEXT,
  last_modified TEXT,
  record_count INTEGER DEFAULT 0,
  status TEXT DEFAULT 'never',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_name TEXT NOT NULL,
  mode TEXT,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  records_imported INTEGER DEFAULT 0,
  error TEXT
);

CREATE TABLE IF NOT EXISTS raw_advisories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  advisory_id TEXT NOT NULL,
  raw_json TEXT NOT NULL,
  modified_at TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(source, advisory_id)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  primary_id TEXT NOT NULL UNIQUE,
  title TEXT,
  description TEXT,
  severity TEXT,
  cvss_score REAL,
  cvss_vector TEXT,
  cwe TEXT,
  published_at TEXT,
  modified_at TEXT,
  source TEXT,
  references_json TEXT,
  remediation TEXT,
  raw_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerability_aliases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vulnerability_id INTEGER NOT NULL,
  alias TEXT NOT NULL,
  source TEXT,
  UNIQUE(vulnerability_id, alias)
);

CREATE TABLE IF NOT EXISTS affected_packages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vulnerability_id INTEGER NOT NULL,
  ecosystem TEXT NOT NULL,
  package_name TEXT NOT NULL,
  purl TEXT,
  fixed_versions_json TEXT,
  source TEXT,
  confidence TEXT DEFAULT 'medium',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS affected_ranges (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  affected_package_id INTEGER NOT NULL,
  range_type TEXT,
  introduced TEXT,
  fixed TEXT,
  last_affected TEXT,
  affected_versions_json TEXT,
  raw_range_json TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS licenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  spdx_id TEXT NOT NULL UNIQUE,
  name TEXT,
  is_osi_approved INTEGER,
  raw_json TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS license_policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id TEXT NOT NULL UNIQUE,
  policy TEXT NOT NULL,
  notes TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rulesets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  source TEXT,
  version TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id TEXT NOT NULL UNIQUE,
  ruleset_id INTEGER,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  source TEXT,
  rule_yaml TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rule_import_errors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT,
  file_path TEXT,
  error TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_targets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  target TEXT NOT NULL,
  target_type TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL UNIQUE,
  target TEXT NOT NULL,
  target_type TEXT,
  project_name TEXT,
  skill_type TEXT,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  options_json TEXT,
  summary_json TEXT,
  error TEXT
);

CREATE TABLE IF NOT EXISTS scan_components (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  ecosystem TEXT,
  name TEXT NOT NULL,
  version TEXT,
  purl TEXT,
  type TEXT,
  evidence TEXT,
  source TEXT,
  licenses_json TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_sboms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  format TEXT NOT NULL,
  path TEXT NOT NULL,
  component_count INTEGER DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  component_name TEXT,
  component_version TEXT,
  ecosystem TEXT,
  vuln_id TEXT,
  rule_id TEXT,
  file_path TEXT,
  line_number INTEGER,
  evidence TEXT,
  remediation TEXT,
  source TEXT,
  raw_json TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(scan_id, finding_id)
);

CREATE TABLE IF NOT EXISTS scan_rule_hits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  file_path TEXT,
  line_number INTEGER,
  evidence TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT,
  report_type TEXT NOT NULL,
  format TEXT NOT NULL,
  path TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS intel_reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  report_id TEXT NOT NULL UNIQUE,
  range_from TEXT,
  range_to TEXT,
  filters_json TEXT,
  summary_json TEXT,
  path_json TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vuln_modified ON vulnerabilities(modified_at);
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_alias_alias ON vulnerability_aliases(alias);
CREATE INDEX IF NOT EXISTS idx_affected_pkg ON affected_packages(ecosystem, package_name);
CREATE INDEX IF NOT EXISTS idx_scan_findings_scan ON scan_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_findings_severity ON scan_findings(severity);
CREATE INDEX IF NOT EXISTS idx_scan_components_scan ON scan_components(scan_id);
"""


DEFAULT_SOURCES = {
    "osv": ("vulnerability", "https://api.osv.dev"),
    "ghsa": ("vulnerability", "https://github.com/advisories"),
    "nvd": ("vulnerability", "https://nvd.nist.gov/vuln/data-feeds"),
    "spdx": ("license", "https://spdx.org/licenses/licenses.json"),
    "aig": ("rules", "https://github.com/Tencent/AI-Infra-Guard"),
    "grype-db": ("scanner-db", None),
}


def initialize_database(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA_SQL)
    from sca_cli.utils.time import utc_now_iso

    now = utc_now_iso()
    for name, (source_type, url) in DEFAULT_SOURCES.items():
        connection.execute(
            """
            INSERT OR IGNORE INTO sources (name, type, url, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (name, source_type, url, now, now),
        )
    connection.commit()
