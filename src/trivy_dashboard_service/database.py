import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from trivy_dashboard_service import settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS scan_containers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    container_id TEXT NOT NULL,
    name TEXT NOT NULL,
    image TEXT NOT NULL,
    image_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    error TEXT,
    current_version TEXT,
    latest_version TEXT,
    update_available INTEGER
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_container_id INTEGER NOT NULL REFERENCES scan_containers(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    package TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    fixed_version TEXT,
    title TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_containers_scan ON scan_containers(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_container ON vulnerabilities(scan_container_id);
"""


def connect() -> sqlite3.Connection:
    path = Path(settings.DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def transaction() -> Iterator[sqlite3.Connection]:
    connection = connect()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def init_db() -> None:
    with transaction() as connection:
        connection.executescript(SCHEMA)
