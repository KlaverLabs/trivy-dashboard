from collections import defaultdict
from datetime import datetime, timezone

from trivy_dashboard_service.database import transaction
from trivy_dashboard_service.model import ContainerInfo, VersionInfo, Vulnerability

FINISHED_CONTAINER_STATUSES = ("done", "failed")

SEVERITY_ORDER = """
    CASE severity
        WHEN 'CRITICAL' THEN 0
        WHEN 'HIGH' THEN 1
        WHEN 'MEDIUM' THEN 2
        WHEN 'LOW' THEN 3
        ELSE 4
    END
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def create_scan(containers: list[ContainerInfo]) -> tuple[int, list[int]]:
    with transaction() as connection:
        scan_id = connection.execute(
            "INSERT INTO scans (status, started_at) VALUES ('running', ?)", (_now(),)
        ).lastrowid
        row_ids = [
            connection.execute(
                "INSERT INTO scan_containers (scan_id, container_id, name, image, image_id)"
                " VALUES (?, ?, ?, ?, ?)",
                (scan_id, c.container_id, c.name, c.image, c.image_id),
            ).lastrowid
            for c in containers
        ]
    return scan_id, row_ids


def finish_scan(scan_id: int, status: str) -> None:
    with transaction() as connection:
        connection.execute(
            "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?",
            (status, _now(), scan_id),
        )


def mark_interrupted() -> None:
    with transaction() as connection:
        connection.execute(
            "UPDATE scan_containers SET status = 'failed', error = 'Scan was interrupted'"
            " WHERE status IN ('pending', 'scanning')"
        )
        connection.execute(
            "UPDATE scans SET status = 'failed', finished_at = ? WHERE status = 'running'",
            (_now(),),
        )


def get_running_scan_id() -> int | None:
    with transaction() as connection:
        row = connection.execute("SELECT id FROM scans WHERE status = 'running'").fetchone()
    return row["id"] if row else None


def mark_containers_scanning(row_ids: list[int]) -> None:
    with transaction() as connection:
        connection.executemany(
            "UPDATE scan_containers SET status = 'scanning' WHERE id = ?",
            [(row_id,) for row_id in row_ids],
        )


def complete_container(row_id: int, version: VersionInfo, vulnerabilities: list[Vulnerability]) -> None:
    with transaction() as connection:
        connection.execute(
            "UPDATE scan_containers SET status = 'done', current_version = ?, latest_version = ?,"
            " update_available = ? WHERE id = ?",
            (version.current, version.latest, version.update_available, row_id),
        )
        connection.executemany(
            "INSERT INTO vulnerabilities (scan_container_id, cve_id, severity, package,"
            " installed_version, fixed_version, title) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (row_id, v.cve_id, v.severity, v.package, v.installed_version, v.fixed_version, v.title)
                for v in vulnerabilities
            ],
        )


def fail_container(row_id: int, error: str, version: VersionInfo) -> None:
    with transaction() as connection:
        connection.execute(
            "UPDATE scan_containers SET status = 'failed', error = ?, current_version = ?,"
            " latest_version = ?, update_available = ? WHERE id = ?",
            (error, version.current, version.latest, version.update_available, row_id),
        )


def list_scans() -> list[dict]:
    with transaction() as connection:
        rows = connection.execute(
            """
            SELECT s.*,
                   COUNT(c.id) AS total,
                   COALESCE(SUM(c.status IN ('done', 'failed')), 0) AS finished,
                   COALESCE(SUM(c.status = 'failed'), 0) AS failed
            FROM scans s
            LEFT JOIN scan_containers c ON c.scan_id = s.id
            GROUP BY s.id
            ORDER BY s.id DESC
            """
        ).fetchall()
    return [dict(row) for row in rows]


def get_scan(scan_id: int) -> dict | None:
    with transaction() as connection:
        row = connection.execute(
            """
            SELECT s.*,
                   COUNT(c.id) AS total,
                   COALESCE(SUM(c.status IN ('done', 'failed')), 0) AS finished,
                   COALESCE(SUM(c.status = 'failed'), 0) AS failed
            FROM scans s
            LEFT JOIN scan_containers c ON c.scan_id = s.id
            WHERE s.id = ?
            GROUP BY s.id
            """,
            (scan_id,),
        ).fetchone()
    return dict(row) if row else None


def list_scan_containers(scan_id: int) -> list[dict]:
    """Containers of a scan, each with its vulnerabilities ordered from highest to lowest severity."""
    with transaction() as connection:
        containers = [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM scan_containers WHERE scan_id = ? ORDER BY name", (scan_id,)
            )
        ]
        vulnerabilities = defaultdict(list)
        for row in connection.execute(
            f"""
            SELECT v.* FROM vulnerabilities v
            JOIN scan_containers c ON c.id = v.scan_container_id
            WHERE c.scan_id = ?
            ORDER BY {SEVERITY_ORDER}, v.cve_id, v.package
            """,
            (scan_id,),
        ):
            vulnerabilities[row["scan_container_id"]].append(dict(row))
    for container in containers:
        container["vulnerabilities"] = vulnerabilities[container["id"]]
    return containers
