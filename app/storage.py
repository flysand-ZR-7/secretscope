"""SQLite storage layer for SecretScope."""
import sqlite3
import os
from datetime import datetime, timezone

from app.models import Finding, ScanResult

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "secretscope.db")


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """Create tables if they don't exist."""
    conn = _get_conn()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                scan_type TEXT,
                timestamp TEXT,
                finding_count INTEGER
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER,
                url TEXT,
                pattern_name TEXT,
                severity TEXT,
                redacted_value TEXT,
                line_number INTEGER,
                context_snippet TEXT,
                validated BOOLEAN DEFAULT 0,
                validation_note TEXT DEFAULT '',
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            );
        """)
        conn.commit()
    finally:
        conn.close()


def save_scan(target: str, scan_type: str, findings: list[Finding]) -> ScanResult:
    """Insert a scan and all its findings in a transaction. Returns ScanResult with id populated."""
    conn = _get_conn()
    try:
        timestamp = datetime.now(timezone.utc).isoformat()
        cursor = conn.execute(
            "INSERT INTO scans (target, scan_type, timestamp, finding_count) VALUES (?, ?, ?, ?)",
            (target, scan_type, timestamp, len(findings)),
        )
        scan_id = cursor.lastrowid

        populated_findings: list[Finding] = []
        for f in findings:
            cursor = conn.execute(
                "INSERT INTO findings (scan_id, url, pattern_name, severity, redacted_value, "
                "line_number, context_snippet, validated, validation_note) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    f.url,
                    f.pattern_name,
                    f.severity,
                    f.redacted_value,
                    f.line_number,
                    f.context_snippet,
                    f.validated,
                    f.validation_note,
                ),
            )
            populated_findings.append(
                f.model_copy(update={"id": cursor.lastrowid, "scan_id": scan_id})
            )

        conn.commit()

        return ScanResult(
            id=scan_id,
            target=target,
            scan_type=scan_type,
            timestamp=timestamp,
            finding_count=len(findings),
            findings=populated_findings,
        )
    finally:
        conn.close()


def get_scans() -> list[ScanResult]:
    """Return all scans (without findings list)."""
    conn = _get_conn()
    try:
        rows = conn.execute(
            "SELECT id, target, scan_type, timestamp, finding_count FROM scans ORDER BY id DESC"
        ).fetchall()
        return [
            ScanResult(
                id=row["id"],
                target=row["target"],
                scan_type=row["scan_type"],
                timestamp=row["timestamp"],
                finding_count=row["finding_count"],
            )
            for row in rows
        ]
    finally:
        conn.close()


def get_scan(scan_id: int) -> ScanResult | None:
    """Return one scan with its findings populated."""
    conn = _get_conn()
    try:
        scan_row = conn.execute(
            "SELECT id, target, scan_type, timestamp, finding_count FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()

        if scan_row is None:
            return None

        finding_rows = conn.execute(
            "SELECT id, scan_id, url, pattern_name, severity, redacted_value, "
            "line_number, context_snippet, validated, validation_note "
            "FROM findings WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()

        findings = [
            Finding(
                id=fr["id"],
                scan_id=fr["scan_id"],
                url=fr["url"],
                pattern_name=fr["pattern_name"],
                severity=fr["severity"],
                redacted_value=fr["redacted_value"],
                line_number=fr["line_number"],
                context_snippet=fr["context_snippet"],
                validated=bool(fr["validated"]),
                validation_note=fr["validation_note"],
            )
            for fr in finding_rows
        ]

        return ScanResult(
            id=scan_row["id"],
            target=scan_row["target"],
            scan_type=scan_row["scan_type"],
            timestamp=scan_row["timestamp"],
            finding_count=scan_row["finding_count"],
            findings=findings,
        )
    finally:
        conn.close()
