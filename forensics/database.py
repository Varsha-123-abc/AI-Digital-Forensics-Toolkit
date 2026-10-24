"""SQLite storage for forensic cases, evidence, and audit events."""
import hashlib
import json
from contextlib import contextmanager
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = PROJECT_ROOT / "cases" / "forensics.db"


def utc_now():
    return datetime.now(timezone.utc).isoformat()
def _calculate_event_hash(
    event_id,
    case_id,
    evidence_id,
    event_type,
    event_time,
    details_json,
    previous_hash,
):
    """Calculate a deterministic SHA-256 hash for an audit event."""
    payload = {
        "event_id": event_id,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "event_type": event_type,
        "event_time": event_time,
        "details_json": details_json,
        "previous_hash": previous_hash,
    }

    canonical_payload = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    return hashlib.sha256(canonical_payload).hexdigest()


def _insert_audit_event(
    connection,
    case_id,
    event_type,
    details,
    evidence_id=None,
    event_time=None,
):
    """Append an audit event to the global hash chain."""
    if not isinstance(details, dict):
        raise ValueError("Audit event details must be a dictionary.")

    if not isinstance(event_type, str) or not event_type.strip():
        raise ValueError("Audit event type cannot be empty.")

    try:
        details_json = json.dumps(
            details,
            sort_keys=True,
            ensure_ascii=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Audit event details must be JSON-serializable."
        ) from exc

    previous = connection.execute(
        """
        SELECT event_hash
        FROM audit_events
        ORDER BY rowid DESC
        LIMIT 1
        """
    ).fetchone()

    previous_hash = previous["event_hash"] if previous else ""
    event_id = uuid.uuid4().hex
    timestamp = event_time or utc_now()
    normalized_type = event_type.strip()

    event_hash = _calculate_event_hash(
        event_id,
        case_id,
        evidence_id,
        normalized_type,
        timestamp,
        details_json,
        previous_hash,
    )

    connection.execute(
        """
        INSERT INTO audit_events (
            event_id,
            case_id,
            evidence_id,
            event_type,
            event_time,
            details_json,
            previous_hash,
            event_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event_id,
            case_id,
            evidence_id,
            normalized_type,
            timestamp,
            details_json,
            previous_hash,
            event_hash,
        ),
    )

    return event_id

def connect_db(db_path=DEFAULT_DB_PATH):
    """Open a database connection with foreign-key enforcement enabled."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def db_connection(db_path=DEFAULT_DB_PATH):
    """Manage a SQLite connection and always close it."""
    connection = connect_db(db_path)
    try:
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db(db_path=DEFAULT_DB_PATH):
    """Create the database schema if it does not already exist."""
    with db_connection(db_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'in_progress', 'closed')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                file_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                sha256 TEXT NOT NULL
                    CHECK (length(sha256) = 64),
                file_size_bytes INTEGER NOT NULL
                    CHECK (file_size_bytes >= 0),
                mime_type_guess TEXT NOT NULL DEFAULT 'unknown',
                collected_at TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES cases(case_id)
            );

            CREATE INDEX IF NOT EXISTS idx_evidence_case_id
                ON evidence(case_id);

            CREATE INDEX IF NOT EXISTS idx_evidence_sha256
                ON evidence(sha256);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    evidence_id TEXT,
    event_type TEXT NOT NULL,
    event_time TEXT NOT NULL,
    details_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL DEFAULT '',
    event_hash TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (case_id) REFERENCES cases(case_id),
    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
);
            CREATE INDEX IF NOT EXISTS idx_audit_case_id
                ON audit_events(case_id);
            """
        )
        # Migrate older databases without resetting an existing hash chain.
        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(audit_events)"
            ).fetchall()
        }

        needs_backfill = (
            "previous_hash" not in columns
            or "event_hash" not in columns
        )

        if "previous_hash" not in columns:
            connection.execute(
                """
                ALTER TABLE audit_events
                ADD COLUMN previous_hash TEXT NOT NULL DEFAULT ''
                """
            )

        if "event_hash" not in columns:
            connection.execute(
                """
                ALTER TABLE audit_events
                ADD COLUMN event_hash TEXT NOT NULL DEFAULT ''
                """
            )

        if needs_backfill:
            events = connection.execute(
                "SELECT * FROM audit_events ORDER BY rowid"
            ).fetchall()

            previous_hash = ""

            for event in events:
                event_hash = _calculate_event_hash(
                    event["event_id"],
                    event["case_id"],
                    event["evidence_id"],
                    event["event_type"],
                    event["event_time"],
                    event["details_json"],
                    previous_hash,
                )

                connection.execute(
                    """
                    UPDATE audit_events
                    SET previous_hash = ?, event_hash = ?
                    WHERE event_id = ?
                    """,
                    (
                        previous_hash,
                        event_hash,
                        event["event_id"],
                    ),
                )

                previous_hash = event_hash

def create_case(title, description="", db_path=DEFAULT_DB_PATH):
    """Create an investigation case and record its creation event."""
    if not isinstance(title, str) or not title.strip():
        raise ValueError("Case title cannot be empty.")

    if not isinstance(description, str):
        raise ValueError("Case description must be a string.")

    case_id = f"CASE-{uuid.uuid4().hex[:12].upper()}"
    now = utc_now()

    with db_connection(db_path) as connection:
        connection.execute(
            """
            INSERT INTO cases (
                case_id, title, description, status, created_at, updated_at
            ) VALUES (?, ?, ?, 'open', ?, ?)
            """,
            (case_id, title.strip(), description.strip(), now, now),
        )

        _insert_audit_event(
            connection,
            case_id,
            "case_created",
            {"title": title.strip()},
            event_time=now,
        )
    return case_id


def add_evidence(case_id, metadata, db_path=DEFAULT_DB_PATH):
    """Register previously collected metadata against an existing case."""
    required = (
        "file_name",
        "file_path",
        "file_size_bytes",
        "sha256",
        "collected_at_utc",
    )

    if not isinstance(case_id, str) or not case_id.strip():
        raise ValueError("Case ID must be a non-empty string.")

    if not isinstance(metadata, dict):
        raise ValueError("Evidence metadata must be a dictionary.")

    if any(key not in metadata for key in required):
        raise ValueError("Evidence metadata is missing required fields.")

    filename = metadata["file_name"]
    filepath = metadata["file_path"]
    size = metadata["file_size_bytes"]
    digest = metadata["sha256"]

    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("Evidence filename cannot be empty.")

    if not isinstance(filepath, str) or not filepath.strip():
        raise ValueError("Evidence path cannot be empty.")

    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ValueError("Evidence size must be a non-negative integer.")

    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(char not in "0123456789abcdefABCDEF" for char in digest)
    ):
        raise ValueError("Evidence must have a valid SHA-256 hex digest.")

    timestamp = metadata["collected_at_utc"]
    if not isinstance(timestamp, str) or not timestamp.strip():
        raise ValueError(
            "Evidence collection timestamp must be a non-empty string."
        )

    mime_type = metadata.get("mime_type_guess", "unknown")
    if not isinstance(mime_type, str) or not mime_type.strip():
        raise ValueError("Evidence MIME type must be a non-empty string.")

    try:
        stored_metadata = json.dumps(metadata, sort_keys=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("Evidence metadata must be JSON-serializable.") from exc

    evidence_id = f"EVD-{uuid.uuid4().hex[:12].upper()}"
    now = utc_now()

    with db_connection(db_path) as connection:
        case_exists = connection.execute(
            "SELECT 1 FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()

        if case_exists is None:
            raise ValueError(f"Case does not exist: {case_id}")

        connection.execute(
            """
            INSERT INTO evidence (
                evidence_id, case_id, file_name, file_path, sha256,
                file_size_bytes, mime_type_guess, collected_at, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evidence_id,
                case_id,
                filename,
                filepath,
                digest.lower(),
                size,
                mime_type.strip(),
                timestamp.strip(),
                stored_metadata,
            ),
        )

        _insert_audit_event(
            connection,
            case_id,
            "evidence_registered",
            {
                "file_name": filename,
                "sha256": digest.lower(),
                "file_size_bytes": size,
            },
            evidence_id=evidence_id,
            event_time=now,
        )
    return evidence_id


def list_cases(db_path=DEFAULT_DB_PATH):
    """Return investigation cases, newest first."""
    with db_connection(db_path) as connection:
        rows = connection.execute(
            "SELECT * FROM cases ORDER BY created_at DESC"
        ).fetchall()

    return [dict(row) for row in rows]


def get_case(case_id, db_path=DEFAULT_DB_PATH):
    """Return a single case, or None if it does not exist."""
    with db_connection(db_path) as connection:
        row = connection.execute(
            "SELECT * FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()

    return dict(row) if row else None


def list_evidence(case_id, db_path=DEFAULT_DB_PATH):
    """Return all evidence registered to a case."""
    with db_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT * FROM evidence
            WHERE case_id = ?
            ORDER BY collected_at DESC
            """,
            (case_id,),
        ).fetchall()

    return [dict(row) for row in rows]


def list_audit_events(case_id, db_path=DEFAULT_DB_PATH):
    """Return the recorded audit events for a case."""
    with db_connection(db_path) as connection:
        rows = connection.execute(
            """
            SELECT * FROM audit_events
            WHERE case_id = ?
            ORDER BY event_time, event_id
            """,
            (case_id,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_evidence(evidence_id, case_id, db_path=DEFAULT_DB_PATH):
    """Return evidence only if it belongs to the specified case."""
    with db_connection(db_path) as connection:
        row = connection.execute(
            """
            SELECT * FROM evidence
            WHERE evidence_id = ? AND case_id = ?
            """,
            (evidence_id, case_id),
        ).fetchone()

    return dict(row) if row else None


def record_audit_event(
    case_id,
    event_type,
    details,
    evidence_id=None,
    db_path=DEFAULT_DB_PATH,
):
    """Record an audit event for a case and optional evidence item."""
    with db_connection(db_path) as connection:
        _insert_audit_event(
            connection,
            case_id,
            event_type,
            details,
            evidence_id=evidence_id,
        )
def verify_audit_chain(db_path=DEFAULT_DB_PATH):
    """Verify audit event hashes and links in insertion order."""
    checked_events = 0
    expected_previous_hash = ""

    with db_connection(db_path) as connection:
        events = connection.execute(
            "SELECT * FROM audit_events ORDER BY rowid"
        ).fetchall()

    for event in events:
        event_id = event["event_id"]

        if event["previous_hash"] != expected_previous_hash:
            return {
                "valid": False,
                "checked_events": checked_events,
                "event_id": event_id,
                "error": "previous_hash_mismatch",
            }

        calculated_hash = _calculate_event_hash(
            event["event_id"],
            event["case_id"],
            event["evidence_id"],
            event["event_type"],
            event["event_time"],
            event["details_json"],
            event["previous_hash"],
        )

        if event["event_hash"] != calculated_hash:
            return {
                "valid": False,
                "checked_events": checked_events,
                "event_id": event_id,
                "error": "event_hash_mismatch",
            }

        expected_previous_hash = event["event_hash"]
        checked_events += 1

    return {
        "valid": True,
        "checked_events": checked_events,
        "event_id": None,
        "error": None,
    }
