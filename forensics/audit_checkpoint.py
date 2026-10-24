"""Signed, file-based checkpoints for the forensic audit chain."""
import tempfile
import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path

from forensics.database import DEFAULT_DB_PATH, db_connection, verify_audit_chain


CHECKPOINT_VERSION = 1


def _canonical_json(payload):
    """Serialize data deterministically for signing."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _load_or_create_key(key_path):
    """Load a signing key or create a new private 256-bit key."""
    path = Path(key_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        descriptor = os.open(
            str(path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
    except FileExistsError:
        key = path.read_bytes()
        if len(key) < 32:
            raise ValueError("Checkpoint signing key must be at least 32 bytes.")
        return key

    key = secrets.token_bytes(32)
    try:
        with os.fdopen(descriptor, "wb") as key_file:
            key_file.write(key)
            key_file.flush()
            os.fsync(key_file.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise

    return key


def _read_key(key_path):
    """Read an existing signing key without creating one."""
    key = Path(key_path).read_bytes()
    if len(key) < 32:
        raise ValueError("Checkpoint signing key must be at least 32 bytes.")
    return key


def _get_chain_tip(db_path):
    """Return the event count and latest audit-chain event."""
    with db_connection(db_path) as connection:
        row = connection.execute(
            """
            SELECT rowid, event_id, event_hash
            FROM audit_events
            ORDER BY rowid DESC
            LIMIT 1
            """
        ).fetchone()

        count = connection.execute(
            "SELECT COUNT(*) FROM audit_events"
        ).fetchone()[0]

    if row is None:
        return {
            "event_count": count,
            "last_rowid": None,
            "last_event_id": None,
            "last_event_hash": None,
        }

    return {
        "event_count": count,
        "last_rowid": row["rowid"],
        "last_event_id": row["event_id"],
        "last_event_hash": row["event_hash"],
    }


def create_checkpoint(
    db_path=DEFAULT_DB_PATH,
    checkpoint_path=None,
    key_path=None,
):
    """Create a signed checkpoint of a valid audit chain."""
    if checkpoint_path is None or key_path is None:
        raise ValueError("checkpoint_path and key_path must be provided.")

    chain_status = verify_audit_chain(db_path=db_path)
    if not chain_status["valid"]:
        raise ValueError(
            f"Cannot checkpoint an invalid audit chain: "
            f"{chain_status['error']}"
        )

    tip = _get_chain_tip(db_path)
    if tip["event_count"] != chain_status["checked_events"]:
        raise RuntimeError("Audit chain changed while creating checkpoint.")

    payload = {
        "version": CHECKPOINT_VERSION,
        **tip,
    }

    key = _load_or_create_key(key_path)
    signature = hmac.new(
        key,
        _canonical_json(payload),
        hashlib.sha256,
    ).hexdigest()

    document = {
        "payload": payload,
        "signature": signature,
    }

    destination = Path(checkpoint_path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    serialized = json.dumps(
        document,
        indent=2,
        sort_keys=True,
    ) + "\n"

    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(serialized)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        # Do not silently replace an existing checkpoint.
        if destination.exists():
            raise FileExistsError(
                f"Checkpoint already exists: {destination}"
            )

        # Atomic creation on the same filesystem.
        os.link(temporary_path, destination)

    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return {
        "created": True,
        **payload,
        "checkpoint_path": str(destination),
    }


def verify_checkpoint(
    db_path=DEFAULT_DB_PATH,
    checkpoint_path=None,
    key_path=None,
):
    """Verify the checkpoint signature and current audit-chain tip."""
    if checkpoint_path is None or key_path is None:
        raise ValueError("checkpoint_path and key_path must be provided.")

    try:
        document = json.loads(
            Path(checkpoint_path).read_text(encoding="utf-8")
        )
        payload = document["payload"]
        signature = document["signature"]

        if not isinstance(payload, dict) or not isinstance(signature, str):
            raise ValueError("Invalid checkpoint structure.")

        if payload.get("version") != CHECKPOINT_VERSION:
            raise ValueError("Unsupported checkpoint version.")

        expected_signature = hmac.new(
            _read_key(key_path),
            _canonical_json(payload),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_signature):
            return {
                "valid": False,
                "error": "checkpoint_signature_mismatch",
            }

    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return {
            "valid": False,
            "error": "checkpoint_unreadable_or_invalid",
        }

    chain_status = verify_audit_chain(db_path=db_path)
    if not chain_status["valid"]:
        return {
            "valid": False,
            "error": "audit_chain_invalid",
            "chain_error": chain_status["error"],
            "event_id": chain_status["event_id"],
        }

    current_tip = _get_chain_tip(db_path)

    if current_tip != {
        key: payload.get(key)
        for key in (
            "event_count",
            "last_rowid",
            "last_event_id",
            "last_event_hash",
        )
    }:
        return {
            "valid": False,
            "error": "audit_chain_checkpoint_mismatch",
            "checkpoint_event_count": payload.get("event_count"),
            "current_event_count": current_tip["event_count"],
        }

    return {
        "valid": True,
        "error": None,
        **current_tip,
    }
