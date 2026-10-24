"""Basic forensic file metadata collection and SHA-256 hashing."""

import hashlib
import mimetypes
import os
import stat
from datetime import datetime, timezone
from pathlib import Path


CHUNK_SIZE = 1024 * 1024  # 1 MiB


class FileChangedDuringCollection(Exception):
    """Raised when the file changes during evidence collection."""


def _utc_timestamp(timestamp):
    """Convert a Unix timestamp into an ISO-8601 UTC timestamp."""
    return datetime.fromtimestamp(
        timestamp, tz=timezone.utc
    ).isoformat()


def analyze_file(file_path):
    """
    Collect basic metadata and SHA-256 for a regular file.

    The analyzer reads the file but does not intentionally modify it.
    A detected change causes collection to fail rather than returning
    a potentially inconsistent hash.
    """
    path = Path(file_path).expanduser().resolve(strict=True)

    if not path.is_file():
        raise ValueError("The supplied path is not a regular file.")

    collected_at = datetime.now(timezone.utc).isoformat()
    digest = hashlib.sha256()
    bytes_read = 0

    with path.open("rb") as evidence_file:
        before = os.fstat(evidence_file.fileno())

        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Only regular files can be analyzed.")

        while True:
            chunk = evidence_file.read(CHUNK_SIZE)
            if not chunk:
                break

            digest.update(chunk)
            bytes_read += len(chunk)

        after = os.fstat(evidence_file.fileno())

    # Detect common signs of modification during collection.
    before_signature = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    after_signature = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )

    if before_signature != after_signature or bytes_read != after.st_size:
        raise FileChangedDuringCollection(
            "File metadata changed during collection; no result returned."
        )

    mime_type, _ = mimetypes.guess_type(path.name)

    return {
        "file_name": path.name,
        "file_path": str(path),
        "file_size_bytes": after.st_size,
        "sha256": digest.hexdigest(),
        "mime_type_guess": mime_type or "unknown",
        "modified_time_utc": _utc_timestamp(after.st_mtime),
        "changed_time_utc": _utc_timestamp(after.st_ctime),
        "collected_at_utc": collected_at,
        "collection_status": "completed",
        "change_detected": False,
    }
