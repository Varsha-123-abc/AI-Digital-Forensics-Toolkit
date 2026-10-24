"""Verify registered evidence against its recorded SHA-256 hash."""

import hmac

from forensics.file_analyzer import (
    FileChangedDuringCollection,
    analyze_file,
)


def verify_evidence_integrity(file_path, recorded_sha256):
    """Return Match, Mismatch, or File unavailable."""
    try:
        current_metadata = analyze_file(file_path)
    except FileChangedDuringCollection:
        return {
            "status": "File unavailable",
            "recorded_sha256": recorded_sha256,
            "calculated_sha256": None,
            "message": (
                "The file changed during verification. "
                "A reliable hash could not be produced."
            ),
        }
    except (OSError, ValueError, RuntimeError) as exc:
        return {
            "status": "File unavailable",
            "recorded_sha256": recorded_sha256,
            "calculated_sha256": None,
            "message": f"The file could not be verified: {exc}",
        }

    calculated_sha256 = current_metadata["sha256"]

    if hmac.compare_digest(
        calculated_sha256.lower(),
        recorded_sha256.lower(),
    ):
        return {
            "status": "Match",
            "recorded_sha256": recorded_sha256,
            "calculated_sha256": calculated_sha256,
            "message": "The current file hash matches the recorded SHA-256.",
        }

    return {
        "status": "Mismatch",
        "recorded_sha256": recorded_sha256,
        "calculated_sha256": calculated_sha256,
        "message": "The current file hash differs from the recorded SHA-256.",
    }
