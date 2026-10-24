"""Local web dashboard for the AI Digital Forensics Toolkit."""
from pathlib import Path

from forensics.audit_checkpoint import create_checkpoint, verify_checkpoint
import json
import os
from datetime import datetime, timezone
from io import BytesIO

from flask import Flask, abort, flash, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename

from forensics.database import (
    DEFAULT_DB_PATH,
    add_evidence,
    create_case,
    get_case,
    get_evidence,
    init_db,
    list_audit_events,
    list_cases,
    list_evidence,
    record_audit_event,
    verify_audit_chain,
)
from forensics.file_analyzer import (
    FileChangedDuringCollection,
    analyze_file,
)
from forensics.indicator_analyzer import analyze_indicators
from forensics.integrity_verifier import verify_evidence_integrity


app = Flask(__name__)
app.secret_key = os.environ.get("FORENSICS_SECRET_KEY") or os.urandom(32)

# The database path is configurable, allowing tests to use temporary databases.
app.config["DATABASE_PATH"] = str(DEFAULT_DB_PATH)
checkpoint_dir = Path.home() / ".local" / "share" / "ai-digital-forensics-toolkit"
key_dir = Path.home() / ".config" / "ai-digital-forensics-toolkit"

app.config["CHECKPOINT_PATH"] = str(checkpoint_dir / "audit-checkpoint.json")
app.config["CHECKPOINT_KEY_PATH"] = str(key_dir / "checkpoint.key")
init_db(app.config["DATABASE_PATH"])


@app.template_filter("pretty_json")
def pretty_json(value):
    """Format JSON strings or Python objects for display."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return value

    return json.dumps(value, indent=2, sort_keys=True)


@app.get("/")
def dashboard():
    db_path = app.config["DATABASE_PATH"]
    cases = list_cases(db_path=db_path)
    evidence_count = sum(
        len(list_evidence(case["case_id"], db_path=db_path))
        for case in cases
    )

    return render_template(
        "dashboard.html",
        cases=cases,
        evidence_count=evidence_count,
    )


@app.post("/cases")
def new_case():
    db_path = app.config["DATABASE_PATH"]
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()

    try:
        case_id = create_case(title, description, db_path=db_path)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("dashboard"))

    flash(f"Investigation case created: {case_id}", "success")
    return redirect(url_for("case_detail", case_id=case_id))
@app.post("/cases/<case_id>/audit-checkpoint/create")
def create_audit_checkpoint_route(case_id):
    db_path = app.config["DATABASE_PATH"]

    if get_case(case_id, db_path=db_path) is None:
        abort(404)

    try:
        result = create_checkpoint(
            db_path=db_path,
            checkpoint_path=app.config["CHECKPOINT_PATH"],
            key_path=app.config["CHECKPOINT_KEY_PATH"],
        )
    except FileExistsError:
        flash("A checkpoint already exists. Verify it before creating another.", "error")
    except (ValueError, RuntimeError, OSError) as exc:
        flash(f"Checkpoint creation failed: {exc}", "error")
    else:
        flash(
            f"Signed checkpoint created for {result['event_count']} audit events.",
            "success",
        )

    return redirect(url_for("case_detail", case_id=case_id))


@app.post("/cases/<case_id>/audit-checkpoint/verify")
def verify_audit_checkpoint_route(case_id):
    db_path = app.config["DATABASE_PATH"]

    if get_case(case_id, db_path=db_path) is None:
        abort(404)

    try:
        result = verify_checkpoint(
            db_path=db_path,
            checkpoint_path=app.config["CHECKPOINT_PATH"],
            key_path=app.config["CHECKPOINT_KEY_PATH"],
        )
    except (ValueError, RuntimeError, OSError) as exc:
        flash(f"Checkpoint verification failed: {exc}", "error")
    else:
        if result.get("valid"):
            flash("Audit checkpoint verification passed.", "success")
        else:
            flash(
                f"Checkpoint verification failed: "
                f"{result.get('error', 'Unknown error')}",
                "error",
            )

    return redirect(url_for("case_detail", case_id=case_id))

@app.get("/cases/<case_id>")
def case_detail(case_id):
    db_path = app.config["DATABASE_PATH"]
    case = get_case(case_id, db_path=db_path)

    if case is None:
        flash("Investigation case not found.", "error")
        return redirect(url_for("dashboard"))

    evidence_records = list_evidence(case_id, db_path=db_path)
    audit_events = list_audit_events(case_id, db_path=db_path)
    audit_chain_status = verify_audit_chain(db_path=db_path)
    checkpoint_path = Path(app.config["CHECKPOINT_PATH"])
    checkpoint_status = None

    if checkpoint_path.exists():
        try:
            checkpoint_status = verify_checkpoint(
                db_path=db_path,
                checkpoint_path=app.config["CHECKPOINT_PATH"],
                key_path=app.config["CHECKPOINT_KEY_PATH"],
            )
        except (ValueError, RuntimeError, OSError) as exc:
            checkpoint_status = {
                "valid": False,
                "error": str(exc),
            }

    # Default every evidence item to Not verified.
    integrity_statuses = {
        item["evidence_id"]: {
            "status": "Not verified",
            "message": "No integrity verification has been recorded.",
            "event_time": None,
        }
        for item in evidence_records
    }

    # Audit events are ordered oldest to newest, so later verification
    # events replace earlier statuses for the same evidence item.
    for event in audit_events:
        if event["event_type"] != "evidence_integrity_verification":
            continue

        evidence_id = event["evidence_id"]
        if evidence_id not in integrity_statuses:
            continue

        try:
            details = json.loads(event["details_json"])
        except (TypeError, json.JSONDecodeError):
            continue

        if not isinstance(details, dict):
            continue

        status = details.get("status")
        if status not in ("Match", "Mismatch", "File unavailable"):
            continue

        integrity_statuses[evidence_id] = {
            "status": status,
            "message": details.get("message", ""),
            "event_time": event["event_time"],
        }

    return render_template(
        "case_detail.html",
        case=case,
        evidence=evidence_records,
        events=audit_events,
        integrity_statuses=integrity_statuses,
        audit_chain_status=audit_chain_status,
        checkpoint_status=checkpoint_status,
        db_path=db_path,
    )


def build_integrity_statuses(evidence_records, audit_events):
    """Return the latest recorded integrity status for each evidence item."""
    statuses = {
        item["evidence_id"]: {
            "status": "Not verified",
            "message": "No integrity verification has been recorded.",
            "event_time": None,
        }
        for item in evidence_records
    }

    for event in audit_events:
        if event["event_type"] != "evidence_integrity_verification":
            continue

        evidence_id = event["evidence_id"]
        if evidence_id not in statuses:
            continue

        try:
            details = json.loads(event["details_json"])
        except (TypeError, json.JSONDecodeError):
            continue

        if not isinstance(details, dict):
            continue

        status = details.get("status")
        if status not in ("Match", "Mismatch", "File unavailable"):
            continue

        statuses[evidence_id] = {
            "status": status,
            "message": details.get("message", ""),
            "event_time": event["event_time"],
        }

    return statuses


@app.get("/cases/<case_id>/report")
def export_case_report(case_id):
    """Download a JSON report containing a case's recorded forensic data."""
    db_path = app.config["DATABASE_PATH"]
    case = get_case(case_id, db_path=db_path)

    if case is None:
        abort(404)

    evidence_records = []
    for item in list_evidence(case_id, db_path=db_path):
        try:
            metadata = json.loads(item["metadata_json"])
        except (TypeError, json.JSONDecodeError):
            metadata = {"raw_metadata": item["metadata_json"]}

        evidence_records.append({
            "evidence_id": item["evidence_id"],
            "file_name": item["file_name"],
            "file_path": item["file_path"],
            "sha256": item["sha256"],
            "file_size_bytes": item["file_size_bytes"],
            "mime_type_guess": item["mime_type_guess"],
            "collected_at": item["collected_at"],
            "metadata": metadata,
        })

    audit_records = []
    for event in list_audit_events(case_id, db_path=db_path):
        try:
            details = json.loads(event["details_json"])
        except (TypeError, json.JSONDecodeError):
            details = {"raw_details": event["details_json"]}

        audit_records.append({
            "event_id": event["event_id"],
            "evidence_id": event["evidence_id"],
            "event_type": event["event_type"],
            "event_time": event["event_time"],
            "details": details,
        })


    integrity_statuses = build_integrity_statuses(
        evidence_records,
        [
            {
                "event_id": event["event_id"],
                "evidence_id": event["evidence_id"],
                "event_type": event["event_type"],
                "event_time": event["event_time"],
                "details_json": json.dumps(event["details"]),
            }
            for event in audit_records
        ],
    )

    audit_chain_status = verify_audit_chain(db_path=db_path)

    checkpoint_path = Path(app.config["CHECKPOINT_PATH"])
    checkpoint_status = None

    if checkpoint_path.exists():
        try:
            checkpoint_status = verify_checkpoint(
                db_path=db_path,
                checkpoint_path=app.config["CHECKPOINT_PATH"],
                key_path=app.config["CHECKPOINT_KEY_PATH"],
            )
        except (ValueError, RuntimeError, OSError) as exc:
            checkpoint_status = {
                "valid": False,
                "error": str(exc),
            }

    report = {
        "report_type": "AI Digital Forensics Toolkit Case Report",
        "report_generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "case": case,
        "evidence": evidence_records,
        "evidence_integrity_statuses": integrity_statuses,
        "audit_events": audit_records,
        "audit_chain_verification": audit_chain_status,
        "signed_checkpoint_verification": checkpoint_status,
        "limitations": [
            "Indicator findings support triage and are not a malware verdict.",
            "No indicators detected does not prove that a file is safe.",
            "MIME type is a filename-based guess unless independently verified.",
            "A SHA-256 hash alone does not prove authenticity or chain of custody.",
            "Audit-chain verification checks recorded event hashes and links.",
            "A valid signed checkpoint does not independently prove that evidence is authentic.",
        ],
    }


    payload = json.dumps(report, indent=2, sort_keys=True).encode("utf-8")
    download_name = f"{secure_filename(case['case_id']) or 'case'}-report.json"

    return send_file(
        BytesIO(payload),
        mimetype="application/json",
        as_attachment=True,
        download_name=download_name,
    )



@app.get("/cases/<case_id>/report/html")
def export_case_html_report(case_id):
    """Download a readable HTML report for a recorded case."""
    db_path = app.config["DATABASE_PATH"]
    case = get_case(case_id, db_path=db_path)

    if case is None:
        abort(404)

    evidence_records = []
    for item in list_evidence(case_id, db_path=db_path):
        try:
            metadata = json.loads(item["metadata_json"])
        except (TypeError, json.JSONDecodeError):
            metadata = {"raw_metadata": item["metadata_json"]}

        evidence_records.append({
            "evidence_id": item["evidence_id"],
            "file_name": item["file_name"],
            "file_path": item["file_path"],
            "sha256": item["sha256"],
            "file_size_bytes": item["file_size_bytes"],
            "mime_type_guess": item["mime_type_guess"],
            "collected_at": item["collected_at"],
            "metadata": metadata,
        })

    audit_records = []
    for event in list_audit_events(case_id, db_path=db_path):
        try:
            details = json.loads(event["details_json"])
        except (TypeError, json.JSONDecodeError):
            details = {"raw_details": event["details_json"]}

        audit_records.append({
            "event_id": event["event_id"],
            "evidence_id": event["evidence_id"],
            "event_type": event["event_type"],
            "event_time": event["event_time"],
            "details": details,
        })


    integrity_statuses = build_integrity_statuses(
        evidence_records,
        [
            {
                "event_id": event["event_id"],
                "evidence_id": event["evidence_id"],
                "event_type": event["event_type"],
                "event_time": event["event_time"],
                "details_json": json.dumps(event["details"]),
            }
            for event in audit_records
        ],
    )

    audit_chain_status = verify_audit_chain(db_path=db_path)

    checkpoint_path = Path(app.config["CHECKPOINT_PATH"])
    checkpoint_status = None

    if checkpoint_path.exists():
        try:
            checkpoint_status = verify_checkpoint(
                db_path=db_path,
                checkpoint_path=app.config["CHECKPOINT_PATH"],
                key_path=app.config["CHECKPOINT_KEY_PATH"],
            )
        except (ValueError, RuntimeError, OSError) as exc:
            checkpoint_status = {
                "valid": False,
                "error": str(exc),
            }

    report = {
        "report_generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "case": case,
        "evidence": evidence_records,
        "evidence_integrity_statuses": integrity_statuses,
        "audit_events": audit_records,
        "audit_chain_verification": audit_chain_status,
        "signed_checkpoint_verification": checkpoint_status,
        "limitations": [
            "Indicator findings support triage and are not a malware verdict.",
            "No indicators detected does not prove that a file is safe.",
            "MIME type is a filename-based guess unless independently verified.",
            "A SHA-256 hash alone does not prove authenticity or chain of custody.",
            "Audit-chain verification checks recorded event hashes and links.",
            "A valid signed checkpoint does not independently prove that evidence is authentic.",
        ],
    }

    html_payload = render_template(
        "forensic_report.html",
        report=report,
    ).encode("utf-8")

    download_name = (
        f"{secure_filename(case['case_id']) or 'case'}-report.html"
    )
    return send_file(
        BytesIO(html_payload),
        mimetype="text/html",
        as_attachment=True,
        download_name=download_name,
    )


@app.post("/cases/<case_id>/analyze")
def analyze_evidence(case_id):
    db_path = app.config["DATABASE_PATH"]
    case = get_case(case_id, db_path=db_path)

    if case is None:
        flash("Investigation case not found.", "error")
        return redirect(url_for("dashboard"))

    file_path = request.form.get("file_path", "").strip()

    if not file_path:
        flash("Enter a file path to analyze.", "error")
        return redirect(url_for("case_detail", case_id=case_id))

    try:
        metadata = analyze_file(file_path)
        metadata["indicators"] = analyze_indicators(metadata)
        evidence_id = add_evidence(case_id, metadata, db_path=db_path)
    except (FileChangedDuringCollection, OSError, ValueError) as exc:
        flash(f"Analysis failed: {exc}", "error")
        return redirect(url_for("case_detail", case_id=case_id))

    flash(f"Evidence registered successfully: {evidence_id}", "success")
    return redirect(url_for("case_detail", case_id=case_id))


@app.post("/cases/<case_id>/evidence/<evidence_id>/verify")
def verify_evidence(case_id, evidence_id):
    """Verify evidence against its originally recorded SHA-256 hash."""
    db_path = app.config["DATABASE_PATH"]

    case = get_case(case_id, db_path=db_path)
    if case is None:
        abort(404)

    evidence = get_evidence(
        evidence_id,
        case_id,
        db_path=db_path,
    )
    if evidence is None:
        abort(404)

    result = verify_evidence_integrity(
        evidence["file_path"],
        evidence["sha256"],
    )

    record_audit_event(
        case_id=case_id,
        evidence_id=evidence_id,
        event_type="evidence_integrity_verification",
        details=result,
        db_path=db_path,
    )

    category = "success" if result["status"] == "Match" else "error"
    flash(
        f"Integrity verification — {result['status']}: "
        f"{result['message']}",
        category,
    )
    return redirect(url_for("case_detail", case_id=case_id))


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
