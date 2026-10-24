# AI Digital Forensics Toolkit

A Python and Flask-based digital forensics portfolio project for file analysis, forensic case management, evidence integrity verification, audit trails, and case report generation.

## Features

- File analysis with SHA-256 hashing and file metadata.
- Indicator analysis for potentially suspicious file characteristics.
- Forensic case management using SQLite.
- Evidence registration and integrity verification.
- Detection of evidence states: `Match`, `Mismatch`, and `File unavailable`.
- Audit trail with hash-chain integrity verification.
- Signed audit checkpoint creation and verification.
- JSON and HTML case report exports.
- Flask web dashboard and application health endpoint.
- Automated unit tests using Python's `unittest`.

## Technology Stack

- Python 3
- Flask
- SQLite
- HTML and CSS
- `unittest`

## Project Structure

```text
AI-Digital-Forensics-Toolkit/
├── app.py
├── forensics/
├── templates/
├── static/
├── tests/
├── cases/
├── reports/
├── sample_data/
├── requirements.txt
├── .gitignore
└── README.md
```

## Installation

On Kali Linux, open a terminal and navigate to the project directory:

```bash
cd ~/AI-Digital-Forensics-Toolkit
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the dependencies:

```bash
python -m pip install -r requirements.txt
```

## Run the Application

Start the Flask application:

```bash
python app.py
```

Open this address in your browser:

http://127.0.0.1:5000

The application is configured for local development. Stop the server with `Ctrl+C`.

## Basic Workflow

1. Open the dashboard.
2. Create a forensic case.
3. Analyze an authorized file.
4. Review the findings and registered evidence.
5. Verify evidence integrity.
6. Review the audit trail and its integrity status.
7. Create or verify an audit checkpoint.
8. Export the case report as JSON or HTML.

## Evidence Integrity

The integrity verifier compares the current file's SHA-256 digest with the recorded digest.

- **Match:** The hashes match at verification time.
- **Mismatch:** The hashes differ.
- **File unavailable:** The file cannot be accessed for verification.

A matching hash does not independently prove the file's origin or establish that evidence was acquired correctly. Preserve original evidence and use controlled copies when practical.

## Audit Trail

The application provides an audit event hash chain and signed audit checkpoints to help detect changes to recorded audit data.

These features are not a substitute for independently protected logs, secure key management, trusted timestamps, or a formally validated forensic process.

## Run Tests

Run the test suite from the project directory:

```bash
python -m unittest discover -s tests -v
```

Check application syntax:

```bash
python -m py_compile app.py
```

## Configuration and Data Safety

The Flask session secret can be supplied using the `FORENSICS_SECRET_KEY` environment variable. Audit checkpoint files and their signing key are stored in user-level application directories by default.

Do not publish real case databases, evidence files, private reports, signing keys, credentials, or other sensitive forensic artifacts.

Review the Git staging list before every commit. Ignore rules do not automatically remove files that have already been tracked.

## Limitations

This is a learning and portfolio project, not a certified or independently validated forensic product. Findings require analyst interpretation, and indicator results may require further investigation.

## License

No license has been specified. Add an appropriate license before permitting others to reuse, modify, or redistribute the project.
