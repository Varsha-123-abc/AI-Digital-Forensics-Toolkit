"""Evidence-based suspicious-file triage indicators."""

from pathlib import Path


EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".com", ".scr",
    ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".jar", ".sh", ".elf",
}

DOUBLE_EXTENSION_PATTERNS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".jpg", ".jpeg", ".png", ".txt",
}

SUSPICIOUS_NAME_PREFIXES = (
    ".",
    "~",
)

SUSPICIOUS_NAME_TERMS = (
    "payload",
    "keylogger",
    "credential_dump",
    "mimikatz",
)


def analyze_indicators(file_metadata):
    """
    Return explainable triage indicators for collected file metadata.

    This function does not determine whether a file is malware.
    """
    filename = file_metadata.get("file_name", "")
    size = file_metadata.get("file_size_bytes")

    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("Metadata must contain a valid file_name.")

    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise ValueError("Metadata must contain a non-negative file size.")

    path = Path(filename)
    name = path.name
    lowered = name.lower()
    suffix = path.suffix.lower()

    findings = []

    if suffix in EXECUTABLE_EXTENSIONS:
        findings.append({
            "indicator": "executable_or_script_extension",
            "severity": "informational",
            "reason": (
                f"The file uses the {suffix} extension, which can identify "
                "an executable or script. This is not proof of maliciousness."
            ),
        })

    suffixes = [part.lower() for part in path.suffixes]

    if (
        len(suffixes) >= 2
        and suffixes[-1] in EXECUTABLE_EXTENSIONS
        and suffixes[-2] in DOUBLE_EXTENSION_PATTERNS
    ):
        findings.append({
            "indicator": "double_extension",
            "severity": "medium",
            "reason": (
                "The filename combines a document or image extension "
                "with an executable or script extension."
            ),
        })

    if lowered.startswith(SUSPICIOUS_NAME_PREFIXES):
        findings.append({
            "indicator": "hidden_or_temporary_style_name",
            "severity": "informational",
            "reason": (
                "The filename begins with a dot or tilde. This can be "
                "normal, but may warrant context-dependent review."
            ),
        })

    matched_terms = [
        term for term in SUSPICIOUS_NAME_TERMS if term in lowered
    ]

    if matched_terms:
        findings.append({
            "indicator": "suspicious_name_keyword",
            "severity": "low",
            "reason": (
                "The filename contains a keyword associated with security "
                "tools or suspicious activity: "
                + ", ".join(matched_terms)
                + ". Filename alone is not evidence of malicious behavior."
            ),
        })

    if size == 0:
        findings.append({
            "indicator": "empty_file",
            "severity": "informational",
            "reason": (
                "The file is empty. It may be benign or incomplete; "
                "there is no content to assess."
            ),
        })

    return {
        "file_name": name,
        "indicator_count": len(findings),
        "triage_status": "review_recommended" if findings else "no_indicators",
        "findings": findings,
        "malware_verdict": "not_determined",
    }
