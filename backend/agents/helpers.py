"""Shared helper functions for the PolicyProbe agents."""

import base64
import re
import unicodedata
from typing import Any
from uuid import uuid4


# ---------------------------------------------------------------------------
# PII redaction helpers
# ---------------------------------------------------------------------------

# Generic / international PII patterns
_PII_PATTERNS: list[tuple[str, str]] = [
    # SSN (US)
    (r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED-SSN]"),
    # Passport numbers (generic alphanumeric 6-9 chars)
    (r"\b[A-Z]{1,2}\d{6,9}\b", "[REDACTED-PASSPORT]"),
    # Credit card numbers (Visa, MC, Amex, etc.)
    (r"\b(?:\d[ -]?){13,16}\b", "[REDACTED-CC]"),
    # Email addresses
    (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "[REDACTED-EMAIL]"),
    # Phone numbers (various formats)
    (r"\b(?:\+?\d[\d\s\-().]{7,}\d)\b", "[REDACTED-PHONE]"),
    # Dates of birth (common formats)
    (r"\b(?:0?[1-9]|[12]\d|3[01])[\/\-.](?:0?[1-9]|1[0-2])[\/\-.](?:19|20)\d{2}\b", "[REDACTED-DOB]"),
    (r"\b(?:19|20)\d{2}[\/\-.](?:0?[1-9]|1[0-2])[\/\-.](?:0?[1-9]|[12]\d|3[01])\b", "[REDACTED-DOB]"),
]

# Singapore-specific PII patterns
_SG_PII_PATTERNS: list[tuple[str, str]] = [
    # NRIC / FIN  (S/T/F/G followed by 7 digits and a letter)
    (r"\b[STFG]\d{7}[A-Z]\b", "[REDACTED-NRIC]"),
    # Singapore passport (E followed by 7 digits)
    (r"\bE\d{7}\b", "[REDACTED-SG-PASSPORT]"),
    # Singapore bank account numbers (6-10 digits, sometimes hyphenated)
    (r"\b\d{3}-\d{5,6}-\d\b", "[REDACTED-BANK-ACCT]"),
    # Singapore phone numbers (+65 prefix or local 8-digit starting with 6/8/9)
    (r"\b(?:\+65[\s\-]?)?[689]\d{7}\b", "[REDACTED-SG-PHONE]"),
    # Full name pattern (Mr/Mrs/Ms/Dr followed by capitalised words)
    (r"\b(?:Mr|Mrs|Ms|Dr|Miss)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b", "[REDACTED-NAME]"),
]

# Prompt injection / malicious content patterns
_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:a|an)\s+", re.IGNORECASE),
    re.compile(r"act\s+as\s+(?:a|an)\s+", re.IGNORECASE),
    re.compile(r"pretend\s+(?:you\s+are|to\s+be)\s+", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
    re.compile(r"<\s*/?(?:system|prompt|instruction|command)\s*>", re.IGNORECASE),
    re.compile(r"\[\s*(?:SYSTEM|INST|INSTRUCTION)\s*\]", re.IGNORECASE),
    re.compile(r"###\s*(?:system|instruction|prompt)", re.IGNORECASE),
    # Shell / binary content
    re.compile(r"(?:/bin/|/usr/bin/|bash\s+-[ci]|sh\s+-[ci]|cmd\.exe|powershell)", re.IGNORECASE),
    re.compile(r"(?:eval|exec|system|popen|subprocess)\s*\(", re.IGNORECASE),
    # Leetspeak variants of "ignore instructions"
    re.compile(r"1gn[o0]r[e3]\s+.*?1n5truct10n5", re.IGNORECASE),
]

# Control / invisible character pattern
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

# Maximum allowed length for extracted content before truncation
_MAX_CONTENT_LENGTH = 4000


def redact_pii(text: str) -> str:
    """Redact common PII categories from *text* using regex patterns.

    Covers SSNs, passport numbers, credit card numbers, email addresses,
    phone numbers, dates of birth, and Singapore-specific identifiers.
    """
    for pattern, replacement in _PII_PATTERNS:
        text = re.sub(pattern, replacement, text)
    for pattern, replacement in _SG_PII_PATTERNS:
        text = re.sub(pattern, replacement, text)
    return text


def _detect_sg_pii(text: str) -> list[str]:
    """Return a list of Singapore PII category names found in *text*."""
    found: list[str] = []
    labels = ["NRIC/FIN", "SG-Passport", "Bank-Account", "SG-Phone", "Full-Name"]
    for (pattern, _), label in zip(_SG_PII_PATTERNS, labels):
        if re.search(pattern, text):
            found.append(label)
    return found


def sanitize_extracted_content(content: str) -> str:
    """Sanitize file-extracted content before it is embedded in an LLM prompt.

    Steps applied in order:
    1. Strip control / invisible characters.
    2. Normalise unicode to NFC to surface hidden homoglyph attacks.
    3. Detect and neutralise prompt-injection patterns.
    4. Decode and screen base64 segments for hidden prompts.
    5. Redact PII (generic + Singapore-specific).
    6. Truncate to *_MAX_CONTENT_LENGTH* characters.
    """
    if not content:
        return content

    # 1. Remove control characters (keep \t, \n, \r)
    content = _CONTROL_CHAR_RE.sub("", content)

    # 2. Unicode normalisation
    content = unicodedata.normalize("NFC", content)

    # 3. Neutralise prompt-injection patterns by prefixing with a warning marker
    for pattern in _INJECTION_PATTERNS:
        content = pattern.sub("[INJECTION-ATTEMPT-REMOVED]", content)

    # 4. Screen base64 segments
    def _screen_b64(match: re.Match) -> str:
        candidate = match.group(0)
        if len(candidate) % 4 != 0:
            return candidate
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
        except Exception:
            return candidate
        # Check decoded text for injection patterns
        for pat in _INJECTION_PATTERNS:
            if pat.search(decoded):
                return "[BASE64-INJECTION-REMOVED]"
        return candidate

    content = re.sub(r"[A-Za-z0-9+/=]{24,}", _screen_b64, content)

    # 5. Redact PII
    content = redact_pii(content)

    # 6. Truncate
    if len(content) > _MAX_CONTENT_LENGTH:
        content = content[:_MAX_CONTENT_LENGTH] + "... [TRUNCATED]"

    return content


def build_file_summary(
    file_contents: list[dict[str, Any]],
    include_raw_text: bool = False,
) -> str:
    if not file_contents:
        return "No files were attached."

    sections = []
    for file_data in file_contents:
        extracted_content = file_data.get("extracted_content", "")

        # Sanitize and redact before any further processing
        extracted_content = sanitize_extracted_content(extracted_content)

        if not include_raw_text and len(extracted_content) > 600:
            extracted_content = extracted_content[:600] + "..."

        sections.append(
            f"Filename: {file_data.get('filename', 'unknown')}\n"
            f"Content Type: {file_data.get('content_type', 'unknown')}\n"
            f"Extracted Content:\n{extracted_content}"
        )

    return "\n\n".join(sections)


def extract_reference_number(message: str, prefix: str) -> str:
    match = re.search(r"\b([A-Z]{2,}-\d{2,}|\d{4,})\b", message or "")
    if match:
        return str(match.group(1))
    return f"{prefix}-{str(uuid4())[:8].upper()}"


def decode_base64_segments(content: str) -> list[str]:
    decoded_segments: list[str] = []
    for candidate in extract_base64_candidates(content):
        if len(candidate) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(candidate, validate=True).decode("utf-8")
        except Exception:
            continue
        if decoded.strip():
            decoded_segments.append(decoded.strip())
    return decoded_segments


def extract_base64_candidates(content: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9+/=]{24,}", content or "")