"""
PDF Parser

Extracts text content from PDF files.

SECURITY NOTES:
- Scans for hidden/invisible text indicators
- Detects and strips suspicious content (base64, leetspeak, shell commands, prompt injection)
- Redacts PII including Singapore-specific PII
- Populates warnings list with detected issues
- No content previews in logs
"""

import io
import re
import base64
import logging
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PII redaction helpers
# ---------------------------------------------------------------------------

# Generic PII patterns
_PII_PATTERNS = [
    # SSN
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED_SSN]'),
    # Credit card numbers (basic)
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'), '[REDACTED_CC]'),
    # Email addresses
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # Phone numbers (various formats)
    (re.compile(r'\b(?:\+?\d[\d\s\-().]{7,}\d)\b'), '[REDACTED_PHONE]'),
    # Dates of birth (common formats)
    (re.compile(r'\b(?:0?[1-9]|[12]\d|3[01])[\/\-.](?:0?[1-9]|1[0-2])[\/\-.](?:19|20)\d{2}\b'), '[REDACTED_DOB]'),
    # Names preceded by common titles
    (re.compile(r'\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b'), '[REDACTED_NAME]'),
]

# Singapore-specific PII patterns
_SG_PII_PATTERNS = [
    # NRIC/FIN: S/T/F/G followed by 7 digits and a letter
    (re.compile(r'\b[STFG]\d{7}[A-Z]\b'), '[REDACTED_NRIC]'),
    # SingPass identifiers (common prefix patterns)
    (re.compile(r'\bSingPass\s*(?:ID|id|Id)?[:\s]+\S+', re.IGNORECASE), '[REDACTED_SINGPASS]'),
    # Singapore phone numbers (+65 prefix)
    (re.compile(r'\b(?:\+65[\s\-]?)?[689]\d{7}\b'), '[REDACTED_SG_PHONE]'),
    # Singapore postal codes
    (re.compile(r'\bSingapore\s+\d{6}\b', re.IGNORECASE), '[REDACTED_SG_POSTAL]'),
    # Full names (common Singapore name patterns — title + name)
    (re.compile(r'\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Mdm)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b'), '[REDACTED_SG_NAME]'),
]


def _redact_pii(text: str) -> Tuple[str, list]:
    """Apply generic and Singapore-specific PII redaction. Returns (redacted_text, warnings)."""
    warnings = []
    for pattern, replacement in _PII_PATTERNS + _SG_PII_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            warnings.append(f"PII detected and redacted ({replacement}): {len(matches)} instance(s)")
            text = pattern.sub(replacement, text)
    return text, warnings


def _redact_metadata_pii(metadata: dict) -> Tuple[dict, list]:
    """Redact PII from string values in a metadata dict."""
    warnings = []
    clean = {}
    for key, value in metadata.items():
        if isinstance(value, str):
            redacted, w = _redact_pii(value)
            clean[key] = redacted
            warnings.extend(w)
        else:
            clean[key] = value
    return clean, warnings


# ---------------------------------------------------------------------------
# Content / prompt-injection scanning helpers
# ---------------------------------------------------------------------------

_PROMPT_INJECTION_PATTERNS = [
    re.compile(r'ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?', re.IGNORECASE),
    re.compile(r'disregard\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?', re.IGNORECASE),
    re.compile(r'you\s+are\s+now\s+(?:a|an)\s+', re.IGNORECASE),
    re.compile(r'act\s+as\s+(?:a|an)\s+', re.IGNORECASE),
    re.compile(r'new\s+instructions?:', re.IGNORECASE),
    re.compile(r'system\s*prompt', re.IGNORECASE),
    re.compile(r'<\s*(?:system|assistant|user)\s*>', re.IGNORECASE),
    re.compile(r'\[INST\]|\[\/INST\]', re.IGNORECASE),
    re.compile(r'###\s*(?:Instruction|System|Human|Assistant)', re.IGNORECASE),
]

_SHELL_COMMAND_PATTERNS = [
    re.compile(r'\b(?:bash|sh|zsh|cmd|powershell|exec|eval|system|popen)\s*[\(\[]', re.IGNORECASE),
    re.compile(r'(?:rm\s+-rf|chmod\s+\d+|chown\s+|sudo\s+|wget\s+|curl\s+http)', re.IGNORECASE),
    re.compile(r'(?:/bin/|/usr/bin/|/etc/passwd|/etc/shadow)', re.IGNORECASE),
    re.compile(r'(?:&&|\|\|)\s*\w+', re.IGNORECASE),
]

_LEETSPEAK_PATTERN = re.compile(
    r'\b(?:[a-z0-9]*(?:[013456789@$!][a-z0-9]*){3,})\b', re.IGNORECASE
)

_BASE64_PATTERN = re.compile(
    r'(?:[A-Za-z0-9+/]{40,}={0,2})'
)

_HIDDEN_TEXT_INDICATORS = [
    re.compile(r'color\s*:\s*(?:white|#fff(?:fff)?|rgba?\(255,\s*255,\s*255)', re.IGNORECASE),
    re.compile(r'font-size\s*:\s*0', re.IGNORECASE),
    re.compile(r'visibility\s*:\s*hidden', re.IGNORECASE),
    re.compile(r'display\s*:\s*none', re.IGNORECASE),
    re.compile(r'opacity\s*:\s*0', re.IGNORECASE),
]


def _is_valid_base64(s: str) -> bool:
    """Check whether a string is actually decodable base64."""
    try:
        base64.b64decode(s + '==', validate=False)
        return True
    except Exception:
        return False


def _scan_and_sanitize(text: str) -> Tuple[str, list]:
    """
    Scan text for malicious/suspicious content.
    Returns (sanitized_text, warnings).
    """
    warnings = []
    sanitized = text

    # Hidden text indicators
    for pattern in _HIDDEN_TEXT_INDICATORS:
        if pattern.search(sanitized):
            warnings.append("Hidden/invisible text indicators detected and removed")
            sanitized = pattern.sub('[HIDDEN_TEXT_REMOVED]', sanitized)

    # Base64-encoded content
    b64_matches = _BASE64_PATTERN.findall(sanitized)
    for match in b64_matches:
        if _is_valid_base64(match):
            warnings.append(f"Base64-encoded content detected and removed ({len(match)} chars)")
            sanitized = sanitized.replace(match, '[BASE64_CONTENT_REMOVED]')

    # Shell / binary commands
    for pattern in _SHELL_COMMAND_PATTERNS:
        if pattern.search(sanitized):
            warnings.append("Shell/binary command pattern detected and removed")
            sanitized = pattern.sub('[SHELL_COMMAND_REMOVED]', sanitized)

    # Prompt injection patterns
    for pattern in _PROMPT_INJECTION_PATTERNS:
        if pattern.search(sanitized):
            warnings.append("Prompt injection pattern detected and removed")
            sanitized = pattern.sub('[INJECTION_REMOVED]', sanitized)

    # Leetspeak
    leet_matches = _LEETSPEAK_PATTERN.findall(sanitized)
    if leet_matches:
        warnings.append(f"Leetspeak/obfuscated content detected ({len(leet_matches)} instance(s))")
        sanitized = _LEETSPEAK_PATTERN.sub('[OBFUSCATED_REMOVED]', sanitized)

    return sanitized, warnings


class PDFParser:
    """
    Parses PDF files and extracts text content.

    Security features:
    - Scans for hidden/invisible text, base64, leetspeak, shell commands, prompt injection
    - Redacts generic and Singapore-specific PII
    - Populates warnings list with detected issues
    - No content previews in logs
    """

    def __init__(self):
        pass

    async def extract_text(self, pdf_bytes: bytes) -> str:
        """
        Extract all text from a PDF file.

        Applies content scanning and PII redaction before returning.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            text_parts = []
            for page_num, page in enumerate(reader.pages):
                page_text = page.extract_text()
                if page_text:
                    text_parts.append(page_text)

                    logger.debug(
                        f"Extracted text from page {page_num + 1}",
                        extra={
                            "page": page_num + 1,
                            "text_length": len(page_text),
                        }
                    )

            full_text = '\n\n'.join(text_parts)

            # Scan and sanitize for malicious content
            full_text, scan_warnings = _scan_and_sanitize(full_text)
            if scan_warnings:
                for w in scan_warnings:
                    logger.warning(f"Content scan warning: {w}")

            # Redact PII (generic + Singapore-specific)
            full_text, pii_warnings = _redact_pii(full_text)
            if pii_warnings:
                for w in pii_warnings:
                    logger.warning(f"PII redaction: {w}")

            logger.info(
                "PDF text extraction complete",
                extra={
                    "total_pages": len(reader.pages),
                    "total_text_length": len(full_text)
                }
            )

            return full_text

        except Exception as e:
            logger.error(f"PDF extraction error: {e}")
            return f"Error extracting PDF: {str(e)}"

    async def extract_metadata(self, pdf_bytes: bytes) -> dict:
        """
        Extract PDF metadata with PII redaction applied to string values.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            metadata = {}
            if reader.metadata:
                for key in reader.metadata:
                    metadata[key] = reader.metadata[key]

            # Redact PII from metadata string values
            metadata, pii_warnings = _redact_metadata_pii(metadata)
            if pii_warnings:
                for w in pii_warnings:
                    logger.warning(f"Metadata PII redaction: {w}")

            return metadata

        except Exception as e:
            logger.error(f"PDF metadata extraction error: {e}")
            return {}

    async def extract_all(self, pdf_bytes: bytes) -> dict:
        """
        Extract all content from PDF with security scanning and PII redaction.
        """
        all_warnings = []

        text = await self.extract_text(pdf_bytes)
        metadata = await self.extract_metadata(pdf_bytes)

        # Re-scan combined output for any residual issues and collect warnings
        _, scan_warnings = _scan_and_sanitize(text)
        all_warnings.extend(scan_warnings)

        _, pii_warnings = _redact_pii(text)
        all_warnings.extend(pii_warnings)

        # Check metadata string values for warnings
        for value in metadata.values():
            if isinstance(value, str):
                _, mw = _redact_pii(value)
                all_warnings.extend(mw)

        return {
            "text": text,
            "metadata": metadata,
            "warnings": all_warnings
        }