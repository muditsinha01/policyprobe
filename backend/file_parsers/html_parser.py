"""
HTML Parser

Extracts text content from HTML files.

SECURITY NOTES:
- Filters hidden elements before extraction
- Scans for prompt injection and suspicious content
- Redacts PII including Singapore-specific PII
- No sensitive content previews in logs
"""

import logging
import re
import base64
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PII Redaction Helpers (General)
# ---------------------------------------------------------------------------

def _redact_general_pii(text: str) -> str:
    """Redact common PII patterns from text."""
    if not text:
        return text

    # SSN
    text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED-SSN]', text)
    # Email addresses
    text = re.sub(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
        '[REDACTED-EMAIL]', text
    )
    # Phone numbers (various formats)
    text = re.sub(
        r'\b(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b',
        '[REDACTED-PHONE]', text
    )
    # Credit card numbers
    text = re.sub(
        r'\b(?:\d[ \-]?){13,16}\b',
        '[REDACTED-CC]', text
    )
    # Dates of birth (common formats)
    text = re.sub(
        r'\b(0?[1-9]|1[0-2])[\/\-](0?[1-9]|[12]\d|3[01])[\/\-](\d{2}|\d{4})\b',
        '[REDACTED-DOB]', text
    )
    # IP addresses
    text = re.sub(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        '[REDACTED-IP]', text
    )
    # Medical record numbers (MRN)
    text = re.sub(
        r'\bMRN[:\s#]*\d{5,10}\b',
        '[REDACTED-MRN]', text, flags=re.IGNORECASE
    )
    return text


# ---------------------------------------------------------------------------
# Singapore PII Redaction Helpers
# ---------------------------------------------------------------------------

def _redact_singapore_pii(text: str) -> str:
    """Detect and redact Singapore-specific PII patterns."""
    if not text:
        return text

    # NRIC/FIN numbers: S/T/F/G followed by 7 digits and a letter
    text = re.sub(
        r'\b[STFG]\d{7}[A-Z]\b',
        '[REDACTED-NRIC]', text, flags=re.IGNORECASE
    )
    # Singapore passport numbers: E followed by 7 digits
    text = re.sub(
        r'\b[EeKk]\d{7}[A-Za-z]?\b',
        '[REDACTED-PASSPORT]', text
    )
    # Singapore mobile numbers: +65 or 65 prefix, 8-digit starting with 8 or 9
    text = re.sub(
        r'(\+65[\s\-]?|65[\s\-]?)?[89]\d{7}\b',
        '[REDACTED-SG-PHONE]', text
    )
    # Singapore bank account numbers (various formats, 10-16 digits)
    text = re.sub(
        r'\b\d{3}-\d{5,6}-\d{1,3}\b',
        '[REDACTED-BANK-ACCT]', text
    )
    # Personal email (already handled by general PII, but ensure coverage)
    # Full names heuristic: Title + Capitalized words
    text = re.sub(
        r'\b(Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+(\s+[A-Z][a-z]+){1,3}\b',
        '[REDACTED-NAME]', text
    )
    return text


def _redact_all_pii(text: str) -> str:
    """Apply all PII redaction (general + Singapore)."""
    text = _redact_general_pii(text)
    text = _redact_singapore_pii(text)
    return text


def _redact_dict_values(d: dict) -> dict:
    """Redact PII from all string values in a dict."""
    result = {}
    for k, v in d.items():
        if isinstance(v, str):
            result[k] = _redact_all_pii(v)
        else:
            result[k] = v
    return result


# ---------------------------------------------------------------------------
# Security Scanning Helpers
# ---------------------------------------------------------------------------

SUSPICIOUS_KEYWORDS = [
    'ignore previous instructions',
    'ignore all previous',
    'disregard previous',
    'forget your instructions',
    'you are now',
    'act as',
    'jailbreak',
    'prompt injection',
    'system prompt',
    'override instructions',
    'new instructions',
    'your new role',
    'pretend you are',
    'roleplay as',
]

SHELL_COMMAND_PATTERNS = [
    r'\b(rm\s+-rf|chmod|chown|sudo|wget|curl\s+http|bash\s+-c|sh\s+-c|exec\(|eval\(|os\.system)\b',
    r'[|;&`$]\s*\w+',
]

LEETSPEAK_PATTERN = re.compile(
    r'\b\w*[013457@!$]\w*\b', re.IGNORECASE
)


def _is_base64(s: str) -> bool:
    """Check if a string looks like base64-encoded content."""
    s = s.strip()
    if len(s) < 20:
        return False
    if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', s):
        try:
            decoded = base64.b64decode(s).decode('utf-8', errors='ignore')
            if len(decoded) > 10 and decoded.isprintable():
                return True
        except Exception:
            pass
    return False


def _scan_for_suspicious_content(text: str) -> list:
    """Scan text for suspicious patterns and return list of warnings."""
    warnings = []
    if not text:
        return warnings

    text_lower = text.lower()

    # Check for prompt injection keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text_lower:
            warnings.append(f"Suspicious prompt-injection keyword detected: '{keyword}'")

    # Check for base64-encoded content
    for token in text.split():
        if _is_base64(token):
            warnings.append("Base64-encoded content detected in text")
            break

    # Check for shell/binary commands
    for pattern in SHELL_COMMAND_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            warnings.append(f"Suspicious shell/binary command pattern detected")
            break

    # Check for leetspeak (heuristic: high ratio of substitution chars)
    leet_matches = LEETSPEAK_PATTERN.findall(text)
    if len(leet_matches) > 5:
        warnings.append("Possible leetspeak/obfuscated content detected")

    return warnings


# ---------------------------------------------------------------------------
# Hidden Element Detection
# ---------------------------------------------------------------------------

def _is_hidden_by_style(style_str: str) -> bool:
    """Check if an inline style string indicates hidden content."""
    if not style_str:
        return False
    style_lower = style_str.lower().replace(' ', '')
    checks = [
        'display:none',
        'visibility:hidden',
        'opacity:0',
    ]
    for check in checks:
        if check in style_lower:
            return True
    # Off-screen positioning
    if re.search(r'(left|top)\s*:\s*-\d{3,}', style_lower):
        return True
    # White text on white background (heuristic)
    if 'color:white' in style_lower or 'color:#fff' in style_lower or 'color:#ffffff' in style_lower:
        return True
    if 'color:rgb(255,255,255)' in style_lower:
        return True
    return False


def _remove_hidden_elements(soup) -> list:
    """
    Remove hidden elements from soup in-place.
    Returns list of warning strings for each hidden element removed.
    """
    warnings = []
    for element in soup.find_all(True):
        style = element.get('style', '')
        if _is_hidden_by_style(style):
            hidden_text = element.get_text(strip=True)
            if hidden_text:
                warnings.append(
                    f"Hidden element removed (style='{style}'): content suppressed"
                )
            element.decompose()
    return warnings


class HTMLParser:
    """
    Parses HTML files and extracts text content.

    Security features:
    - Filters hidden elements (display:none, visibility:hidden, off-screen, white-on-white)
    - Scans for prompt injection, base64, leetspeak, shell commands
    - Redacts PII (general and Singapore-specific)
    - No sensitive content previews in logs
    """

    def __init__(self):
        pass

    async def extract_text(self, html_content: str) -> str:
        """
        Extract visible text from HTML content, filtering hidden elements
        and redacting PII.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script and style elements
            for element in soup(['script', 'style']):
                element.decompose()

            # Remove hidden elements and collect warnings
            hidden_warnings = _remove_hidden_elements(soup)
            if hidden_warnings:
                for w in hidden_warnings:
                    logger.warning(f"HTML hidden content detected: {w}")

            text = soup.get_text(separator='\n', strip=True)

            # Redact PII
            text = _redact_all_pii(text)

            logger.info(
                "HTML text extraction complete",
                extra={
                    "text_length": len(text),
                    "hidden_elements_removed": len(hidden_warnings),
                }
            )

            return text

        except Exception as e:
            logger.error(f"HTML extraction error: {e}")
            return f"Error extracting HTML: {str(e)}"

    async def extract_visible_only(self, html_content: str) -> str:
        """
        Extract only visible text, properly filtering hidden elements.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script and style elements
            for element in soup(['script', 'style']):
                element.decompose()

            # Remove hidden elements
            hidden_warnings = _remove_hidden_elements(soup)
            if hidden_warnings:
                for w in hidden_warnings:
                    logger.warning(f"HTML hidden content filtered in extract_visible_only: {w}")

            text = soup.get_text(separator='\n', strip=True)

            # Redact PII
            text = _redact_all_pii(text)

            logger.info(
                "HTML visible-only extraction complete",
                extra={
                    "text_length": len(text),
                    "hidden_elements_removed": len(hidden_warnings),
                }
            )

            return text

        except Exception as e:
            logger.error(f"HTML visible-only extraction error: {e}")
            return f"Error extracting HTML: {str(e)}"

    async def extract_metadata(self, html_content: str) -> dict:
        """
        Extract HTML metadata (title, meta tags) with PII redaction.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')
            metadata = {}

            # Title
            title = soup.find('title')
            if title:
                metadata['title'] = title.get_text()

            # Meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name and content:
                    metadata[name] = content

            # Redact PII from metadata values
            metadata = _redact_dict_values(metadata)

            return metadata

        except Exception as e:
            logger.error(f"HTML metadata extraction error: {e}")
            return {}

    async def extract_all(self, html_content: str) -> dict:
        """
        Extract all content from HTML with security scanning and PII redaction.
        """
        warnings = []

        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script and style elements
            for element in soup(['script', 'style']):
                element.decompose()

            # Remove hidden elements and collect warnings
            hidden_warnings = _remove_hidden_elements(soup)
            warnings.extend(hidden_warnings)

            text = soup.get_text(separator='\n', strip=True)

            # Scan for suspicious content before redaction
            scan_warnings = _scan_for_suspicious_content(text)
            warnings.extend(scan_warnings)

            # Redact PII
            text = _redact_all_pii(text)

            # Extract metadata separately
            metadata = await self.extract_metadata(html_content)

            # Scan metadata values for suspicious content
            for k, v in metadata.items():
                if isinstance(v, str):
                    meta_warnings = _scan_for_suspicious_content(v)
                    for w in meta_warnings:
                        warnings.append(f"Metadata field '{k}': {w}")

            if warnings:
                logger.warning(
                    "HTML extraction completed with security warnings",
                    extra={"warning_count": len(warnings)}
                )
            else:
                logger.info(
                    "HTML extraction complete",
                    extra={"text_length": len(text)}
                )

            return {
                "text": text,
                "metadata": metadata,
                "warnings": warnings,
            }

        except Exception as e:
            logger.error(f"HTML extract_all error: {e}")
            return {
                "text": f"Error extracting HTML: {str(e)}",
                "metadata": {},
                "warnings": warnings,
            }