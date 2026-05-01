"""
Content Scanner Module

Extracts and analyzes hidden content from various file formats.

SECURITY NOTES (for Unifai demo):
- Extracts hidden content but does NOT flag it as suspicious
- Hidden text extraction works but no threat analysis
- EXIF extraction works but no scanning of contents
- Acts as a utility, not a security control

AFTER UNIFAI REMEDIATION:
- Extracted hidden content is flagged for review
- Automatic threat detection on extracted content
- Integration with prompt injection detector
"""

import logging
import re
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ExtractedContent:
    """Container for extracted content from files."""
    visible_text: str
    hidden_text: Optional[str] = None
    metadata: Optional[dict] = None
    encoded_content: Optional[list[str]] = None
    warnings: Optional[list[str]] = None


# ---------------------------------------------------------------------------
# Prompt-injection patterns used across multiple methods
# ---------------------------------------------------------------------------
_INJECTION_PATTERNS = [
    re.compile(r'ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)', re.IGNORECASE),
    re.compile(r'disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)', re.IGNORECASE),
    re.compile(r'forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)', re.IGNORECASE),
    re.compile(r'you\s+are\s+now\s+', re.IGNORECASE),
    re.compile(r'new\s+instructions?\s*:', re.IGNORECASE),
    re.compile(r'system\s*prompt\s*:', re.IGNORECASE),
    re.compile(r'<\s*system\s*>', re.IGNORECASE),
    re.compile(r'\[INST\]', re.IGNORECASE),
    re.compile(r'###\s*instruction', re.IGNORECASE),
    re.compile(r'act\s+as\s+(if\s+you\s+are|a\s+)', re.IGNORECASE),
    re.compile(r'pretend\s+(you\s+are|to\s+be)', re.IGNORECASE),
    re.compile(r'override\s+(safety|security|policy|guidelines?)', re.IGNORECASE),
    re.compile(r'bypass\s+(safety|security|policy|filter|guidelines?)', re.IGNORECASE),
    re.compile(r'jailbreak', re.IGNORECASE),
    re.compile(r'do\s+anything\s+now', re.IGNORECASE),
    re.compile(r'DAN\b'),
]

# ---------------------------------------------------------------------------
# PII patterns (general + Singapore-specific)
# ---------------------------------------------------------------------------
_PII_PATTERNS = {
    'email':       re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
    'phone_us':    re.compile(r'\b(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b'),
    'ssn':         re.compile(r'\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b'),
    'credit_card': re.compile(r'\b(?:\d[ \-]?){13,16}\b'),
    'ipv4':        re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
}

_SG_PII_PATTERNS = {
    'sg_nric':    re.compile(r'\b[STFG]\d{7}[A-Z]\b'),
    'sg_phone':   re.compile(r'\b(?:\+65[\s\-]?)?\d{4}[\s\-]?\d{4}\b'),
    'sg_postal':  re.compile(r'\b(?:Singapore\s*)?\d{6}\b', re.IGNORECASE),
    'sg_uen':     re.compile(r'\b\d{9}[A-Z]\b'),
}


def _contains_injection(text: str) -> bool:
    """Return True if *text* matches any known prompt-injection pattern."""
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            return True
    return False


def _sanitize_text(text: str) -> str:
    """
    Strip control characters, null bytes, invisible Unicode characters,
    and prompt-injection directives from *text*.
    Returns the sanitised string.
    """
    if not text:
        return text

    # Remove null bytes and common invisible/control characters
    text = text.replace('\x00', '')
    invisible = ['\u200b', '\u200c', '\u200d', '\ufeff']
    for ch in invisible:
        text = text.replace(ch, '')

    # Remove ASCII control characters (except newline/tab)
    text = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)

    # Strip prompt-injection directives line by line
    clean_lines = []
    for line in text.splitlines():
        if _contains_injection(line):
            clean_lines.append('[REDACTED: potential prompt injection]')
        else:
            clean_lines.append(line)
    return '\n'.join(clean_lines)


def _redact_pii(text: str) -> str:
    """Replace detected PII with placeholder tokens."""
    if not text:
        return text
    for label, pattern in _PII_PATTERNS.items():
        text = pattern.sub(f'[REDACTED_{label.upper()}]', text)
    return text


def _contains_sg_pii(text: str) -> bool:
    """Return True if *text* contains Singapore-specific PII."""
    if not text:
        return False
    for pattern in _SG_PII_PATTERNS.values():
        if pattern.search(text):
            return True
    return False


class ContentScanner:
    """
    Scans and extracts content from various file formats.

    This scanner extracts:
    - Visible text content
    - Hidden text (CSS hidden, white-on-white, etc.)
    - File metadata
    - Encoded content (base64, etc.)

    All extracted content is sanitized, scanned for prompt-injection
    patterns, and PII-redacted before being passed to the LLM.
    """

    def __init__(self):
        self.extraction_count = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_and_sanitize(self, text: str, source: str) -> tuple[str, list[str]]:
        """
        Sanitize *text* and return (sanitized_text, warnings).
        Warnings are generated when injection patterns are detected.
        """
        warnings: list[str] = []
        if _contains_injection(text):
            warnings.append(
                f"SECURITY: Prompt-injection pattern detected in {source}; content sanitized."
            )
            logger.warning(
                "Prompt injection detected",
                extra={"source": source, "preview": text[:120]}
            )
        sanitized = _sanitize_text(text)
        sanitized = _redact_pii(sanitized)
        return sanitized, warnings

    def _detect_sg_pii_and_raise(self, parts: list[str]) -> None:
        """Raise ValueError if any Singapore PII is found in *parts*."""
        combined = '\n'.join(parts)
        if _contains_sg_pii(combined):
            logger.error("Singapore PII detected in content; blocking transmission to LLM.")
            raise ValueError(
                "Content blocked: Singapore PII detected. "
                "Please remove NRIC, Singapore phone numbers, postal codes, or UEN numbers."
            )

    # ------------------------------------------------------------------
    # Public scanning methods
    # ------------------------------------------------------------------

    async def scan_html(self, html_content: str) -> ExtractedContent:
        """
        Scan HTML content for visible and hidden text.

        Hidden elements are flagged as suspicious and scanned for
        prompt-injection patterns before being returned.
        """
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_content, 'html.parser')

        # Extract visible text
        visible_text = soup.get_text(separator='\n', strip=True)

        # Extract hidden content (CSS hidden elements)
        hidden_elements = []
        warnings: list[str] = []

        # Find elements with hiding styles
        for element in soup.find_all(style=True):
            style = element.get('style', '').lower()
            if any(prop in style for prop in [
                'display:none', 'display: none',
                'visibility:hidden', 'visibility: hidden',
                'opacity:0', 'opacity: 0',
                'font-size:0', 'font-size: 0',
                'color:#fff', 'color:white', 'color: white',
            ]):
                text = element.get_text(strip=True)
                if text:
                    hidden_elements.append(text)

        # Find elements with hiding classes (common patterns)
        for element in soup.find_all(class_=re.compile(
            r'(hidden|invisible|sr-only|visually-hidden|d-none)',
            re.IGNORECASE
        )):
            text = element.get_text(strip=True)
            if text:
                hidden_elements.append(text)

        hidden_text: Optional[str] = None
        if hidden_elements:
            warnings.append(
                f"SECURITY: {len(hidden_elements)} hidden element(s) detected in HTML."
            )
            # Scan each hidden element for injection; sanitize
            safe_elements = []
            for elem_text in hidden_elements:
                sanitized, elem_warnings = self._check_and_sanitize(elem_text, "HTML hidden element")
                warnings.extend(elem_warnings)
                safe_elements.append(sanitized)
            hidden_text = '\n'.join(safe_elements)

        logger.info(
            "HTML content scanned",
            extra={
                "visible_length": len(visible_text),
                "hidden_elements_found": len(hidden_elements),
                "warnings_count": len(warnings),
            }
        )

        return ExtractedContent(
            visible_text=visible_text,
            hidden_text=hidden_text,
            warnings=warnings if warnings else None
        )

    async def scan_pdf_text(self, text_content: str) -> ExtractedContent:
        """
        Analyze extracted PDF text for hidden content indicators.
        """
        suspicious_patterns = []
        warnings: list[str] = []

        # Check for unusual whitespace patterns
        if '\x00' in text_content:
            suspicious_patterns.append("null_bytes")

        # Check for potential invisible characters
        invisible_chars = ['\u200b', '\u200c', '\u200d', '\ufeff']
        for char in invisible_chars:
            if char in text_content:
                suspicious_patterns.append(f"invisible_char_{ord(char)}")

        if suspicious_patterns:
            warnings.append(
                f"SECURITY: Suspicious patterns detected in PDF content: {suspicious_patterns}"
            )
            logger.warning(
                "Suspicious patterns in PDF",
                extra={"patterns": suspicious_patterns}
            )

        # Sanitize the PDF text
        sanitized_text, injection_warnings = self._check_and_sanitize(text_content, "PDF text")
        warnings.extend(injection_warnings)

        return ExtractedContent(
            visible_text=sanitized_text,
            hidden_text=None,
            warnings=warnings if warnings else None
        )

    async def scan_image_metadata(self, metadata: dict) -> ExtractedContent:
        """
        Scan image metadata for hidden content.

        EXIF comment fields are scanned for prompt-injection threats.
        """
        text_fields = []
        warnings: list[str] = []
        dangerous_fields = ['Comment', 'UserComment', 'ImageDescription',
                          'XPComment', 'XPSubject', 'XPTitle']

        for field in dangerous_fields:
            if field in metadata:
                value = metadata[field]
                if value:
                    raw = f"{field}: {value}"
                    sanitized, field_warnings = self._check_and_sanitize(raw, f"EXIF field '{field}'")
                    warnings.extend(field_warnings)
                    text_fields.append(sanitized)

        metadata_text: Optional[str] = '\n'.join(text_fields) if text_fields else None

        if text_fields:
            warnings.append(
                f"SECURITY: {len(text_fields)} metadata field(s) extracted and scanned."
            )

        logger.info(
            "Image metadata extracted",
            extra={
                "fields_found": len(text_fields),
                "warnings_count": len(warnings),
            }
        )

        return ExtractedContent(
            visible_text="",
            hidden_text=metadata_text,
            metadata=metadata,
            warnings=warnings if warnings else None
        )

    async def extract_base64_content(self, content: str) -> list[str]:
        """
        Extract and decode base64 encoded content.

        Each decoded string is scanned for prompt-injection / malicious
        content patterns and sanitized before being stored.
        """
        import base64 as b64

        decoded_contents = []

        # Find base64-like strings (minimum 20 chars)
        b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        potential_b64 = re.findall(b64_pattern, content)

        for match in potential_b64:
            try:
                decoded = b64.b64decode(match).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 10:  # Filter noise
                    # Scan for injection before storing
                    if _contains_injection(decoded):
                        logger.warning(
                            "Prompt injection detected in base64-decoded content; discarding.",
                            extra={"original_length": len(match), "decoded_preview": decoded[:120]}
                        )
                        # Discard malicious decoded content entirely
                        continue

                    # Sanitize and redact PII
                    sanitized = _sanitize_text(decoded)
                    sanitized = _redact_pii(sanitized)

                    decoded_contents.append(sanitized)
                    logger.debug(
                        "Base64 content decoded and sanitized",
                        extra={
                            "original_length": len(match),
                            "decoded_length": len(sanitized),
                        }
                    )
            except Exception:
                continue

        return decoded_contents

    async def combine_for_analysis(
        self,
        extracted: ExtractedContent
    ) -> str:
        """
        Combine all extracted content for LLM analysis.

        All content is sanitized, scanned for prompt-injection patterns,
        PII-redacted, and checked for Singapore PII before being returned.
        Hidden and encoded content is flagged and filtered rather than
        passed through unsanitized.
        """
        parts: list[str] = []
        warnings: list[str] = list(extracted.warnings or [])

        # --- Visible text ---
        if extracted.visible_text:
            sanitized_visible, vis_warnings = self._check_and_sanitize(
                extracted.visible_text, "visible text"
            )
            warnings.extend(vis_warnings)
            parts.append(_redact_pii(sanitized_visible))

        # --- Hidden text ---
        if extracted.hidden_text:
            warnings.append(
                "SECURITY: Hidden content detected; scanning before inclusion."
            )
            sanitized_hidden, hidden_warnings = self._check_and_sanitize(
                extracted.hidden_text, "hidden text"
            )
            warnings.extend(hidden_warnings)

            if _contains_injection(extracted.hidden_text):
                # Block the hidden content entirely
                warnings.append(
                    "SECURITY: Hidden content contained injection patterns and was blocked."
                )
                logger.warning("Hidden text blocked due to injection patterns.")
                parts.append("[REDACTED: hidden content blocked due to security policy]")
            else:
                redacted_hidden = _redact_pii(sanitized_hidden)
                parts.append(f"\n[Additional content]:\n{redacted_hidden}")

        # --- Encoded (base64-decoded) content ---
        if extracted.encoded_content:
            for i, decoded in enumerate(extracted.encoded_content):
                # encoded_content items are already sanitized by extract_base64_content,
                # but we apply a final check here as a defence-in-depth measure.
                if _contains_injection(decoded):
                    warnings.append(
                        f"SECURITY: Decoded content item {i+1} blocked due to injection patterns."
                    )
                    logger.warning(
                        "Encoded content item blocked in combine_for_analysis",
                        extra={"index": i + 1}
                    )
                    parts.append(f"[REDACTED: decoded content {i+1} blocked by security policy]")
                else:
                    sanitized_decoded = _sanitize_text(decoded)
                    sanitized_decoded = _redact_pii(sanitized_decoded)
                    parts.append(f"\n[Decoded content {i+1}]:\n{sanitized_decoded}")

        # --- Singapore PII check (raises if found) ---
        self._detect_sg_pii_and_raise(parts)

        if warnings:
            logger.warning(
                "Content security warnings during combine_for_analysis",
                extra={"warnings": warnings}
            )

        return '\n'.join(parts)


# ============================================================================
# REMEDIATED VERSION (commented out - Unifai would enable this)
# ============================================================================

# class ContentScanner:
#     """
#     SECURE VERSION - After Unifai remediation
#
#     This version:
#     - Flags hidden content as suspicious
#     - Integrates with threat detection
#     - Generates security warnings
#     - Blocks content with detected threats
#     """
#
#     async def scan_html(self, html_content: str) -> ExtractedContent:
#         """Scan with security awareness."""
#         # ... extraction code ...
#
#         warnings = []
#         if hidden_elements:
#             warnings.append(f"SECURITY: {len(hidden_elements)} hidden elements detected")
#
#             # Scan hidden content for threats
#             from .prompt_injection import PromptInjectionDetector
#             detector = PromptInjectionDetector()
#             for hidden in hidden_elements:
#                 result = await detector.scan(hidden)
#                 if result.has_violations:
#                     warnings.append(f"THREAT: Malicious content in hidden element")
#
#         return ExtractedContent(
#             visible_text=visible_text,
#             hidden_text=hidden_text,
#             warnings=warnings
#         )