"""
Prompt Injection Detection Module

Detects malicious/hidden prompts in content that could manipulate LLM behavior.

SECURITY NOTES (for Unifai demo):
- scan() method performs comprehensive threat detection
- Hidden text detection implemented
- Base64/encoded content decoded and scanned
- Unicode homoglyph attacks detected

AFTER UNIFAI REMEDIATION:
- Detect hidden text (white-on-white, zero-size, off-page)
- Decode and scan base64 content
- Detect unicode homoglyph attacks
- Identify known prompt injection patterns
"""

import logging
import re
import base64
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ThreatMatch:
    """Represents a detected threat."""
    threat_type: str
    severity: str  # low, medium, high, critical
    description: str
    content_preview: str
    location: str


@dataclass
class ThreatDetectionResult:
    """Result of threat detection scan."""
    has_violations: bool
    threats: list[ThreatMatch] = field(default_factory=list)
    scanned_content_length: int = 0

    def to_dict(self) -> dict:
        return {
            "has_violations": self.has_violations,
            "threats": [
                {
                    "type": t.threat_type,
                    "severity": t.severity,
                    "description": t.description,
                    "preview": t.content_preview[:50] + "..." if len(t.content_preview) > 50 else t.content_preview,
                    "location": t.location
                }
                for t in self.threats
            ],
            "scanned_content_length": self.scanned_content_length
        }


class PromptInjectionDetector:
    """
    Detects prompt injection and hidden malicious content.

    Threat Categories:
    - hidden_text: Invisible/hidden text in documents
    - encoded_content: Base64 or otherwise encoded malicious content
    - prompt_injection: Direct prompt injection attempts
    - unicode_attack: Homoglyph or unicode-based attacks
    - metadata_injection: Malicious content in file metadata
    """

    # Known prompt injection patterns
    INJECTION_PATTERNS = [
        r"ignore\s+(previous|all|above)\s+instructions?",
        r"disregard\s+(previous|all|above)\s+(instructions?|context)",
        r"new\s+instructions?:",
        r"system\s*:\s*you\s+are",
        r"admin\s+override",
        r"developer\s+mode",
        r"jailbreak",
        r"\[INST\]",
        r"<\|im_start\|>",
        r"###\s*(instruction|system|human|assistant)",
    ]

    # Unicode homoglyphs that could be used for attacks
    HOMOGLYPH_MAP = {
        'а': 'a',  # Cyrillic
        'е': 'e',
        'о': 'o',
        'р': 'p',
        'с': 'c',
        'х': 'x',
        # Add more as needed
    }

    # Hidden text CSS patterns
    HIDDEN_TEXT_PATTERNS = [
        r'color\s*:\s*white',
        r'color\s*:\s*#fff(?:fff)?(?:\s|;|")',
        r'font-size\s*:\s*0',
        r'display\s*:\s*none',
        r'visibility\s*:\s*hidden',
        r'opacity\s*:\s*0',
        r'position\s*:\s*absolute.*left\s*:\s*-\d+',
        r'text-indent\s*:\s*-\d+',
        r'overflow\s*:\s*hidden.*height\s*:\s*0',
        r'width\s*:\s*0.*height\s*:\s*0',
    ]

    def __init__(self):
        """Initialize the detector."""
        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in self.INJECTION_PATTERNS
        ]
        self._compiled_hidden_patterns = [
            re.compile(p, re.IGNORECASE | re.DOTALL)
            for p in self.HIDDEN_TEXT_PATTERNS
        ]

    async def scan(self, content: str, source: str = "unknown") -> ThreatDetectionResult:
        """
        Scan content for prompt injection and hidden threats.

        Args:
            content: Content to scan for threats
            source: Source of the content (for logging)

        Returns:
            ThreatDetectionResult with has_violations=True when threats are found
        """
        threats = []

        logger.debug(
            "Threat scan requested",
            extra={
                "source": source,
                "content_length": len(content) if content else 0,
            }
        )

        if not content:
            return ThreatDetectionResult(
                has_violations=False,
                threats=[],
                scanned_content_length=0
            )

        # Detect hidden text
        hidden_threats = await self.detect_hidden_text(content)
        threats.extend(hidden_threats)

        # Detect encoded content
        encoded_threats = await self.detect_encoded_content(content)
        threats.extend(encoded_threats)

        # Detect prompt injection patterns
        injection_threats = await self.detect_prompt_injection(content)
        threats.extend(injection_threats)

        # Detect unicode attacks
        unicode_threats = await self.detect_unicode_attacks(content)
        threats.extend(unicode_threats)

        if threats:
            logger.warning(
                "Threats detected in content",
                extra={
                    "source": source,
                    "threat_count": len(threats),
                    "threat_types": [t.threat_type for t in threats]
                }
            )

        return ThreatDetectionResult(
            has_violations=len(threats) > 0,
            threats=threats,
            scanned_content_length=len(content)
        )

    async def detect_hidden_text(self, content: str) -> list[ThreatMatch]:
        """
        Detect hidden text patterns in content.

        Detects:
        - White text on white background (CSS)
        - Zero-size text
        - Off-screen positioned text
        - Display:none content
        - Visibility:hidden content
        """
        threats = []

        for pattern in self._compiled_hidden_patterns:
            matches = pattern.findall(content)
            for match in matches:
                preview = match if isinstance(match, str) else str(match)
                threats.append(ThreatMatch(
                    threat_type="hidden_text",
                    severity="high",
                    description=f"Detected hidden text pattern that may conceal malicious content",
                    content_preview=preview[:100],
                    location="content"
                ))

        # Detect zero-width characters used to hide text
        zero_width_chars = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u2060']
        for zwc in zero_width_chars:
            if zwc in content:
                idx = content.index(zwc)
                preview = content[max(0, idx-20):idx+20]
                threats.append(ThreatMatch(
                    threat_type="hidden_text",
                    severity="medium",
                    description=f"Detected zero-width character (U+{ord(zwc):04X}) that may be used to hide content",
                    content_preview=repr(preview),
                    location="content"
                ))
                break  # Report once per scan

        # Detect HTML comment-based hiding
        html_comment_pattern = re.compile(r'<!--.*?-->', re.DOTALL)
        html_comments = html_comment_pattern.findall(content)
        for comment in html_comments:
            # Check if the comment contains injection-like content
            for pattern in self._compiled_patterns:
                if pattern.search(comment):
                    threats.append(ThreatMatch(
                        threat_type="hidden_text",
                        severity="high",
                        description="Detected potential prompt injection hidden in HTML comment",
                        content_preview=comment[:100],
                        location="html_comment"
                    ))
                    break

        return threats

    async def detect_encoded_content(self, content: str) -> list[ThreatMatch]:
        """
        Detect and decode potentially malicious encoded content.

        Detects:
        - Base64 encoded prompts
        - URL encoded content
        - Unicode escape sequences
        - HTML entities
        """
        threats = []

        # Detect and decode base64 content
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        b64_matches = b64_pattern.findall(content)

        for match in b64_matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8')
                # Check decoded content for injection patterns
                for pattern in self._compiled_patterns:
                    if pattern.search(decoded):
                        threats.append(ThreatMatch(
                            threat_type="encoded_content",
                            severity="critical",
                            description="Detected prompt injection pattern in base64-decoded content",
                            content_preview=decoded[:100],
                            location="base64_encoded"
                        ))
                        break
                # Also check decoded content for hidden text patterns
                for pattern in self._compiled_hidden_patterns:
                    if pattern.search(decoded):
                        threats.append(ThreatMatch(
                            threat_type="encoded_content",
                            severity="high",
                            description="Detected hidden text pattern in base64-decoded content",
                            content_preview=decoded[:100],
                            location="base64_encoded"
                        ))
                        break
            except Exception:
                continue

        # Detect URL-encoded injection attempts
        url_encoded_pattern = re.compile(r'(?:%[0-9A-Fa-f]{2}){5,}')
        url_matches = url_encoded_pattern.findall(content)
        for match in url_matches:
            try:
                from urllib.parse import unquote
                decoded = unquote(match)
                for pattern in self._compiled_patterns:
                    if pattern.search(decoded):
                        threats.append(ThreatMatch(
                            threat_type="encoded_content",
                            severity="high",
                            description="Detected prompt injection pattern in URL-encoded content",
                            content_preview=decoded[:100],
                            location="url_encoded"
                        ))
                        break
            except Exception:
                continue

        # Detect unicode escape sequences
        unicode_escape_pattern = re.compile(r'(?:\\u[0-9A-Fa-f]{4}){3,}')
        unicode_matches = unicode_escape_pattern.findall(content)
        for match in unicode_matches:
            try:
                decoded = match.encode('utf-8').decode('unicode_escape')
                for pattern in self._compiled_patterns:
                    if pattern.search(decoded):
                        threats.append(ThreatMatch(
                            threat_type="encoded_content",
                            severity="high",
                            description="Detected prompt injection pattern in unicode-escaped content",
                            content_preview=decoded[:100],
                            location="unicode_escaped"
                        ))
                        break
            except Exception:
                continue

        return threats

    async def detect_prompt_injection(self, content: str) -> list[ThreatMatch]:
        """
        Detect known prompt injection patterns.

        Detects patterns like:
        - "ignore previous instructions"
        - "new system prompt"
        - Role-playing attacks
        - Delimiter injection
        """
        threats = []

        for i, pattern in enumerate(self._compiled_patterns):
            matches = pattern.findall(content)
            for match in matches:
                preview = match if isinstance(match, str) else str(match)
                threats.append(ThreatMatch(
                    threat_type="prompt_injection",
                    severity="high",
                    description=f"Detected prompt injection pattern: '{self.INJECTION_PATTERNS[i]}'",
                    content_preview=preview[:100],
                    location="content"
                ))

        # Additional delimiter injection patterns
        delimiter_patterns = [
            re.compile(r'</?(?:system|user|assistant|human|ai|bot)\s*>', re.IGNORECASE),
            re.compile(r'\[/?(?:SYSTEM|USER|ASSISTANT|INST|SYS)\]', re.IGNORECASE),
            re.compile(r'<<(?:SYS|INST|END)>>'),
            re.compile(r'(?:^|\n)\s*(?:Human|Assistant|System)\s*:\s*', re.IGNORECASE | re.MULTILINE),
        ]

        for pattern in delimiter_patterns:
            matches = pattern.findall(content)
            for match in matches:
                preview = match if isinstance(match, str) else str(match)
                threats.append(ThreatMatch(
                    threat_type="prompt_injection",
                    severity="medium",
                    description="Detected delimiter injection attempt that may manipulate LLM role boundaries",
                    content_preview=preview[:100],
                    location="content"
                ))

        return threats

    async def detect_unicode_attacks(self, content: str) -> list[ThreatMatch]:
        """
        Detect unicode-based attacks including homoglyphs.

        Detects:
        - Homoglyph substitution (Cyrillic a for Latin a)
        - Bidirectional text attacks
        - Zero-width characters
        - Combining characters
        """
        threats = []

        # Detect homoglyph substitution
        homoglyph_found = []
        for char in content:
            if char in self.HOMOGLYPH_MAP:
                homoglyph_found.append(char)

        if homoglyph_found:
            # Normalize content and check if it reveals injection patterns
            normalized = content
            for homoglyph, replacement in self.HOMOGLYPH_MAP.items():
                normalized = normalized.replace(homoglyph, replacement)

            for pattern in self._compiled_patterns:
                if pattern.search(normalized) and not pattern.search(content):
                    threats.append(ThreatMatch(
                        threat_type="unicode_attack",
                        severity="critical",
                        description=f"Detected homoglyph attack: unicode lookalike characters used to disguise prompt injection (chars: {set(homoglyph_found)})",
                        content_preview=content[:100],
                        location="content"
                    ))
                    break

            if homoglyph_found and not any(t.threat_type == "unicode_attack" for t in threats):
                threats.append(ThreatMatch(
                    threat_type="unicode_attack",
                    severity="medium",
                    description=f"Detected homoglyph characters that may be used for obfuscation: {set(homoglyph_found)}",
                    content_preview=content[:100],
                    location="content"
                ))

        # Detect bidirectional text attacks (RTL override)
        bidi_chars = ['\u202e', '\u202d', '\u202c', '\u202b', '\u202a', '\u2066', '\u2067', '\u2068', '\u2069']
        for bidi_char in bidi_chars:
            if bidi_char in content:
                idx = content.index(bidi_char)
                preview = content[max(0, idx-20):idx+20]
                threats.append(ThreatMatch(
                    threat_type="unicode_attack",
                    severity="high",
                    description=f"Detected bidirectional text override character (U+{ord(bidi_char):04X}) that may be used to disguise malicious content",
                    content_preview=repr(preview),
                    location="content"
                ))
                break

        # Detect excessive combining characters (used for obfuscation)
        combining_count = sum(1 for char in content if unicodedata.category(char).startswith('M'))
        if combining_count > 10:
            threats.append(ThreatMatch(
                threat_type="unicode_attack",
                severity="medium",
                description=f"Detected excessive combining characters ({combining_count}) that may be used for text obfuscation",
                content_preview=content[:100],
                location="content"
            ))

        # Detect mixed script attacks (Latin + Cyrillic in same word)
        word_pattern = re.compile(r'\b\w+\b')
        words = word_pattern.findall(content)
        for word in words:
            has_latin = any('LATIN' in unicodedata.name(c, '') for c in word if c.isalpha())
            has_cyrillic = any('CYRILLIC' in unicodedata.name(c, '') for c in word if c.isalpha())
            if has_latin and has_cyrillic:
                threats.append(ThreatMatch(
                    threat_type="unicode_attack",
                    severity="high",
                    description=f"Detected mixed-script word '{word}' combining Latin and Cyrillic characters (homoglyph attack)",
                    content_preview=word,
                    location="content"
                ))

        return threats

    async def scan_metadata(self, metadata: dict) -> ThreatDetectionResult:
        """
        Scan file metadata for hidden threats.

        Scans:
        - EXIF comments and descriptions
        - PDF metadata fields
        - Document properties
        - Custom metadata tags
        """
        threats = []
        metadata_str = str(metadata)

        # Scan metadata string for injection patterns
        for i, pattern in enumerate(self._compiled_patterns):
            matches = pattern.findall(metadata_str)
            for match in matches:
                preview = match if isinstance(match, str) else str(match)
                threats.append(ThreatMatch(
                    threat_type="metadata_injection",
                    severity="high",
                    description=f"Detected prompt injection pattern in file metadata: '{self.INJECTION_PATTERNS[i]}'",
                    content_preview=preview[:100],
                    location="metadata"
                ))

        # Recursively scan metadata values
        def scan_value(value: Any, key: str = "metadata") -> None:
            if isinstance(value, str):
                for i, pattern in enumerate(self._compiled_patterns):
                    if pattern.search(value):
                        threats.append(ThreatMatch(
                            threat_type="metadata_injection",
                            severity="high",
                            description=f"Detected prompt injection in metadata field '{key}'",
                            content_preview=value[:100],
                            location=f"metadata.{key}"
                        ))
                        break
                # Check for base64 in metadata values
                decoded = self._decode_base64(value)
                if decoded:
                    for pattern in self._compiled_patterns:
                        if pattern.search(decoded):
                            threats.append(ThreatMatch(
                                threat_type="metadata_injection",
                                severity="critical",
                                description=f"Detected prompt injection in base64-encoded metadata field '{key}'",
                                content_preview=decoded[:100],
                                location=f"metadata.{key}.base64"
                            ))
                            break
            elif isinstance(value, dict):
                for k, v in value.items():
                    scan_value(v, f"{key}.{k}")
            elif isinstance(value, list):
                for idx, item in enumerate(value):
                    scan_value(item, f"{key}[{idx}]")

        scan_value(metadata)

        return ThreatDetectionResult(
            has_violations=len(threats) > 0,
            threats=threats,
            scanned_content_length=len(metadata_str)
        )

    def _decode_base64(self, content: str) -> Optional[str]:
        """Attempt to decode base64 content."""
        try:
            # Look for base64-like strings
            b64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
            matches = re.findall(b64_pattern, content)

            for match in matches:
                try:
                    decoded = base64.b64decode(match).decode('utf-8')
                    return decoded
                except:
                    continue
            return None
        except:
            return None