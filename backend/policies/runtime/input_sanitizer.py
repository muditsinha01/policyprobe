"""
Input Sanitizer

Sanitizes user input before processing.
"""

import re
import logging
import unicodedata
import os
from typing import Any

logger = logging.getLogger(__name__)

MAX_INPUT_LENGTH = 32768

HTML_SCRIPT_PATTERN = re.compile(
    r'<\s*(script|iframe|object|embed|form|input|button|link|meta|style|base|applet|xml)'
    r'[^>]*>.*?<\s*/\s*\1\s*>|<\s*(script|iframe|object|embed|form|input|button|link|meta|style|base|applet|xml)[^>]*/?>',
    re.IGNORECASE | re.DOTALL
)
HTML_TAG_PATTERN = re.compile(r'<[^>]+>', re.IGNORECASE)
JAVASCRIPT_PATTERN = re.compile(r'javascript\s*:', re.IGNORECASE)
EVENT_HANDLER_PATTERN = re.compile(r'\bon\w+\s*=', re.IGNORECASE)

SQL_INJECTION_PATTERNS = re.compile(
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|TRUNCATE|REPLACE|MERGE)\b"
    r"|--|;|\bOR\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+[\'\"]?"
    r"|\bAND\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+[\'\"]?"
    r"|'\s*OR\s*'1'\s*=\s*'1"
    r"|\bxp_\w+|\bsp_\w+)",
    re.IGNORECASE
)

COMMAND_INJECTION_PATTERN = re.compile(
    r'[;&|`$]|\$\(|\$\{|>\s*/|<\s*/|\|\||\&\&'
)

PATH_TRAVERSAL_PATTERN = re.compile(
    r'\.\.[/\\]|[/\\]\.\.|%2e%2e[/\\%]|[/\\]%2e%2e',
    re.IGNORECASE
)

NULL_BYTE_PATTERN = re.compile(r'\x00')


class InputSanitizer:
    """
    Sanitizes user input before processing.

    Sanitizes:
    - HTML/script injection
    - SQL injection patterns
    - Command injection
    - Path traversal
    - Encoding attacks
    """

    def __init__(self):
        pass

    async def sanitize(self, input_data: Any) -> Any:
        """
        Sanitize input data.
        """
        logger.debug(
            "Sanitization requested",
            extra={
                "input_type": type(input_data).__name__,
                "input_preview": str(input_data)[:100]
            }
        )

        if isinstance(input_data, str):
            return await self._sanitize_string(input_data)
        elif isinstance(input_data, dict):
            return {k: await self.sanitize(v) for k, v in input_data.items()}
        elif isinstance(input_data, list):
            return [await self.sanitize(item) for item in input_data]
        else:
            return input_data

    async def _sanitize_string(self, text: str) -> str:
        """
        Sanitize a string value by removing dangerous patterns.
        """
        # Enforce maximum length
        if len(text) > MAX_INPUT_LENGTH:
            text = text[:MAX_INPUT_LENGTH]

        # Normalize encoding first
        text = await self.normalize_encoding(text)

        # Remove null bytes
        text = NULL_BYTE_PATTERN.sub('', text)

        # Remove dangerous HTML/script tags
        text = HTML_SCRIPT_PATTERN.sub('', text)
        text = HTML_TAG_PATTERN.sub('', text)
        text = JAVASCRIPT_PATTERN.sub('', text)
        text = EVENT_HANDLER_PATTERN.sub('', text)

        # Remove SQL injection patterns
        text = SQL_INJECTION_PATTERNS.sub('', text)

        # Remove command injection characters
        text = COMMAND_INJECTION_PATTERN.sub('', text)

        # Remove path traversal sequences
        text = PATH_TRAVERSAL_PATTERN.sub('', text)

        return text.strip()

    async def sanitize_for_llm(self, content: str) -> str:
        """
        Sanitize content before sending to LLM.
        """
        if not isinstance(content, str):
            content = str(content)

        # Enforce maximum length before sending to LLM
        if len(content) > MAX_INPUT_LENGTH:
            content = content[:MAX_INPUT_LENGTH]

        # Normalize encoding
        content = await self.normalize_encoding(content)

        # Remove null bytes
        content = NULL_BYTE_PATTERN.sub('', content)

        # Remove dangerous HTML/script tags
        content = HTML_SCRIPT_PATTERN.sub('', content)
        content = HTML_TAG_PATTERN.sub('', content)
        content = JAVASCRIPT_PATTERN.sub('', content)
        content = EVENT_HANDLER_PATTERN.sub('', content)

        # Remove SQL injection patterns
        content = SQL_INJECTION_PATTERNS.sub('', content)

        # Remove command injection characters
        content = COMMAND_INJECTION_PATTERN.sub('', content)

        # Remove path traversal sequences
        content = PATH_TRAVERSAL_PATTERN.sub('', content)

        return content.strip()

    async def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename to prevent path traversal.
        """
        if not isinstance(filename, str):
            filename = str(filename)

        # Remove null bytes
        filename = NULL_BYTE_PATTERN.sub('', filename)

        # Remove path traversal sequences
        filename = PATH_TRAVERSAL_PATTERN.sub('', filename)

        # Strip directory components
        filename = os.path.basename(filename)

        # Remove any remaining path separators
        filename = filename.replace('/', '').replace('\\', '')

        # Remove dangerous characters from filenames
        filename = re.sub(r'[;&|`$<>"\']', '', filename)

        # Normalize encoding
        filename = await self.normalize_encoding(filename)

        return filename.strip()

    async def normalize_encoding(self, content: str) -> str:
        """
        Normalize text encoding to prevent attacks.
        """
        if not isinstance(content, str):
            content = str(content)

        # Normalize Unicode to NFC form to prevent homograph attacks
        content = unicodedata.normalize('NFC', content)

        # Decode common URL encoding patterns that may hide attacks
        content = re.sub(r'%([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), content)

        # Remove non-printable characters except common whitespace
        content = ''.join(
            ch for ch in content
            if unicodedata.category(ch) not in ('Cc', 'Cf', 'Cs', 'Co', 'Cn')
            or ch in ('\n', '\r', '\t', ' ')
        )

        return content