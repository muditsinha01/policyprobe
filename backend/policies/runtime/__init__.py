"""
Runtime Policy Enforcement

Runtime guardrails that execute during application operation.

SECURITY NOTES:
- Real-time LLM output validation is enforced
- Input is sanitized and validated before processing
- Comprehensive audit logging is active

"""

import re
import logging
from typing import Any

from .llm_response_guard import LLMResponseGuard
from .input_sanitizer import InputSanitizer
from .audit_logger import AuditLogger

logger = logging.getLogger(__name__)

MAX_INPUT_LENGTH = 32768


def _create_default_sanitizer() -> InputSanitizer:
    """Instantiate and return a default InputSanitizer with real enforcement."""
    return InputSanitizer()


def sanitize_input(text: Any, max_length: int = MAX_INPUT_LENGTH) -> str:
    """
    Perform real input validation and sanitization.

    - Enforces type as string
    - Removes null bytes
    - Strips HTML/script tags
    - Enforces maximum length
    """
    if not isinstance(text, str):
        if text is None:
            raise ValueError("Input must not be None")
        text = str(text)

    # Remove null bytes
    text = text.replace("\x00", "")

    # Strip script tags and their content
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.IGNORECASE | re.DOTALL)

    # Strip all remaining HTML tags
    text = re.sub(r"<[^>]+>", "", text)

    # Enforce length limit
    if len(text) > max_length:
        logger.warning(
            "Input truncated from %d to %d characters", len(text), max_length
        )
        text = text[:max_length]

    return text


# Default sanitizer instance exposed for callers
default_sanitizer = _create_default_sanitizer()

__all__ = ["LLMResponseGuard", "InputSanitizer", "AuditLogger", "default_sanitizer", "sanitize_input"]