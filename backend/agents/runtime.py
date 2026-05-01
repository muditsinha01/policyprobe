"""Thin runtime registry that ties the separated agent files together."""

import base64
import os
import re
from copy import deepcopy
from typing import Any

from .credit_eval_agent import credit_eval_agent
from .file_processor_agent import file_processor_agent
from .mcp_servers import MCP_SERVERS
from .orchestrator_agent import orchestrator_agent
from .rate_check_agent import rate_check_agent
from .loan_processing_agent import loan_processing_agent
from .scheduling_agent import scheduling_agent
from .support_agent import support_agent


AGENTS: dict[str, Any] = {
    loan_processing_agent.AGENT_NAME: loan_processing_agent,
    file_processor_agent.AGENT_NAME: file_processor_agent,
    support_agent.AGENT_NAME: support_agent,
    credit_eval_agent.AGENT_NAME: credit_eval_agent,
    rate_check_agent.AGENT_NAME: rate_check_agent,
    orchestrator_agent.AGENT_NAME: orchestrator_agent,
    scheduling_agent.AGENT_NAME: scheduling_agent,
}

# Maximum allowed lengths
_MAX_MESSAGE_LENGTH = 32_000
_MAX_FILENAME_LENGTH = 255
_MAX_FILE_CONTENT_LENGTH = 10_000_000  # 10 MB

# Dangerous patterns for input sanitization
_DANGEROUS_PATTERNS = [
    re.compile(r"<script[\s\S]*?>[\s\S]*?</script>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),
]

# Prompt injection / malicious content patterns for file content
_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+", re.IGNORECASE),
    re.compile(r"act\s+as\s+(a\s+)?", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above)", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(previous|prior|above|your)", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
    re.compile(r"<\|.*?\|>"),
    re.compile(r"\[INST\]|\[/INST\]|\[SYS\]|\[/SYS\]"),
    re.compile(r"###\s*(instruction|system|prompt)", re.IGNORECASE),
]

# Leetspeak substitution map for normalization
_LEET_MAP = str.maketrans("013456789@$!", "oieashgtbgas!")

# Binary/shell command patterns
_SHELL_PATTERNS = [
    re.compile(r"(^|\s)(bash|sh|zsh|cmd|powershell|exec|eval|system|popen)\s*[\(\-]", re.IGNORECASE | re.MULTILINE),
    re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"),  # non-printable control chars
    re.compile(r"\\x[0-9a-fA-F]{2}"),  # hex escape sequences
]

# Invisible/hidden text patterns
_INVISIBLE_PATTERNS = [
    re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]"),  # zero-width and directional chars
    re.compile(r"color\s*:\s*(?:white|#fff|#ffffff|rgba?\([^)]*,\s*0\))", re.IGNORECASE),
    re.compile(r"font-size\s*:\s*0", re.IGNORECASE),
    re.compile(r"opacity\s*:\s*0", re.IGNORECASE),
    re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE),
    re.compile(r"display\s*:\s*none", re.IGNORECASE),
]


def _get_auth_token() -> str:
    token = os.environ.get("AGENT_AUTH_TOKEN", "")
    if not token:
        raise RuntimeError("AGENT_AUTH_TOKEN environment variable is not set")
    return token


def _verify_auth_token(token: str | None) -> None:
    if not token:
        raise PermissionError("Authentication token is required")
    expected = _get_auth_token()
    if token != expected:
        raise PermissionError("Invalid authentication token")


def _strip_dangerous_chars(value: str) -> str:
    """Strip dangerous characters and patterns from a string."""
    for pattern in _DANGEROUS_PATTERNS:
        value = pattern.sub("", value)
    # Remove null bytes
    value = value.replace("\x00", "")
    return value.strip()


def _validate_chat_context(context: dict[str, Any]) -> dict[str, Any]:
    """Validate and sanitize the chat request context."""
    if not isinstance(context, dict):
        raise ValueError("Context must be a dictionary")

    sanitized = deepcopy(context)

    # Validate and sanitize 'message' field if present
    if "message" in sanitized:
        message = sanitized["message"]
        if not isinstance(message, str):
            raise ValueError("Field 'message' must be a string")
        if len(message) > _MAX_MESSAGE_LENGTH:
            raise ValueError(f"Field 'message' exceeds maximum length of {_MAX_MESSAGE_LENGTH} characters")
        sanitized["message"] = _strip_dangerous_chars(message)

    # Validate 'messages' list if present
    if "messages" in sanitized:
        messages = sanitized["messages"]
        if not isinstance(messages, list):
            raise ValueError("Field 'messages' must be a list")
        cleaned_messages = []
        for i, msg in enumerate(messages):
            if not isinstance(msg, dict):
                raise ValueError(f"Message at index {i} must be a dictionary")
            cleaned_msg = deepcopy(msg)
            if "content" in cleaned_msg:
                content = cleaned_msg["content"]
                if not isinstance(content, str):
                    raise ValueError(f"Message content at index {i} must be a string")
                if len(content) > _MAX_MESSAGE_LENGTH:
                    raise ValueError(f"Message content at index {i} exceeds maximum length")
                cleaned_msg["content"] = _strip_dangerous_chars(content)
            cleaned_messages.append(cleaned_msg)
        sanitized["messages"] = cleaned_messages

    return sanitized


def _check_file_content_for_malicious_patterns(content: str, filename: str) -> None:
    """Check file content for hidden prompts, injection attacks, and malicious payloads."""

    # Check for invisible/hidden text patterns
    for pattern in _INVISIBLE_PATTERNS:
        if pattern.search(content):
            raise ValueError(f"File '{filename}' contains hidden or invisible text that may conceal malicious content")

    # Check for prompt injection patterns
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(content):
            raise ValueError(f"File '{filename}' contains suspicious instruction patterns indicative of prompt injection")

    # Check for shell/binary command patterns
    for pattern in _SHELL_PATTERNS:
        if pattern.search(content):
            raise ValueError(f"File '{filename}' contains binary data or shell command patterns")

    # Check for base64-encoded prompts
    # Extract potential base64 strings and decode them to check for injection
    b64_candidates = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", content)
    for candidate in b64_candidates:
        try:
            decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="ignore")
            for pattern in _INJECTION_PATTERNS:
                if pattern.search(decoded):
                    raise ValueError(f"File '{filename}' contains base64-encoded prompt injection content")
        except Exception as exc:
            if isinstance(exc, ValueError):
                raise
            # Ignore decode errors for non-base64 strings
            pass

    # Check for leetspeak prompts by normalizing and re-checking
    normalized = content.translate(_LEET_MAP)
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(normalized):
            raise ValueError(f"File '{filename}' contains leetspeak-obfuscated prompt injection content")


def _validate_file_attachment(
    content: str | None,
    filename: str,
    content_type: str,
) -> tuple[str | None, str, str]:
    """Validate and sanitize file attachment inputs."""
    # Validate filename
    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("Filename must be a non-empty string")
    if len(filename) > _MAX_FILENAME_LENGTH:
        raise ValueError(f"Filename exceeds maximum length of {_MAX_FILENAME_LENGTH} characters")
    # Strip path traversal attempts
    safe_filename = os.path.basename(filename.replace("\\", "/"))
    if not safe_filename:
        raise ValueError("Filename is invalid after sanitization")

    # Validate content_type
    if not isinstance(content_type, str) or not content_type.strip():
        raise ValueError("Content type must be a non-empty string")
    safe_content_type = content_type.strip()

    # Validate and check content
    safe_content = content
    if content is not None:
        if not isinstance(content, str):
            raise ValueError("File content must be a string or None")
        if len(content) > _MAX_FILE_CONTENT_LENGTH:
            raise ValueError(f"File content exceeds maximum allowed size of {_MAX_FILE_CONTENT_LENGTH} bytes")
        # Check for malicious content in the file
        _check_file_content_for_malicious_patterns(content, safe_filename)

    return safe_content, safe_filename, safe_content_type


def build_catalog() -> dict[str, Any]:
    return {
        "agents": deepcopy([agent.to_dict() for agent in AGENTS.values()]),
        "mcp_servers": deepcopy(list(MCP_SERVERS.values())),
    }


async def handle_chat_request(context: dict[str, Any], token: str | None = None) -> dict[str, Any]:
    _verify_auth_token(token)
    sanitized_context = _validate_chat_context(context)
    return await orchestrator_agent.handle(sanitized_context)


async def process_file_attachment(
    content: str | None,
    filename: str,
    content_type: str,
    token: str | None = None,
) -> dict[str, Any]:
    _verify_auth_token(token)
    safe_content, safe_filename, safe_content_type = _validate_file_attachment(content, filename, content_type)
    return await file_processor_agent.process_attachment(safe_content, safe_filename, safe_content_type)