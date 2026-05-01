"""
OpenAI-compatible model gateway client.

This keeps the request shape real and makes the selected model visible in each
agent file via the `model=` argument on every call.
"""

import asyncio
import logging
import os
import re
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

APPROVED_MODELS = [
    "gpt-4",
    "gpt-4-turbo",
    "gpt-4o",
    "gpt-3.5-turbo",
    "claude-3-opus",
    "claude-3-sonnet",
    "claude-3-haiku",
    "claude-3-5-sonnet",
    "gemini-pro",
    "gemini-1.5-pro",
]

ALLOWED_ROLES = {"system", "user", "assistant"}
MAX_CONTENT_LENGTH = 100000
SAFE_MODEL_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]+$')

DYNAMIC_CODE_PRIMITIVES = [
    "eval",
    "exec",
    "subprocess",
    "os.system",
    "compile",
    "__import__",
    "execfile",
    "globals",
    "locals",
    "vars",
]


def _sanitize_llm_output(content: str) -> str:
    """Check LLM output for dynamic code execution primitives and raise if found."""
    for primitive in DYNAMIC_CODE_PRIMITIVES:
        if primitive in content:
            raise ValueError(
                f"LLM output contains forbidden dynamic code execution primitive: '{primitive}'"
            )
    return content


class OpenAICompatibleClient:
    """Minimal async wrapper around a chat-completions style API."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.base_url = (
            base_url
            or os.getenv("MODEL_GATEWAY_BASE_URL")
            or "http://127.0.0.1:4000/v1"
        ).rstrip("/")
        self.api_key = api_key or os.getenv("MODEL_GATEWAY_API_KEY")

    def _validate_and_sanitize(
        self,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float,
        max_tokens: int,
    ) -> tuple[str, list[dict[str, Any]]]:
        """Validate and sanitize model and messages parameters."""
        if not isinstance(model, str) or not model.strip():
            raise ValueError("model must be a non-empty string.")
        model = model.strip()

        if not isinstance(messages, list) or len(messages) == 0:
            raise ValueError("messages must be a non-empty list.")

        sanitized_messages = []
        for i, msg in enumerate(messages):
            if not isinstance(msg, dict):
                raise ValueError(f"Message at index {i} must be a dict.")
            role = msg.get("role")
            content = msg.get("content")
            if role is None or content is None:
                raise ValueError(
                    f"Message at index {i} must contain 'role' and 'content' keys."
                )
            if not isinstance(role, str) or role.strip() not in ALLOWED_ROLES:
                raise ValueError(
                    f"Message at index {i} has invalid role '{role}'. "
                    f"Allowed roles: {ALLOWED_ROLES}."
                )
            if not isinstance(content, str):
                raise ValueError(
                    f"Message at index {i} 'content' must be a string."
                )
            if len(content) > MAX_CONTENT_LENGTH:
                raise ValueError(
                    f"Message at index {i} 'content' exceeds maximum length of {MAX_CONTENT_LENGTH}."
                )
            sanitized_messages.append({
                "role": role.strip(),
                "content": content.strip(),
            })

        if not isinstance(temperature, (int, float)) or not (0.0 <= temperature <= 2.0):
            raise ValueError("temperature must be a float between 0.0 and 2.0.")

        if not isinstance(max_tokens, int) or not (1 <= max_tokens <= 32768):
            raise ValueError("max_tokens must be an integer between 1 and 32768.")

        return model, sanitized_messages

    def _validate_and_sanitize_inputs(
        self,
        model: str,
        messages: list[dict[str, Any]],
    ) -> tuple[str, list[dict[str, Any]]]:
        """Validate and sanitize model string and messages list for safe API forwarding."""
        if not isinstance(model, str) or not model.strip():
            raise ValueError("model must be a non-empty string.")
        model = model.strip()
        if not SAFE_MODEL_PATTERN.match(model):
            raise ValueError(
                f"model '{model}' contains unsafe characters. Only alphanumeric, "
                "hyphens, underscores, and dots are allowed."
            )

        if not isinstance(messages, list) or len(messages) == 0:
            raise ValueError("messages must be a non-empty list.")

        sanitized_messages = []
        for i, msg in enumerate(messages):
            if not isinstance(msg, dict):
                raise ValueError(f"Message at index {i} must be a dict.")
            allowed_keys = {"role", "content"}
            extra_keys = set(msg.keys()) - allowed_keys
            if extra_keys:
                raise ValueError(
                    f"Message at index {i} contains disallowed keys: {extra_keys}. "
                    f"Only 'role' and 'content' are permitted."
                )
            role = msg.get("role")
            content = msg.get("content")
            if role is None or content is None:
                raise ValueError(
                    f"Message at index {i} must contain both 'role' and 'content'."
                )
            if not isinstance(role, str) or role.strip() not in ALLOWED_ROLES:
                raise ValueError(
                    f"Message at index {i} has invalid role '{role}'. "
                    f"Allowed roles: {ALLOWED_ROLES}."
                )
            if not isinstance(content, str):
                raise ValueError(
                    f"Message at index {i} 'content' must be a string."
                )
            if len(content) > MAX_CONTENT_LENGTH:
                raise ValueError(
                    f"Message at index {i} 'content' exceeds maximum allowed length of {MAX_CONTENT_LENGTH}."
                )
            sanitized_messages.append({
                "role": role.strip(),
                "content": content.strip(),
            })

        return model, sanitized_messages

    async def chat(
        self,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 400,
    ) -> str:
        if model not in APPROVED_MODELS:
            raise ValueError(
                f"Model '{model}' is not in the approved model list. "
                f"Approved models: {APPROVED_MODELS}"
            )

        model, messages = self._validate_and_sanitize(model, messages, temperature, max_tokens)
        model, messages = self._validate_and_sanitize_inputs(model, messages)

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        def _post() -> str:
            logger.info(
                "Sending LLM request",
                extra={
                    "model": model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                },
            )
            try:
                response = requests.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=20,
                )
                response.raise_for_status()
                data = response.json()
                choices = data.get("choices", [])
                if choices:
                    message = choices[0].get("message", {})
                    content = message.get("content", "")
                    if isinstance(content, str):
                        stripped_content = content.strip()
                        _sanitize_llm_output(stripped_content)
                        logger.info(
                            "Received LLM response",
                            extra={"model": model, "response_content": stripped_content},
                        )
                        return stripped_content
                return f"Model API returned no content for model {model}."
            except requests.RequestException as exc:
                logger.warning(
                    "Model gateway request failed",
                    extra={"model": model, "error": str(exc)},
                )
                return f"Model gateway unavailable for {model}: {exc}"

        return await asyncio.to_thread(_post)