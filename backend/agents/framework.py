"""Small agent framework base class used by the PolicyProbe agents."""

import logging
import os
import re
from abc import ABC, abstractmethod
from copy import deepcopy
from typing import Any

from llm.bedrock import BedrockClient

logger = logging.getLogger(__name__)

DYNAMIC_CODE_PATTERNS = [
    re.compile(r'\beval\s*\('),
    re.compile(r'\bexec\s*\('),
    re.compile(r'\bos\.system\s*\('),
    re.compile(r'\bsubprocess\b.*shell\s*=\s*True'),
    re.compile(r'\b__import__\s*\('),
    re.compile(r'\bcompile\s*\('),
    re.compile(r'\bexecfile\s*\('),
]

PROMPT_INJECTION_PATTERNS = [
    re.compile(r'ignore\s+(all\s+)?(previous|prior|above)\s+instructions', re.IGNORECASE),
    re.compile(r'disregard\s+(all\s+)?(previous|prior|above)\s+instructions', re.IGNORECASE),
    re.compile(r'you\s+are\s+now\s+', re.IGNORECASE),
    re.compile(r'forget\s+(all\s+)?(previous|prior|above)\s+instructions', re.IGNORECASE),
    re.compile(r'system\s*prompt', re.IGNORECASE),
    re.compile(r'<\s*/?system\s*>', re.IGNORECASE),
    re.compile(r'\[\s*INST\s*\]', re.IGNORECASE),
]


class PolicyProbeAgentFramework(ABC):
    """Base class that makes agent metadata and model usage obvious."""

    FRAMEWORK_NAME = "PolicyProbeAgentFramework"
    AGENT_ID = ""
    AGENT_NAME = ""
    VERSION = "1.0.0"
    MODEL_NAME = ""
    BEDROCK_MODEL_ID = ""
    BEDROCK_FALLBACK_MODEL_ID = ""
    DESCRIPTION = ""
    MCP_SERVERS: list[str] = []
    GUARDRAILS: dict[str, Any] = {}
    SYSTEM_PROMPT = ""
    IS_ROUTABLE = True
    IS_SCAN_ONLY = False
    TASK_COMPLETE_KEY = "task_complete"

    def __init__(self):
        self.bedrock_client = BedrockClient()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.AGENT_ID,
            "name": self.AGENT_NAME,
            "version": self.VERSION,
            "framework": self.FRAMEWORK_NAME,
            "model": self.MODEL_NAME,
            "bedrock_model_id": self.BEDROCK_MODEL_ID,
            "bedrock_fallback_model_id": self.BEDROCK_FALLBACK_MODEL_ID,
            "description": self.DESCRIPTION,
            "mcp_servers": list(self.MCP_SERVERS),
            "guardrails": deepcopy(self.GUARDRAILS),
            "system_prompt": self.SYSTEM_PROMPT,
            "is_routable": self.IS_ROUTABLE,
            "is_scan_only": self.IS_SCAN_ONLY,
        }

    def _sanitize_llm_output(self, response: str) -> str:
        """Check LLM output for dynamic code execution primitives and raise ValueError if found."""
        for pattern in DYNAMIC_CODE_PATTERNS:
            if pattern.search(response):
                raise ValueError(
                    f"LLM output contains a disallowed dynamic code execution primitive "
                    f"matching pattern: {pattern.pattern}"
                )
        return response

    def _sanitize_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Validate and sanitize input messages before sending to the LLM."""
        if not isinstance(messages, list):
            raise ValueError("messages must be a list")
        sanitized = []
        for msg in messages:
            if not isinstance(msg, dict):
                raise ValueError("Each message must be a dict")
            if "role" not in msg or "content" not in msg:
                raise ValueError("Each message must have 'role' and 'content' keys")
            role = msg["role"]
            if role not in ("system", "user", "assistant"):
                raise ValueError(f"Invalid message role: {role!r}")
            content = msg["content"]
            if not isinstance(content, str):
                raise ValueError("Message content must be a string")
            for pattern in PROMPT_INJECTION_PATTERNS:
                if pattern.search(content):
                    raise ValueError(
                        f"Message content contains a potential prompt injection pattern: "
                        f"{pattern.pattern}"
                    )
            sanitized.append({"role": role, "content": content})
        return sanitized

    def is_task_complete(self, result: dict[str, Any]) -> bool:
        """Check whether the result dict contains the required completion signal."""
        return bool(result.get(self.TASK_COMPLETE_KEY, False))

    async def call_bedrock_model(
        self,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 350,
    ) -> str:
        sanitized_messages = self._sanitize_messages(messages)

        deployment_override_model = os.getenv("BEDROCK_MODEL_ID")
        active_model = self.BEDROCK_MODEL_ID

        # Deployment override: force all routable runtime agents onto the same
        # Bedrock model while leaving scan-only agents unchanged for scanners.
        if deployment_override_model and self.IS_ROUTABLE and not self.IS_SCAN_ONLY:
            active_model = deployment_override_model

        logger.info(
            "LLM request: agent=%s model=%s temperature=%s max_tokens=%s messages=%r",
            self.AGENT_ID,
            active_model,
            temperature,
            max_tokens,
            sanitized_messages,
        )
        primary_response = await self.bedrock_client.chat(
            messages=sanitized_messages,
            model=active_model,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        logger.info(
            "LLM response: agent=%s model=%s response=%r",
            self.AGENT_ID,
            active_model,
            primary_response,
        )
        if (
            (
                "Error communicating with LLM:" in primary_response
                or primary_response.startswith("LLM service not configured")
                or primary_response.startswith("Error:")
            )
            and self.BEDROCK_FALLBACK_MODEL_ID
        ):
            logger.info(
                "LLM fallback request: agent=%s model=%s temperature=%s max_tokens=%s messages=%r",
                self.AGENT_ID,
                self.BEDROCK_FALLBACK_MODEL_ID,
                temperature,
                max_tokens,
                sanitized_messages,
            )
            fallback_response = await self.bedrock_client.chat(
                messages=sanitized_messages,
                model=self.BEDROCK_FALLBACK_MODEL_ID,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            logger.info(
                "LLM fallback response: agent=%s model=%s response=%r",
                self.AGENT_ID,
                self.BEDROCK_FALLBACK_MODEL_ID,
                fallback_response,
            )
            return self._sanitize_llm_output(fallback_response)
        return self._sanitize_llm_output(primary_response)

    @abstractmethod
    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        """Handle a request for this agent.

        Termination contract: subclasses MUST include the key defined by
        TASK_COMPLETE_KEY in the returned dict and set it to True when the
        agent has finished processing and considers its task complete.  The
        `run` method enforces this contract and will raise a RuntimeError if
        the completion signal is absent or falsy.
        """

    async def run(self, context: dict[str, Any]) -> dict[str, Any]:
        """Invoke `handle` and enforce the termination criteria before returning."""
        result = await self.handle(context)
        if not self.is_task_complete(result):
            raise RuntimeError(
                f"Agent {self.AGENT_ID!r} returned a result without the required "
                f"completion signal (key={self.TASK_COMPLETE_KEY!r}). "
                "Subclasses must set this key to True when the task is complete."
            )
        return result