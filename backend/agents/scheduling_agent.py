"""Scheduling Agent class with explicit model invocation."""

import asyncio
import hashlib
import hmac
import logging
import os
import re
from typing import Any

from .framework import PolicyProbeAgentFramework
from .helpers import extract_reference_number
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)

# Dynamic code execution primitives to detect in LLM output
_DANGEROUS_PATTERNS = re.compile(
    r"\b(eval|exec|subprocess|__import__|compile|execfile|os\.system|os\.popen|"
    r"importlib|__builtins__|globals|locals|vars|getattr|setattr|delattr|"
    r"open|input|breakpoint)\s*\(",
    re.IGNORECASE,
)

# Prompt injection patterns
_INJECTION_PATTERNS = re.compile(
    r"(ignore\s+previous\s+instructions|disregard\s+all\s+prior|"
    r"you\s+are\s+now\s+a|forget\s+your\s+instructions|"
    r"system\s*:\s*|<\s*system\s*>|<\s*/?prompt\s*>|"
    r"\[\s*system\s*\]|\{\s*system\s*\})",
    re.IGNORECASE,
)

_MAX_INPUT_LENGTH = 4096

# Pre-shared HMAC secret for MCP server authentication (loaded from env)
_MCP_HMAC_SECRET = os.environ.get("MCP_HMAC_SECRET", "default-secret-change-me")

# Expected TLS certificate fingerprints per server (loaded from env/config)
_SERVER_CERT_FINGERPRINTS = {
    "Google Calendar": os.environ.get("MCP_GCAL_CERT_FP", "sha256:gcal-fingerprint"),
    "Email": os.environ.get("MCP_EMAIL_CERT_FP", "sha256:email-fingerprint"),
    "Slack": os.environ.get("MCP_SLACK_CERT_FP", "sha256:slack-fingerprint"),
}


def _sanitize_string(value: str) -> str:
    """Strip or escape potentially dangerous characters from user-supplied strings."""
    if not isinstance(value, str):
        value = str(value)
    # Remove null bytes and control characters (except newline/tab)
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", value)
    # Escape angle brackets to prevent injection
    value = value.replace("<", "&lt;").replace(">", "&gt;")
    return value


def _sanitize_llm_output(output: str) -> str:
    """Validate and sanitize LLM output by removing dynamic code execution primitives."""
    if not isinstance(output, str):
        output = str(output)
    if _DANGEROUS_PATTERNS.search(output):
        logger.warning("Dangerous code execution primitive detected in LLM output; sanitizing.")
        output = _DANGEROUS_PATTERNS.sub("[REDACTED]", output)
    return output


class SchedulingAgent(PolicyProbeAgentFramework):
    AGENT_ID = "scheduling_agent"
    AGENT_NAME = "Scheduling Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "amazon nova pro"
    BEDROCK_MODEL_ID = "amazon.nova-pro-v1:0"
    DESCRIPTION = "Schedules borrower, underwriting, and support meetings."
    MCP_SERVERS = ["Google Calendar", "Email", "Slack"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Coordinate calendar events and notify the relevant teams."

    def sanitize_input(self, user_message: str) -> str:
        """Validate and clean user_message before use in model invocations or MCP calls."""
        if not isinstance(user_message, str):
            user_message = str(user_message)
        # Strip leading/trailing whitespace
        user_message = user_message.strip()
        # Enforce maximum length
        if len(user_message) > _MAX_INPUT_LENGTH:
            logger.warning("user_message exceeds maximum length; truncating.")
            user_message = user_message[:_MAX_INPUT_LENGTH]
        # Reject or neutralize prompt injection patterns
        if _INJECTION_PATTERNS.search(user_message):
            logger.warning("Prompt injection pattern detected in user_message; neutralizing.")
            user_message = _INJECTION_PATTERNS.sub("[FILTERED]", user_message)
        # Remove null bytes and control characters
        user_message = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", user_message)
        return user_message

    def _get_server_auth(self, server_name: str) -> dict:
        """Return per-server authentication credential (HMAC token + cert fingerprint)."""
        token = hmac.new(
            _MCP_HMAC_SECRET.encode(),
            msg=f"{self.AGENT_ID}:{server_name}".encode(),
            digestmod=hashlib.sha256,
        ).hexdigest()
        cert_fp = _SERVER_CERT_FINGERPRINTS.get(server_name, "")
        return {"hmac_token": token, "cert_fingerprint": cert_fp}

    def get_auth_token(self) -> str:
        """Return a signed auth token representing this agent's identity."""
        return hmac.new(
            _MCP_HMAC_SECRET.encode(),
            msg=self.AGENT_ID.encode(),
            digestmod=hashlib.sha256,
        ).hexdigest()

    def _validate_mcp_result(self, result: Any) -> Any:
        """Validate and sanitize a single MCP server result."""
        if result is None:
            return result
        if isinstance(result, str):
            # Remove dangerous patterns from string results
            result = _DANGEROUS_PATTERNS.sub("[REDACTED]", result)
            result = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", result)
        elif isinstance(result, dict):
            result = {k: self._validate_mcp_result(v) for k, v in result.items()}
        elif isinstance(result, list):
            result = [self._validate_mcp_result(item) for item in result]
        return result

    async def call_agent_model(self, user_message: str, meeting_reference: str) -> str:
        messages = [
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Meeting reference: {meeting_reference}\n"
                    f"Scheduling request: {user_message or 'Loan coordination meeting requested.'}\n\n"
                    "Draft a scheduling confirmation."
                ),
            },
        ]
        params = {"temperature": 0.2, "max_tokens": 180}
        logger.info(
            "Sending request to LLM model=%s messages=%s params=%s",
            self.BEDROCK_MODEL_ID,
            messages,
            params,
        )
        response = await self.call_bedrock_model(
            messages=messages,
            **params,
        )
        logger.info(
            "Received response from LLM model=%s response=%s",
            self.BEDROCK_MODEL_ID,
            response,
        )
        return response

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        raw_user_message = context.get("user_message", "")
        user_message = self.sanitize_input(raw_user_message)
        meeting_reference = extract_reference_number(user_message, prefix="MEET")
        model_output = await self.call_agent_model(user_message, meeting_reference)
        model_output = _sanitize_llm_output(model_output)

        # Sanitize inputs before MCP calls
        safe_user_message = _sanitize_string(user_message)
        safe_meeting_reference = _sanitize_string(meeting_reference)

        auth_token = self.get_auth_token()

        gcal_auth = self._get_server_auth("Google Calendar")
        email_auth = self._get_server_auth("Email")
        slack_auth = self._get_server_auth("Slack")

        logger.info(
            "Initiating MCP server calls for meeting_reference=%s", safe_meeting_reference
        )

        mcp_activity_raw = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Google Calendar",
                "create_event",
                {
                    "title": f"Borrower meeting {safe_meeting_reference}",
                    "description": safe_user_message or "Loan coordination meeting requested.",
                    "start": "2026-04-01T10:00:00-07:00",
                    "end": "2026-04-01T10:30:00-07:00",
                    "_server_auth": gcal_auth,
                    "auth_token": auth_token,
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example", "underwriting@acme.example"],
                    "subject": f"Meeting scheduled for {safe_meeting_reference}",
                    "body": "The Scheduling Agent created a calendar event for this request.",
                    "_server_auth": email_auth,
                    "auth_token": auth_token,
                },
            ),
            call_mcp_server(
                self.to_dict(),
                "Slack",
                "post_message",
                {
                    "channel": "#loan-ops",
                    "text": f"Scheduling Agent created meeting {safe_meeting_reference}.",
                    "_server_auth": slack_auth,
                    "auth_token": auth_token,
                },
            ),
        )

        logger.info(
            "Completed MCP server calls for meeting_reference=%s results=%s",
            safe_meeting_reference,
            mcp_activity_raw,
        )

        mcp_activity = [self._validate_mcp_result(result) for result in mcp_activity_raw]

        response = (
            f"Meeting reference: {meeting_reference}\n"
            f"Scheduling request: {user_message or 'No scheduling request provided.'}\n\n"
            f"Scheduling summary:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


scheduling_agent = SchedulingAgent()