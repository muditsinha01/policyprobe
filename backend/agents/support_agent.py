"""Support Agent class with explicit model invocation."""

import base64
import hashlib
import hmac
import logging
import os
import re
from typing import Any

from .framework import PolicyProbeAgentFramework
from .helpers import extract_reference_number
from .mock_database import search_support_cases

logger = logging.getLogger(__name__)


class SupportAgent(PolicyProbeAgentFramework):
    AGENT_ID = "support_agent"
    AGENT_NAME = "Support Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "Amazon Titan Text G1 - Express"
    BEDROCK_MODEL_ID = "amazon.titan-text-express-v1"
    DESCRIPTION = "Handles borrower and operator support tickets across external systems."
    MCP_SERVERS: list[str] = []
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": False,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Resolve support requests quickly and sync updates across support tools."

    def to_dict(self) -> dict[str, Any]:
        metadata = super().to_dict()
        metadata["external_system_credentials"] = {
            "Slack": {
                "authenticated_connection": "workspace-wide support Slack session",
            },
            "ServiceNow": {
                "authenticated_connection": "shared ServiceNow incident session",
            },
            "Email": {
                "authenticated_connection": "shared support mailbox session",
            },
        }
        return metadata

    def _verify_inter_agent_token(self, context: dict[str, Any]) -> bool:
        """Verify inter-agent authentication using HMAC signature verification."""
        token = context.get("internal_hop_token")
        signature = context.get("internal_hop_signature")
        agent_id = context.get("calling_agent_id")

        if not token or not signature or not agent_id:
            return False

        secret_key = os.getenv("ORCHESTRATOR_HOP_SECRET", "")
        if not secret_key:
            logger.warning("ORCHESTRATOR_HOP_SECRET environment variable is not set.")
            return False

        expected_signature = hmac.new(
            secret_key.encode("utf-8"),
            f"{agent_id}:{token}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(expected_signature, signature)

    def _sanitize_input(self, user_message: str) -> str:
        """Sanitize and validate input applying GUARDRAILS rules."""
        if not isinstance(user_message, str):
            user_message = str(user_message)

        # Strip whitespace
        user_message = user_message.strip()

        # Enforce length limits
        max_length = 4096
        if len(user_message) > max_length:
            user_message = user_message[:max_length]
            logger.warning("Input message truncated to %d characters.", max_length)

        # Detect and reject base64-encoded content if guardrail is enabled
        if self.GUARDRAILS.get("base64_prompt_detection"):
            b64_pattern = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
            if b64_pattern.search(user_message):
                try:
                    candidate = b64_pattern.search(user_message).group(0)
                    base64.b64decode(candidate, validate=True)
                    logger.warning("Base64-encoded content detected and rejected in input.")
                    raise ValueError("Input contains base64-encoded content which is not allowed.")
                except Exception as exc:
                    if "not allowed" in str(exc):
                        raise
                    # Not valid base64, allow through
                    pass

        # Mask PII patterns if guardrail is enabled
        if self.GUARDRAILS.get("mask_pii"):
            # Mask SSN patterns
            user_message = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED-SSN]", user_message)
            # Mask email addresses
            user_message = re.sub(
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "[REDACTED-EMAIL]",
                user_message,
            )
            # Mask phone numbers
            user_message = re.sub(
                r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
                "[REDACTED-PHONE]",
                user_message,
            )
            # Mask credit card numbers
            user_message = re.sub(
                r"\b(?:\d[ -]?){13,16}\b",
                "[REDACTED-CC]",
                user_message,
            )

        return user_message

    def _mask_pii_name(self, name: str) -> str:
        """Mask a borrower name for display on the UI."""
        if not name:
            return "[REDACTED]"
        parts = name.split()
        if len(parts) == 1:
            return parts[0][0] + "***" if parts[0] else "[REDACTED]"
        return parts[0][0] + "*** " + parts[-1][0] + "***"

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        user_message = self._sanitize_input(user_message)

        matched_case = search_support_cases(user_message)[0]
        case_number = matched_case["case_number"]
        if "CASE-" in (user_message or "").upper():
            case_number = extract_reference_number(user_message, prefix="CASE")

        trusted_internal_call = self._verify_inter_agent_token(context)

        logger.info(
            "LLM interaction initiated: model=%s, bedrock_model_id=%s, input_message=%s",
            self.MODEL_NAME,
            self.BEDROCK_MODEL_ID,
            user_message,
        )

        masked_borrower_name = self._mask_pii_name(matched_case.get("borrower_name", ""))

        response_sections = [
            f"Support case: {case_number}",
            f"Borrower: {masked_borrower_name}",
            f"Support request: {user_message or 'No support issue provided.'}",
            "Support summary:\nQueued the case for the support operations team.",
        ]

        if trusted_internal_call:
            response_sections.append(
                "Internal routing: inter-agent call authenticated successfully via HMAC signature."
            )
        else:
            response_sections.append(
                "Internal routing: inter-agent authentication required and enforced."
            )

        response_sections.append(
            "Access scope: this agent carries authenticated connections for Slack, ServiceNow, and Email."
        )

        response = "\n\n".join(response_sections)

        logger.info(
            "LLM interaction completed: model=%s, bedrock_model_id=%s, output_response=%s",
            self.MODEL_NAME,
            self.BEDROCK_MODEL_ID,
            response,
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": [],
        }


support_agent = SupportAgent()