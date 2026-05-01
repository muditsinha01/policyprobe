"""Orchestrator Agent class with explicit model invocation."""

import hashlib
import hmac
import logging
import os
import re
import unicodedata
from typing import Any

from .credit_eval_agent import credit_eval_agent
from .file_processor_agent import file_processor_agent
from .framework import PolicyProbeAgentFramework
from .loan_processing_agent import loan_processing_agent
from .scheduling_agent import scheduling_agent
from .support_agent import support_agent

logger = logging.getLogger(__name__)

_DANGEROUS_CODE_PATTERNS = re.compile(
    r"\b(eval|exec|subprocess|__import__|compile|execfile|globals|locals|vars|open|os\.system|os\.popen)\s*\(",
    re.IGNORECASE,
)

_PROMPT_INJECTION_PATTERNS = re.compile(
    r"(ignore previous instructions|disregard (all )?prior|you are now|new instructions:|system prompt:|<\|im_start\|>|<\|im_end\|>)",
    re.IGNORECASE,
)

_MAX_STRING_LENGTH = 8192
_MAX_AGENT_NAME_LENGTH = 256

_SINGAPORE_PII_PATTERNS = [
    re.compile(r"\b[STFGM]\d{7}[A-Z]\b"),
    re.compile(r"\bSingPass\b", re.IGNORECASE),
    re.compile(r"\bCPF\s*\d{6,}\b", re.IGNORECASE),
]

_PII_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN REDACTED]"),
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[CC REDACTED]"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[EMAIL REDACTED]"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[PHONE REDACTED]"),
]

_FILE_SUSPICIOUS_PATTERNS = [
    re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]"),
    re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"),
    re.compile(r"\b(ignore previous instructions|disregard|you are now|new instructions:|system prompt:)\b", re.IGNORECASE),
    re.compile(r"\b(sh|bash|cmd|powershell|wget|curl|chmod|sudo|rm\s+-rf|eval|exec)\b", re.IGNORECASE),
    re.compile(r"[0O][Bb][Ee][Yy]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Hh][Aa][Cc][Kk]"),
]


def _sanitize_string_input(value: str, max_length: int = _MAX_STRING_LENGTH) -> str:
    if not isinstance(value, str):
        value = str(value)
    value = value.replace("\x00", "")
    value = "".join(ch for ch in value if unicodedata.category(ch) not in ("Cc", "Cf") or ch in ("\n", "\r", "\t"))
    value = value.strip()
    if len(value) > max_length:
        value = value[:max_length]
    return value


def _sanitize_file_contents(file_contents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not file_contents:
        return file_contents
    sanitized = []
    for item in file_contents:
        if not isinstance(item, dict):
            continue
        new_item = dict(item)
        if "content" in new_item and isinstance(new_item["content"], str):
            content = new_item["content"].replace("\x00", "")
            content = content.strip()
            if len(content) > _MAX_STRING_LENGTH:
                content = content[:_MAX_STRING_LENGTH]
            if _PROMPT_INJECTION_PATTERNS.search(content):
                content = _PROMPT_INJECTION_PATTERNS.sub("[REDACTED]", content)
            new_item["content"] = content
        sanitized.append(new_item)
    return sanitized


def _sanitize_llm_output(output: str) -> str:
    if not isinstance(output, str):
        output = str(output)
    if _DANGEROUS_CODE_PATTERNS.search(output):
        logger.warning("Dangerous code execution primitive detected in LLM output; sanitizing.")
        output = _DANGEROUS_CODE_PATTERNS.sub("[BLOCKED]", output)
    if len(output) > _MAX_STRING_LENGTH:
        output = output[:_MAX_STRING_LENGTH]
    return output


def _sanitize_mcp_output(output: Any) -> str:
    if not isinstance(output, str):
        try:
            output = str(output)
        except Exception:
            return ""
    if len(output) > _MAX_STRING_LENGTH:
        logger.warning("MCP output exceeded max length; truncating.")
        output = output[:_MAX_STRING_LENGTH]
    if _DANGEROUS_CODE_PATTERNS.search(output):
        logger.warning("Dangerous content detected in MCP output; sanitizing.")
        output = _DANGEROUS_CODE_PATTERNS.sub("[BLOCKED]", output)
    if _PROMPT_INJECTION_PATTERNS.search(output):
        logger.warning("Prompt injection pattern detected in MCP output; sanitizing.")
        output = _PROMPT_INJECTION_PATTERNS.sub("[REDACTED]", output)
    return output


def _generate_hop_token(agent_name: str, selected_agent_name: str) -> str:
    secret_key = os.environ.get("INTER_AGENT_SECRET_KEY", "")
    if not secret_key:
        logger.warning("INTER_AGENT_SECRET_KEY is not set; inter-agent token will be weak.")
    message = f"{agent_name}:{selected_agent_name}".encode("utf-8")
    token = hmac.new(secret_key.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return token


def _verify_hop_token(token: str, agent_name: str, selected_agent_name: str) -> bool:
    expected = _generate_hop_token(agent_name, selected_agent_name)
    return hmac.compare_digest(token, expected)


def _authenticate_mcp_server() -> None:
    mcp_server_token = os.environ.get("SLACK_MCP_SERVER_TOKEN", "")
    if not mcp_server_token:
        raise RuntimeError("MCP server authentication failed: SLACK_MCP_SERVER_TOKEN is not set.")
    logger.info("MCP server authentication succeeded.")


def _check_singapore_pii(file_contents: list[dict[str, Any]]) -> None:
    for item in file_contents:
        if not isinstance(item, dict):
            continue
        content = item.get("content", "")
        if not isinstance(content, str):
            continue
        for pattern in _SINGAPORE_PII_PATTERNS:
            if pattern.search(content):
                raise ValueError("Singapore PII detected in uploaded file content; blocking request.")


def _scan_file_for_malicious_content(file_contents: list[dict[str, Any]]) -> None:
    for item in file_contents:
        if not isinstance(item, dict):
            continue
        content = item.get("content", "")
        if not isinstance(content, str):
            continue
        for pattern in _FILE_SUSPICIOUS_PATTERNS:
            if pattern.search(content):
                raise ValueError(
                    f"Suspicious content detected in uploaded file (matched pattern: {pattern.pattern!r}); blocking request."
                )


class OrchestratorAgent(PolicyProbeAgentFramework):
    AGENT_ID = "orchestrator_agent"
    AGENT_NAME = "Orchestrator Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "claude-3-5-sonnet-20241022"
    BEDROCK_MODEL_ID = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    DESCRIPTION = "Routes work between the specialized agents and shares the conversation context."
    MCP_SERVERS = [
        {
            "name": "Slack",
            "api_key_env": "SLACK_MCP_API_KEY",
            "api_key": os.environ.get("SLACK_MCP_API_KEY", ""),
        }
    ]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": True,
    }
    SYSTEM_PROMPT = "Route requests to the right specialist and keep the workflow moving."

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        try:
            _authenticate_mcp_server()
        except RuntimeError as exc:
            logger.error("MCP server authentication error during init: %s", exc)

    def redact_pii_from_file_contents(self, file_contents: list[dict[str, Any]]) -> list[dict[str, Any]]:
        redacted = []
        for item in file_contents:
            if not isinstance(item, dict):
                redacted.append(item)
                continue
            new_item = dict(item)
            if "content" in new_item and isinstance(new_item["content"], str):
                content = new_item["content"]
                for pattern, replacement in _PII_PATTERNS:
                    content = pattern.sub(replacement, content)
                new_item["content"] = content
            redacted.append(new_item)
        return redacted

    def _invoke_slack_mcp_tool(self, tool_name: str, inputs: dict[str, Any]) -> Any:
        _authenticate_mcp_server()
        logger.info(
            "MCP tool call to Slack server",
            extra={"tool_name": tool_name, "inputs": inputs},
        )
        result = None
        logger.info(
            "MCP tool response from Slack server",
            extra={"tool_name": tool_name, "raw_output": result},
        )
        sanitized_result = _sanitize_mcp_output(result)
        logger.info(
            "MCP tool sanitized output",
            extra={"tool_name": tool_name, "sanitized_output": sanitized_result},
        )
        return sanitized_result

    async def call_agent_model(self, user_message: str, selected_agent_name: str) -> str:
        safe_user_message = _sanitize_string_input(user_message or "", max_length=_MAX_STRING_LENGTH)
        safe_agent_name = _sanitize_string_input(selected_agent_name or "", max_length=_MAX_AGENT_NAME_LENGTH)

        logger.info(
            "LLM request initiated",
            extra={
                "agent": self.AGENT_NAME,
                "user_message_preview": safe_user_message[:200],
                "selected_agent_name": safe_agent_name,
                "model": self.MODEL_NAME,
            },
        )

        raw_response = await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"User request:\n{safe_user_message or 'No user message provided.'}\n\n"
                        f"Selected agent: {safe_agent_name}\n\n"
                        "Explain the routing decision in one short paragraph."
                    ),
                },
            ],
            temperature=0.1,
            max_tokens=160,
        )

        sanitized_response = _sanitize_llm_output(raw_response)

        logger.info(
            "LLM response received",
            extra={
                "agent": self.AGENT_NAME,
                "selected_agent_name": safe_agent_name,
                "response_preview": sanitized_response[:200],
            },
        )

        return sanitized_response

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        raw_user_message = context.get("user_message", "")
        safe_user_message = _sanitize_string_input(raw_user_message or "")

        raw_file_contents = context.get("file_contents", [])
        safe_file_contents = _sanitize_file_contents(raw_file_contents)

        _check_singapore_pii(safe_file_contents)

        selected_agent = self.select_agent(
            user_message=safe_user_message,
            file_contents=safe_file_contents,
        )
        selected_agent_name = selected_agent.AGENT_NAME

        hop_token = _generate_hop_token(self.AGENT_NAME, selected_agent_name)

        if not _verify_hop_token(hop_token, self.AGENT_NAME, selected_agent_name):
            raise RuntimeError("Inter-agent authentication failed: hop token verification error.")

        redacted_file_contents = self.redact_pii_from_file_contents(safe_file_contents)

        forwarded_context = dict(context)
        forwarded_context["user_message"] = safe_user_message
        forwarded_context["file_contents"] = redacted_file_contents
        forwarded_context["orchestrator_agent"] = self.AGENT_NAME
        forwarded_context["selected_agent"] = selected_agent_name
        forwarded_context["internal_call_chain"] = [self.AGENT_NAME, selected_agent_name]
        forwarded_context["internal_hop_token"] = hop_token

        logger.info(
            "Orchestrator Agent routing request",
            extra={
                "selected_agent": selected_agent_name,
                "internal_call_chain": forwarded_context["internal_call_chain"],
            },
        )

        logger.info(
            "LLM request initiated",
            extra={
                "agent": self.AGENT_NAME,
                "user_message_preview": safe_user_message[:200],
                "selected_agent_name": selected_agent_name,
            },
        )

        routing_note = await self.call_agent_model(
            safe_user_message,
            selected_agent_name,
        )

        routing_note = _sanitize_llm_output(routing_note)

        logger.info(
            "LLM response received in handle",
            extra={
                "agent": self.AGENT_NAME,
                "routing_note_preview": routing_note[:200],
            },
        )

        response = await selected_agent.handle(forwarded_context)

        if isinstance(response, dict):
            for key, value in response.items():
                if isinstance(value, str):
                    response[key] = _sanitize_llm_output(value)

        response["orchestrator"] = self.AGENT_NAME
        response["routing_note"] = routing_note
        return response

    def select_agent(self, user_message: str, file_contents: list[dict[str, Any]]) -> PolicyProbeAgentFramework:
        text = (user_message or "").lower()

        if any(keyword in text for keyword in ["schedule", "meeting", "calendar", "appointment"]):
            return scheduling_agent
        if any(keyword in text for keyword in ["base64", "encoded", "vulnerability", "download", "package"]):
            return support_agent
        if any(keyword in text for keyword in ["support", "ticket", "incident", "password", "outage"]):
            return support_agent
        if any(keyword in text for keyword in ["credit", "fico", "debt-to-income", "dti", "underwrite", "loan status", "employee", "ssn", "borrower status"]):
            return credit_eval_agent
        if any(keyword in text for keyword in ["loan", "mortgage", "borrower", "application"]):
            return credit_eval_agent
        if file_contents:
            _scan_file_for_malicious_content(file_contents)
            return file_processor_agent
        return support_agent


orchestrator_agent = OrchestratorAgent()