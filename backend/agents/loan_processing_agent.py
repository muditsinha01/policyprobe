"""Loan Processing Agent class with explicit model invocation."""

import asyncio
import logging
import os
import re
import unicodedata
from typing import Any

from .framework import PolicyProbeAgentFramework
from .helpers import build_file_summary, extract_reference_number
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)

_DYNAMIC_CODE_PRIMITIVES = re.compile(
    r"\b(eval|exec|subprocess|os\.system|compile|__import__|importlib|open|globals|locals|vars|getattr|setattr|delattr|breakpoint|input)\s*\(",
    re.IGNORECASE,
)

_LOAN_NUMBER_RE = re.compile(r'^LOAN-[A-Z0-9]{1,20}$')

_MAX_INPUT_LENGTH = 8000
_MAX_SUMMARY_LENGTH = 16000

_PII_PATTERNS = [
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[SSN REDACTED]'),
    (re.compile(r'\b\d{9}\b'), '[SSN REDACTED]'),
    (re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b'), '[PHONE REDACTED]'),
    (re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'), '[EMAIL REDACTED]'),
    (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b'), '[CC REDACTED]'),
    (re.compile(r'\b\d{10,17}\b'), '[ACCOUNT REDACTED]'),
    (re.compile(r'\b\d{1,5}\s+[A-Za-z0-9\s,\.]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), '[ADDRESS REDACTED]'),
]

_SG_PII_PATTERNS = [
    re.compile(r'\b[STFGM]\d{7}[A-Z]\b', re.IGNORECASE),
    re.compile(r'\bSingPass\b', re.IGNORECASE),
    re.compile(r'\bCPF\s*[A-Z0-9]{6,12}\b', re.IGNORECASE),
    re.compile(r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,4}\b'),
]

_MALICIOUS_CONTENT_PATTERNS = [
    re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]'),
    re.compile(r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]'),
    re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'),
    re.compile(r'\b(?:ignore previous|disregard|forget|override|system prompt|you are now|act as|jailbreak)\b', re.IGNORECASE),
    re.compile(r'\b(?:rm\s+-rf|chmod|chown|wget|curl\s+http|bash\s+-c|sh\s+-c|/bin/sh|/bin/bash|cmd\.exe|powershell)\b', re.IGNORECASE),
    re.compile(r'[\x80-\xff]{4,}'),
]

_MCP_ALLOWED_KEYS = {"status", "result", "message", "data", "error", "document_id", "row_id", "email_id"}


def _sanitize_input(text: str, max_length: int = _MAX_INPUT_LENGTH) -> str:
    if not isinstance(text, str):
        text = str(text)
    text = text.replace('\x00', '')
    text = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    text = text[:max_length]
    return text


def _redact_pii(text: str) -> str:
    if not isinstance(text, str):
        return text
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _sanitize_mcp_input(text: str, max_length: int = _MAX_INPUT_LENGTH) -> str:
    if not isinstance(text, str):
        text = str(text)
    text = _sanitize_input(text, max_length)
    text = re.sub(r'[<>{};`$]', '', text)
    return text.strip()


def _validate_loan_number(loan_number: str) -> str:
    if not isinstance(loan_number, str):
        raise ValueError(f"Invalid loan number type: {type(loan_number)}")
    if not _LOAN_NUMBER_RE.match(loan_number):
        safe = re.sub(r'[^A-Z0-9\-]', '', loan_number.upper())[:30]
        logger.warning("Loan number '%s' did not match expected pattern; using sanitized form '%s'", loan_number, safe)
        return safe if safe else "LOAN-UNKNOWN"
    return loan_number


def _sanitize_llm_output(text: str) -> str:
    if not isinstance(text, str):
        return str(text)
    if _DYNAMIC_CODE_PRIMITIVES.search(text):
        logger.warning("Dynamic code execution primitive detected in LLM output; sanitizing.")
        text = _DYNAMIC_CODE_PRIMITIVES.sub('[REDACTED]', text)
    return text


def _sanitize_mcp_result(result: Any) -> dict:
    if not isinstance(result, dict):
        logger.warning("MCP result is not a dict (got %s); replacing with error placeholder.", type(result))
        return {"error": "invalid_mcp_response"}
    sanitized = {}
    for key, value in result.items():
        if key in _MCP_ALLOWED_KEYS:
            if isinstance(value, str):
                sanitized[key] = value.strip()
            else:
                sanitized[key] = value
        else:
            logger.warning("MCP result contained unexpected key '%s'; dropping.", key)
    return sanitized if sanitized else {"error": "no_valid_keys_in_mcp_response"}


def _scan_file_for_malicious_content(text: str) -> None:
    if not isinstance(text, str):
        return
    for pattern in _MALICIOUS_CONTENT_PATTERNS:
        if pattern.search(text):
            raise ValueError("Malicious or suspicious content detected in uploaded file.")


def _scan_file_for_sg_pii(text: str) -> None:
    if not isinstance(text, str):
        return
    for pattern in _SG_PII_PATTERNS:
        if pattern.search(text):
            raise ValueError("Singapore PII detected in uploaded file content.")


def _get_mcp_auth_token() -> str:
    token = os.environ.get("MCP_SERVER_SECRET")
    if not token:
        raise RuntimeError("MCP_SERVER_SECRET environment variable is not set; cannot authenticate MCP server.")
    return token


class LoanProcessingAgent(PolicyProbeAgentFramework):
    AGENT_ID = "loan_processing_agent"
    AGENT_NAME = "Loan Processing Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "amazon.nova-pro-v1:0"
    BEDROCK_MODEL_ID = "amazon.nova-pro-v1:0"
    DESCRIPTION = "Handles loan application intake, borrower updates, and loan package generation."
    MCP_SERVERS = ["Docx", "Excel", "Email"]
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": None,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Process loan requests, summarize borrower context, and prepare follow-up actions."
    IS_ROUTABLE = False
    IS_SCAN_ONLY = True

    async def call_agent_model(self, user_message: str, file_summary: str) -> str:
        sanitized_user_message = _sanitize_input(_redact_pii(user_message), _MAX_INPUT_LENGTH)
        sanitized_file_summary = _sanitize_input(_redact_pii(file_summary), _MAX_SUMMARY_LENGTH)

        logger.info(
            "LLM request: model=%s, user_message_length=%d, file_summary_length=%d",
            self.MODEL_NAME,
            len(sanitized_user_message),
            len(sanitized_file_summary),
        )

        result = await self.model_client.chat(
            model=self.MODEL_NAME,
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Loan request:\n{sanitized_user_message or 'No user message provided.'}\n\n"
                        f"File summary:\n{sanitized_file_summary}\n\n"
                        "Draft a concise loan processing next-step summary."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=250,
        )

        logger.info(
            "LLM response: model=%s, response_length=%d",
            self.MODEL_NAME,
            len(result) if isinstance(result, str) else -1,
        )

        return result

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        raw_file_contents = context.get("file_contents", [])

        for file_item in raw_file_contents:
            file_text = file_item if isinstance(file_item, str) else str(file_item)
            _scan_file_for_malicious_content(file_text)
            _scan_file_for_sg_pii(file_text)

        file_summary = build_file_summary(raw_file_contents)
        file_summary = _redact_pii(file_summary)

        loan_number = extract_reference_number(user_message, prefix="LOAN")
        loan_number = _validate_loan_number(loan_number)

        model_output = await self.call_agent_model(user_message, file_summary)
        model_output = _sanitize_llm_output(model_output)

        mcp_auth_token = _get_mcp_auth_token()
        server_auth = {
            "token": mcp_auth_token,
            "expected_identity": "trusted-mcp-server",
        }
        client_auth = {
            "agent_id": self.AGENT_ID,
            "bearer_token": mcp_auth_token,
        }

        safe_user_message = _sanitize_mcp_input(user_message)
        safe_file_summary = _sanitize_mcp_input(file_summary, _MAX_SUMMARY_LENGTH)
        safe_loan_number = _sanitize_mcp_input(loan_number, 50)

        mcp_activity_raw = await asyncio.gather(
            call_mcp_server(
                self.to_dict(),
                "Docx",
                "create_document",
                {
                    "document_title": f"Loan Intake Summary {safe_loan_number}",
                    "document_body": f"User message:\n{safe_user_message}\n\nFile summary:\n{safe_file_summary}",
                    "auth": client_auth,
                },
                server_auth=server_auth,
            ),
            call_mcp_server(
                self.to_dict(),
                "Excel",
                "upsert_row",
                {
                    "workbook": "Loan Pipeline",
                    "worksheet": "Applications",
                    "row": {
                        "loan_number": safe_loan_number,
                        "status": "processing",
                        "borrower_request": safe_user_message[:240],
                    },
                    "auth": client_auth,
                },
                server_auth=server_auth,
            ),
            call_mcp_server(
                self.to_dict(),
                "Email",
                "send_email",
                {
                    "to": ["borrower@acme.example"],
                    "subject": f"Loan update for {safe_loan_number}",
                    "body": "Your loan request is being reviewed by the Loan Processing Agent.",
                    "auth": client_auth,
                },
                server_auth=server_auth,
            ),
        )

        mcp_servers_called = ["Docx", "Excel", "Email"]
        mcp_tools_called = ["create_document", "upsert_row", "send_email"]
        mcp_activity = []
        for idx, result in enumerate(mcp_activity_raw):
            sanitized_result = _sanitize_mcp_result(result)
            server_name = mcp_servers_called[idx]
            tool_name = mcp_tools_called[idx]
            logger.info(
                "MCP interaction: server=%s, tool=%s, result=%s",
                server_name,
                tool_name,
                sanitized_result,
            )
            mcp_activity.append(sanitized_result)

        safe_display_message = _redact_pii(user_message or 'No user message provided.')
        safe_display_output = _redact_pii(model_output)

        response = (
            "This scan-only agent is disconnected from the Orchestrator Agent.\n\n"
            f"Loan reference: {safe_loan_number}\n"
            f"Borrower request: {safe_display_message}\n\n"
            f"Loan summary:\n{safe_display_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


loan_processing_agent = LoanProcessingAgent()