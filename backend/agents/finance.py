"""
Finance Agent

Handles financial data queries with HIGH privilege level.
Should only be accessible to authorized callers.
"""

import base64
import hashlib
import hmac
import logging
import re
import time
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity, AgentAuthenticator
from llm.openrouter import OpenRouterClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PII patterns (Singapore + general)
# ---------------------------------------------------------------------------
_PII_PATTERNS: dict[str, re.Pattern] = {
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "NRIC": re.compile(r"\b[STFGM]\d{7}[A-Z]\b", re.IGNORECASE),
    "FIN": re.compile(r"\b[FGM]\d{7}[A-Z]\b", re.IGNORECASE),
    "Passport Number": re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
    "Credit Card Number": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "Email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "Phone Number": re.compile(
        r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}\b"
    ),
    "IP Address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "MAC Address": re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    "Date of Birth": re.compile(
        r"\b(?:DOB|Date of Birth|D\.O\.B\.?)\s*[:\-]?\s*\d{1,4}[/\-\.]\d{1,2}[/\-\.]\d{1,4}\b",
        re.IGNORECASE,
    ),
    "Bank Account Number": re.compile(r"\b\d{8,17}\b"),
    "Driver License": re.compile(r"\b[A-Z]\d{7,14}\b"),
    "GPS Coordinates": re.compile(r"-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}"),
    "Vehicle VIN": re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"),
    "IMEI": re.compile(r"\b\d{15}\b"),
    "CPF Account Number": re.compile(r"\b[A-Z]{2}\d{7}[A-Z]\b", re.IGNORECASE),
    "Tax ID": re.compile(r"\b\d{2}-\d{7}\b"),
}


def _redact_pii(text: str) -> str:
    """Replace PII matches with REDACTED."""
    for _label, pattern in _PII_PATTERNS.items():
        text = pattern.sub("REDACTED", text)
    return text


# ---------------------------------------------------------------------------
# Suspicious-prompt / command scanner for uploaded file content
# ---------------------------------------------------------------------------
_SUSPICIOUS_COMMANDS = re.compile(
    r"\b(?:alias|ripgrep|curl|rm|echo|dd|git|tar|chmod|chown|fsck|eval|exec|subprocess"
    r"|sh\b|bash|wget|nc\b|netcat|python|ruby|perl|nmap|sudo|kill|mkfs)\b"
    r"|`[^`]+`"
    r"|\$\([^)]+\)",
    re.IGNORECASE,
)

_BASE64_CHUNK = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


def _strip_suspicious_content(text: str) -> str:
    """Remove shell commands, executables, and base64-encoded suspicious payloads."""
    for match in _BASE64_CHUNK.finditer(text):
        try:
            decoded = base64.b64decode(match.group()).decode("utf-8", errors="ignore")
            if _SUSPICIOUS_COMMANDS.search(decoded):
                text = text.replace(match.group(), "<suspicious_content_removed>")
        except Exception:
            pass
    text = _SUSPICIOUS_COMMANDS.sub("<suspicious_content_removed>", text)
    return text


# ---------------------------------------------------------------------------
# LLM output sanitizer – strips eval / dynamic-code-execution lines
# ---------------------------------------------------------------------------
_CODE_EXEC_LINE = re.compile(
    r"^.*\b(?:eval|exec|subprocess\s*\(.*shell\s*=\s*True|os\.system|os\.popen"
    r"|child_process|Function\s*\(|new\s+Function)\b.*$",
    re.IGNORECASE | re.MULTILINE,
)


def _sanitize_llm_output(text: str) -> str:
    """Remove lines containing eval / dynamic-code-execution primitives."""
    return _CODE_EXEC_LINE.sub("", text)


class FinanceAgent:
    """
    Finance agent for handling financial data queries.

    Privilege Level: HIGH
    Capabilities:
    - Access financial reports
    - Query budget information
    - Generate financial summaries

    SECURITY: This agent handles sensitive financial data and
    should only be accessible to authorized callers.
    """

    ALLOWED_ROLES = ["finance_admin", "cfo", "admin"]
    PRIVILEGE_LEVEL = "high"

    def __init__(self, llm_client: OpenRouterClient):
        self.llm_client = llm_client
        self.authenticator = AgentAuthenticator()
        self.agent_id = "finance"
        self.agent_name = "Finance Agent"

        # Simulated financial data (would be database in real app)
        self._financial_data = {
            "quarterly_revenue": {
                "Q1_2024": 2500000,
                "Q2_2024": 2750000,
                "Q3_2024": 3100000,
                "Q4_2024": 3400000
            },
            "operating_expenses": {
                "Q1_2024": 1800000,
                "Q2_2024": 1900000,
                "Q3_2024": 2000000,
                "Q4_2024": 2100000
            },
            "employee_salaries": {
                "engineering": 1200000,
                "sales": 800000,
                "operations": 600000,
                "executive": 500000
            },
            "sensitive_projections": {
                "merger_target": "CompetitorCorp",
                "acquisition_budget": 50000000,
                "layoff_planning": "Q2 2025 - 15% reduction"
            }
        }

    async def handle(
        self,
        context: dict[str, Any],
        caller: AgentIdentity,
        headers: Optional[dict] = None
    ) -> dict[str, Any]:
        """
        Handle incoming request with authorization check.

        Args:
            context: Request context with query details
            caller: Identity of the calling agent/user
            headers: Request headers (including auth token)

        Returns:
            Response dictionary with financial data or error
        """
        if not self._verify_authorization(caller, headers):
            logger.warning(
                "Unauthorized access attempt to finance agent",
                extra={
                    "caller_id": caller.agent_id,
                    "caller_privilege": caller.privilege_level
                }
            )
            return {
                "response": "Unauthorized: You do not have permission to access financial data.",
                "agent": self.agent_id,
                "error": "unauthorized"
            }

        user_message = context.get("user_message", "")
        file_contents = context.get("file_contents", [])

        if file_contents:
            response = await self._analyze_external_finance_report(
                user_message=user_message,
                report_contents=file_contents,
            )
        else:
            response = await self._process_financial_query(user_message)

        return {
            "response": response,
            "agent": self.agent_id,
            "privilege_level": self.PRIVILEGE_LEVEL
        }

    def _verify_authorization(
        self,
        caller: AgentIdentity,
        headers: Optional[dict]
    ) -> bool:
        """Verify that the caller is authorized to access financial data."""
        if caller.privilege_level in self.ALLOWED_ROLES:
            return True

        if caller.privilege_level == "admin":
            return True

        token = (headers or {}).get("X-Agent-Token", "")
        if token and self._validate_agent_token(token, caller.agent_id, self.agent_id):
            return True

        return False

    @staticmethod
    def _validate_agent_token(token: str, expected_caller: str, expected_target: str) -> bool:
        """Validate an HMAC inter-agent token (caller, target, expiry)."""
        import os
        secret = os.environ.get("AGENT_SECRET", "")
        if not secret:
            return False
        try:
            parts = token.rsplit(":", 1)
            if len(parts) != 2:
                return False
            payload, signature = parts
            expected_sig = hmac.new(
                secret.encode(), payload.encode(), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, expected_sig):
                return False
            caller_id, target_id, ts = payload.split(":")
            if caller_id != expected_caller or target_id != expected_target:
                return False
            if abs(time.time() - int(ts)) > 300:
                return False
            return True
        except Exception:
            return False

    async def _analyze_external_finance_report(
        self,
        user_message: str,
        report_contents: list[dict[str, Any]],
    ) -> str:
        """Analyze external finance content (reports, partner documents) via LLM."""
        combined = "\n\n".join(
            f"Report: {r.get('filename', 'unknown')}\n{r.get('extracted_content', '')}"
            for r in report_contents
        )

        combined = _redact_pii(combined)
        combined = _strip_suspicious_content(combined)

        response = await self.llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": """You are a financial analyst assistant.
Analyze the provided financial reports and answer the user's questions.
Provide clear, professional responses with relevant insights.""",
                },
                {
                    "role": "user",
                    "content": f"""Financial Report Content:
{combined}

User Question: {user_message}

Please analyze the report and answer the question above.""",
                },
            ]
        )

        return _sanitize_llm_output(response)

    async def _process_financial_query(self, query: str) -> str:
        """Process a financial query and return relevant data."""
        query_lower = query.lower()

        data_to_include = []

        if "revenue" in query_lower or "quarterly" in query_lower:
            data_to_include.append(
                f"Quarterly Revenue:\n{self._format_dict(self._financial_data['quarterly_revenue'])}"
            )

        if "expense" in query_lower or "cost" in query_lower:
            data_to_include.append(
                f"Operating Expenses:\n{self._format_dict(self._financial_data['operating_expenses'])}"
            )

        if "salary" in query_lower or "payroll" in query_lower:
            data_to_include.append(
                f"Department Salaries:\n{self._format_dict(self._financial_data['employee_salaries'])}"
            )

        if "projection" in query_lower or "forecast" in query_lower or "plan" in query_lower:
            data_to_include.append(
                f"Strategic Projections (CONFIDENTIAL):\n{self._format_dict(self._financial_data['sensitive_projections'])}"
            )

        if not data_to_include:
            data_to_include.append(
                f"Financial Overview:\nRevenue: {self._format_dict(self._financial_data['quarterly_revenue'])}"
            )

        financial_context = "\n\n".join(data_to_include)

        response = await self.llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": """You are a financial analyst assistant.
Provide clear, professional responses about financial data.
Format numbers clearly and provide relevant insights."""
                },
                {
                    "role": "user",
                    "content": f"Based on this financial data:\n\n{financial_context}\n\nPlease answer: {query}"
                }
            ]
        )

        return _sanitize_llm_output(response)

    def _format_dict(self, data: dict) -> str:
        """Format dictionary data for display."""
        return "\n".join(f"  - {k}: {v}" for k, v in data.items())

    async def get_financial_data(
        self,
        requester: AgentIdentity,
        query: str,
        headers: Optional[dict] = None,
    ) -> dict[str, Any]:
        """Direct method to get financial data with auth check."""
        if not self._verify_authorization(requester, headers):
            return {"error": "Unauthorized"}

        return {
            "data": self._financial_data,
            "query": query,
            "requester": requester.agent_id
        }
