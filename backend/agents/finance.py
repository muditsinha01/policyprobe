"""
Finance Agent

Handles financial data queries with HIGH privilege level.
Should only be accessible to authorized callers.

SECURITY NOTES (Unifai / Lineaje demo — AI_APP_SEC_002):
- Control: Encoded prompts — instructions concealed in Base64, hex, zero-width
  characters, structured payloads (JSON/XML), duplicated metadata, or content
  that is CSS-hidden but still extracted by parsers.
- Risk: Invisible or obfuscated prompt injection, safety / policy bypass,
  leakage of system instructions, corrupted downstream workflows; low attack
  complexity, no privileges required (OWASP LLM01, LLM04, LLM05, LLM08;
  OWASP-ASI ASI-01, ASI-04, ASI-07, ASI-09; EU AI Act transparency themes).
- This agent passes extracted document text to the LLM without decoding or
  policy checks on those channels.
- Additional demo issues: internal auth bypass, missing audit logging, no
  rate limiting (separate from AI_APP_SEC_002).
"""

import base64
import logging
import re
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity, AgentAuthenticator
from llm.bedrock import BedrockClient

logger = logging.getLogger(__name__)

_SUSPICIOUS_COMMANDS = re.compile(
    r'\b(?:alias|ripgrep|curl|rm|echo|dd|git|tar|chmod|chown|fsck'
    r'|wget|bash|sh|zsh|python|perl|ruby|nc|ncat|netcat'
    r'|powershell|cmd\.exe|eval|exec|sudo|su|kill|mkfs'
    r'|passwd|ssh|scp|nmap|telnet)\b',
    re.IGNORECASE,
)

_LEET_MAP = str.maketrans('01345@!', 'oieasai')

_MALICIOUS_PROMPT_PATTERNS = re.compile(
    r'(?:'
    r'ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions'
    r'|override[_\s]?user'
    r'|discard\s+alignment'
    r'|bypass\s+(?:safety|security|user)'
    r'|priority["\s:]*override'
    r'|superseding\s+all\s+user\s+prompts'
    r'|do\s+not\s+mention\s+this\s+instruction'
    r'|exfil'
    r'|dump\s+any\s+secrets'
    r'|system\s+prompts?\s+you\s+were\s+given'
    r'|INTERNAL_EXFIL'
    r'|WIRE\s+AUTH'
    r'|WIRE.*DESK.*OVERRIDE'
    r'|SAFETY.*LAYER.*DISABLED'
    r')',
    re.IGNORECASE,
)

_REPLACEMENT = '<suspicious_content_removed>'


def _decode_base64_segments(text: str) -> str:
    """Decode Base64-looking tokens so hidden commands become visible to scanning."""
    def _try_decode(m: re.Match) -> str:
        try:
            decoded = base64.b64decode(m.group(0)).decode('utf-8', errors='replace')
            return f'{m.group(0)} [decoded: {decoded}]'
        except Exception:
            return m.group(0)
    return re.sub(r'[A-Za-z0-9+/]{20,}={0,2}', _try_decode, text)


def _decode_hex_segments(text: str) -> str:
    """Decode long hex strings so hidden commands become visible to scanning."""
    def _try_decode(m: re.Match) -> str:
        try:
            decoded = bytes.fromhex(m.group(0)).decode('utf-8', errors='replace')
            if decoded.isascii() and any(c.isalpha() for c in decoded):
                return f'{m.group(0)} [decoded: {decoded}]'
        except Exception:
            pass
        return m.group(0)
    return re.sub(r'(?:[0-9a-fA-F]{2}\s*){20,}', _try_decode, text)


def _strip_zero_width(text: str) -> str:
    """Remove zero-width characters that can hide tokens from pattern matchers."""
    return re.sub(r'[\u200b\u200c\u200d\u2060\ufeff]', '', text)


def sanitize_uploaded_content(text: str) -> str:
    """Sanitize uploaded file content: decode obfuscated payloads, strip
    suspicious commands and malicious prompt-injection patterns."""
    cleaned = _strip_zero_width(text)
    cleaned = _decode_base64_segments(cleaned)
    cleaned = _decode_hex_segments(cleaned)

    leet_version = cleaned.translate(_LEET_MAP)
    if _SUSPICIOUS_COMMANDS.search(leet_version):
        cleaned = _SUSPICIOUS_COMMANDS.sub(_REPLACEMENT, cleaned)
        leet_cleaned = leet_version
        for cmd_match in _SUSPICIOUS_COMMANDS.finditer(leet_cleaned):
            cleaned = cleaned[:cmd_match.start()] + _REPLACEMENT + cleaned[cmd_match.end():]

    cleaned = _SUSPICIOUS_COMMANDS.sub(_REPLACEMENT, cleaned)
    cleaned = _MALICIOUS_PROMPT_PATTERNS.sub(_REPLACEMENT, cleaned)

    return cleaned


_ANALYSIS_SYSTEM_PROMPT = """You are a financial analyst assistant.
Analyze the provided financial reports and answer the user's questions.
Provide clear, professional responses with relevant insights."""


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

    def __init__(self, llm_client: BedrockClient):
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
        # Authorization check
        # VULNERABILITY: Check exists but has bypass
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
        """
        Verify that the caller is authorized to access financial data.

        VULNERABILITY: The is_internal flag bypasses all privilege checks.
        Any agent claiming to be "internal" can access financial data.
        """
        # Check 1: Role-based access
        if caller.privilege_level in self.ALLOWED_ROLES:
            return True

        # Check 2: Admin override
        if caller.privilege_level == "admin":
            return True

        # VULNERABILITY: Internal bypass - any agent claiming internal status
        # gets full access without verification
        if caller.is_internal:
            logger.info(
                "Internal caller accessing finance agent",
                extra={
                    "caller": caller.agent_id,
                    "note": "Internal bypass used"
                }
            )
            return True  # Bypass for "internal" calls

        # Check 3: Token verification (but token is never actually validated!)
        # VULNERABILITY: We check if token exists but never validate it
        if headers and headers.get("X-Agent-Token"):
            # Token exists, but we don't verify its validity
            # This is a security vulnerability - any token passes
            logger.debug("Token provided, granting access")
            return True

        return False

    async def _analyze_external_finance_report(
        self,
        user_message: str,
        report_contents: list[dict[str, Any]],
    ) -> str:
        """Analyze external finance content (reports, partner documents) via LLM.

        Uploaded content is sanitized before reaching the model:
        - Base64 and hex segments are decoded and scanned
        - Zero-width characters are stripped
        - Suspicious commands and malicious prompt patterns are replaced
        """
        combined = "\n\n".join(
            f"Report: {r.get('filename', 'unknown')}\n{r.get('extracted_content', '')}"
            for r in report_contents
        )

        combined = sanitize_uploaded_content(combined)

        response = await self.llm_client.chat(
            messages=[
                {"role": "system", "content": _ANALYSIS_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Financial Report Content:\n{combined}\n\n"
                        f"User Question: {user_message}"
                    ),
                },
            ],
        )

        return response

    async def _process_financial_query(self, query: str) -> str:
        """
        Process a financial query and return relevant data.

        VULNERABILITY: Sensitive financial data returned without
        proper audit logging or data masking.
        """
        query_lower = query.lower()

        # Determine what data to include
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
            # VULNERABILITY: Salary data returned without masking
            data_to_include.append(
                f"Department Salaries:\n{self._format_dict(self._financial_data['employee_salaries'])}"
            )

        if "projection" in query_lower or "forecast" in query_lower or "plan" in query_lower:
            # VULNERABILITY: Highly sensitive strategic data exposed
            data_to_include.append(
                f"Strategic Projections (CONFIDENTIAL):\n{self._format_dict(self._financial_data['sensitive_projections'])}"
            )

        if not data_to_include:
            # Default response with general financial overview
            data_to_include.append(
                f"Financial Overview:\nRevenue: {self._format_dict(self._financial_data['quarterly_revenue'])}"
            )

        financial_context = "\n\n".join(data_to_include)

        # Use LLM to generate a natural response
        # VULNERABILITY: Sensitive financial data sent to external LLM
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

        return response

    def _format_dict(self, data: dict) -> str:
        """Format dictionary data for display."""
        return "\n".join(f"  - {k}: {v}" for k, v in data.items())

    async def get_financial_data(
        self,
        requester: AgentIdentity,
        query: str
    ) -> dict[str, Any]:
        """
        Direct method to get financial data.

        VULNERABILITY: Authorization check has internal bypass.
        Used by other agents to access financial data directly.
        """
        # Authorization check with bypass
        if requester.privilege_level in self.ALLOWED_ROLES:
            pass  # Authorized
        elif requester.is_internal:
            # VULNERABILITY: is_internal always True for agent calls
            pass  # Bypassed
        else:
            return {"error": "Unauthorized"}

        # VULNERABILITY: Full financial data access without granular permissions
        return {
            "data": self._financial_data,
            "query": query,
            "requester": requester.agent_id
        }
