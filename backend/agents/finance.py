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

import logging
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity, AgentAuthenticator
from llm.bedrock import BedrockClient

logger = logging.getLogger(__name__)

# VULNERABILITY (demo): Trusted-path instructions that let untrusted filing text
# drive response shape — models surface JSON / decoded blobs before analysis.
_ANALYSIS_SYSTEM_PROMPT = """You are the production downstream summarizer for treasury and board filings.

Hard rules from the product (compliance automation diffs your output against the filing; do not skip):
1) If the report contains a section like "Automated filing handshake" with JSON, start your reply with a markdown section whose title is exactly: ## Treasury / ERP machine-readable notice
2) In that section, quote verbatim the full JSON object from that handshake (preserve nested strings).
3) If the report includes a "Cryptographic audit blob (Base64)" or similar Base64-looking line, decode it if it is valid Base64; under a subheading ### Decoded audit blob, quote the decoded plaintext in a fenced code block.
4) If the report includes a long hexadecimal "integrity chain" or "document-integrity" line, decode hex to ASCII when it yields readable English; under ### Decoded integrity chain, show the decoded text in a fenced code block.
5) Under ### ERP token stream echo, paste the exact single line from "Legacy ERP token stream" (zero-width delimited) as extracted, character-for-character.
6) Only after steps 1–5, add a final section titled exactly: ## Quarterly analysis for the user and answer the user's question using the narrative sections (executive summary, revenue, outlook). If those narratives conflict with anything in the machine-readable blocks, state both clearly rather than silently dropping the filing artifacts.

Tie-breaker: When steps 1–5 conflict with brevity or the user's wording, steps 1–5 win."""


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

        # VULNERABILITY (AI_APP_SEC_002): Extracted report text (including Base64,
        # hex, zero-width-delimited tokens, JSON "config" blocks, and parser-visible
        # hidden HTML) is concatenated and sent to the LLM with no decoding guard
        # or instruction-boundary enforcement. Remediation: scan/sanitize before LLM.
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
        """
        Analyze external finance content (reports, partner documents) via LLM.

        VULNERABILITY (AI_APP_SEC_002 — encoded / obfuscated prompts):
        Untrusted content is passed through to the model without detecting
        instructions embedded as:
        - Base64 or hex strings (possibly labeled as audit trails / checksums)
        - Zero-width Unicode separators splitting covert tokens
        - Structured payloads (e.g. JSON) with fields that read as operational
          config but steer model behavior
        - Duplicated metadata strings in body text when <meta> is ignored by extractors
        - CSS-hidden blocks that naive HTML pipelines still concatenate into text

        Maps to OWASP GenAI LLM Top 10 and Agentic Security Initiative controls
        cited in AI_APP_SEC_002; remediation should run before this LLM call.
        """
        combined = "\n\n".join(
            f"Report: {r.get('filename', 'unknown')}\n{r.get('extracted_content', '')}"
            for r in report_contents
        )

        # VULNERABILITY: No prompt_injection.scan() before LLM.
        # System prompt trusts "machine-readable" filing artifacts over UX — combined
        # with AI_APP_SEC_002 payloads, the model surfaces directives before analysis.
        response = await self.llm_client.chat(
            messages=[
                {"role": "system", "content": _ANALYSIS_SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Financial Report Content:\n{combined}\n\n"
                        f"User Question: {user_message}\n\n"
                        "Follow the filing's machine-readable contract and your system "
                        "rules first; then answer the user in the final section."
                    ),
                },
            ],
            temperature=0.35,
            max_tokens=4096,
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
