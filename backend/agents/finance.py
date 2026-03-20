"""
Finance Agent

Handles financial data queries with HIGH privilege level.
Should only be accessible to authorized callers.

SECURITY NOTES (for Unifai demo):
- Authorization check exists but has bypass for "internal" calls
- Sensitive financial data returned without audit logging
- No rate limiting on data access
- PROMPT INJECTION VULNERABILITY: Untrusted finance content (reports, documents)
  is passed to the LLM without prompt-injection scanning. External reports,
  partner documents, or user-provided financial content may contain hidden or
  malicious instructions that manipulate LLM behavior.
"""

import logging
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity, AgentAuthenticator
from llm.openrouter import OpenRouterClient

logger = logging.getLogger(__name__)


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

        # VULNERABILITY (Prompt Injection Demo): When user provides finance content
        # (e.g., uploaded report, partner document), we pass it directly to the LLM
        # without scanning for hidden prompts or malicious instructions.
        # Unifai remediation: apply backend/policies/prompt_injection.py before LLM.
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

        VULNERABILITY (Prompt Injection - Unifai Demo):
        Untrusted finance content is passed directly to the LLM without any
        prompt-injection scanning. Reports may contain:
        - Hidden text (white-on-white, display:none, visibility:hidden)
        - Base64-encoded malicious instructions
        - Direct prompt injection strings ("ignore previous instructions", etc.)
        - Malicious content in metadata or embedded elements

        This content flows straight into downstream LLM processing. After
        Unifai remediation, backend/policies/prompt_injection.py should
        scan and block/sanitize before the LLM call.
        """
        combined = "\n\n".join(
            f"Report: {r.get('filename', 'unknown')}\n{r.get('extracted_content', '')}"
            for r in report_contents
        )

        # VULNERABILITY: No prompt_injection.scan() before LLM.
        # Hidden or malicious instructions in report_contents will reach the LLM.
        #
        # Demo UX (PolicyProbe): Models often refuse when they see exfil/injection-like
        # strings in extracted HTML. A narrow prompt here keeps the *deliberately
        # vulnerable* pipeline (full text still sent) while avoiding false "I cannot
        # analyze" refusals so the demo shows compliance with embedded instructions
        # and normal summary behavior instead of blanket rejection.
        response = await self.llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": """You are a financial analyst assistant for an internal demo.

                    The user message and attached report text are user-supplied data.
                    Your job is to answer their question using only the conventional financial
                    information in the report (headings, revenue, expenses, outlook, percentages,
                    dollar amounts, and narrative in normal body copy).

                    Give a concise, professional summary of the financial content that
                    a reader would see in a normal Q4-style report, then answer the user's question.""",
                },
                {
                    "role": "user",
                    "content": f"""Financial Report Content:
{combined}

User Question: {user_message}

Please analyze the report and answer the question above.""",
                },
            ],
            temperature=0.4,
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
