"""
Agent Orchestrator

Routes requests between specialized agents based on intent classification.
Manages the multi-agent workflow and aggregates responses.
"""

import hashlib
import hmac
import logging
import re
import secrets
import time
from typing import Any, Optional

from .tech_support import TechSupportAgent
from .finance import FinanceAgent
from .file_processor import FileProcessorAgent
from .auth.agent_auth import AgentAuthenticator, AgentIdentity
from llm.openrouter import OpenRouterClient

logger = logging.getLogger(__name__)


_PII_PATTERNS: dict[str, re.Pattern] = {
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "NRIC": re.compile(r"\b[STFGM]\d{7}[A-Z]\b", re.IGNORECASE),
    "FIN": re.compile(r"\b[FGM]\d{7}[A-Z]\b", re.IGNORECASE),
    "Passport Number": re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
    "Credit Card Number": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "Email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    "Phone Number": re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}\b"),
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
    """Scan *text* for PII patterns and replace matches with REDACTED."""
    for label, pattern in _PII_PATTERNS.items():
        text = pattern.sub("REDACTED", text)
    return text


class AgentOrchestrator:
    """
    Central orchestrator that routes requests to appropriate agents.

    The orchestrator:
    1. Classifies user intent
    2. Routes to the appropriate agent
    3. Handles inter-agent communication
    4. Aggregates and returns responses
    """

    TOKEN_TTL_SECONDS = 300

    def __init__(self):
        self.llm_client = OpenRouterClient()
        self.authenticator = AgentAuthenticator()

        # Initialize agents
        self.tech_support = TechSupportAgent(self.llm_client)
        self.finance = FinanceAgent(self.llm_client)
        self.file_processor = FileProcessorAgent()

        # Agent registry with privilege levels
        self.agents = {
            "tech_support": {
                "agent": self.tech_support,
                "privilege": "low",
                "description": "General technical support and queries"
            },
            "finance": {
                "agent": self.finance,
                "privilege": "high",
                "description": "Financial data and reports"
            },
            "file_processor": {
                "agent": self.file_processor,
                "privilege": "medium",
                "description": "File processing and analysis"
            }
        }

        self._agent_secret = secrets.token_hex(32)

    def _generate_agent_token(self, caller_id: str, target_id: str) -> str:
        """Create a short-lived HMAC token scoped to a specific agent-to-agent call."""
        timestamp = str(int(time.time()))
        payload = f"{caller_id}:{target_id}:{timestamp}"
        signature = hmac.new(
            self._agent_secret.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        return f"{payload}:{signature}"

    def _validate_agent_token(self, token: str, expected_caller: str, expected_target: str) -> bool:
        """Validate an inter-agent HMAC token, checking caller, target and expiry."""
        try:
            parts = token.rsplit(":", 1)
            if len(parts) != 2:
                return False
            payload, signature = parts
            expected_sig = hmac.new(
                self._agent_secret.encode(), payload.encode(), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, expected_sig):
                return False
            caller_id, target_id, ts = payload.split(":")
            if caller_id != expected_caller or target_id != expected_target:
                return False
            if abs(time.time() - int(ts)) > self.TOKEN_TTL_SECONDS:
                return False
            return True
        except Exception:
            return False

    async def process(self, context: dict[str, Any]) -> dict[str, Any]:
        """
        Process incoming request and route to appropriate agent(s).

        Args:
            context: Request context including message, files, and metadata

        Returns:
            Response dictionary with agent output
        """
        user_message = context.get("user_message", "")
        file_contents = context.get("file_contents", [])

        logger.info(
            "Orchestrator processing request",
            extra={
                "message_length": len(user_message),
                "file_count": len(file_contents),
            }
        )

        # Determine which agent should handle the request
        intent = await self._classify_intent(user_message, file_contents)

        # Route to appropriate agent
        if intent == "finance":
            return await self._route_to_finance(context)
        elif intent == "file_analysis":
            return await self._route_to_file_processor(context)
        else:
            return await self._route_to_tech_support(context)

    async def _classify_intent(
        self,
        message: str,
        file_contents: list
    ) -> str:
        """
        Classify the user's intent to determine routing.

        Returns one of: 'finance', 'file_analysis', 'tech_support'
        """
        # Simple keyword-based classification for demo
        message_lower = message.lower()

        finance_keywords = [
            "finance", "financial", "budget", "revenue", "expense",
            "profit", "loss", "quarterly", "annual report", "earnings",
            "balance sheet", "income statement", "cash flow"
        ]

        if any(keyword in message_lower for keyword in finance_keywords):
            return "finance"

        if file_contents:
            return "file_analysis"

        return "tech_support"

    async def _route_to_tech_support(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Route request to tech support agent."""
        caller = AgentIdentity(
            agent_id="orchestrator",
            agent_name="Orchestrator",
            privilege_level="system",
            is_internal=True
        )

        token = self._generate_agent_token("orchestrator", "tech_support")
        if not self._validate_agent_token(token, "orchestrator", "tech_support"):
            logger.error("Inter-agent auth failed for orchestrator -> tech_support")
            return {"response": "Internal authentication error.", "agent": "orchestrator"}

        headers = {"X-Agent-Token": token}

        response = await self.tech_support.handle(
            context=context,
            caller=caller,
            headers=headers
        )

        return response

    async def _route_to_finance(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Route request to finance agent with authenticated inter-agent call."""
        caller = AgentIdentity(
            agent_id="orchestrator",
            agent_name="Orchestrator",
            privilege_level="system",
            is_internal=True
        )

        token = self._generate_agent_token("orchestrator", "finance")
        if not self._validate_agent_token(token, "orchestrator", "finance"):
            logger.error("Inter-agent auth failed for orchestrator -> finance")
            return {"response": "Internal authentication error.", "agent": "orchestrator"}

        headers = {"X-Agent-Token": token}

        logger.info(
            "Routing to finance agent",
            extra={
                "caller": caller.agent_id,
                "privilege": caller.privilege_level,
            }
        )

        response = await self.finance.handle(
            context=context,
            caller=caller,
            headers=headers
        )

        return response

    async def _route_to_file_processor(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Route request to file processor agent."""
        file_contents = context.get("file_contents", [])

        if not file_contents:
            return {
                "response": "No files were provided to analyze.",
                "agent": "file_processor"
            }

        # Process files, redacting PII before sending to the LLM
        analyses = []
        for file_data in file_contents:
            extracted = _redact_pii(file_data.get("extracted_content", ""))
            analyses.append(f"File: {file_data.get('filename')}\n{extracted}")

        combined_content = "\n\n".join(analyses)

        user_question = context.get("user_message", "")

        analysis = await self.llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful document analyst. Answer the user's questions based on the provided document content. Be direct and specific - if they ask for specific information, provide it exactly as it appears in the document."
                },
                {
                    "role": "user",
                    "content": f"""Document Content:
{combined_content}

User Question: {user_question}

Please answer the user's question based on the document content above."""
                }
            ]
        )

        return {
            "response": analysis,
            "agent": "file_processor",
            "files_processed": len(file_contents)
        }

    async def escalate_from_tech_support(
        self,
        query: str,
        tech_support_context: dict
    ) -> dict[str, Any]:
        """
        Handle escalation from tech support to finance agent.

        Validates that the escalation carries a valid inter-agent token
        before forwarding to the finance agent.
        """
        incoming_token = tech_support_context.get("agent_token", "")
        if not self._validate_agent_token(incoming_token, "tech_support", "finance"):
            logger.warning("Unauthorised escalation attempt from tech_support to finance")
            return {
                "response": "Escalation denied: inter-agent authentication failed.",
                "agent": "orchestrator",
            }

        escalation_context = {
            "user_message": query,
            "escalated_from": "tech_support",
            "original_context": tech_support_context,
            "escalation_reason": "Financial data requested"
        }

        logger.info("Escalating from tech support to finance")

        return await self._route_to_finance(escalation_context)
