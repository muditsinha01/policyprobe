"""
DeepSeek Demo Agent

Standalone demo agent that is intentionally not wired into the orchestrator.
It exists only so the app has a separate agent implementation available for
manual demos or future experiments.
"""

import logging
import os
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity
from llm.bedrock import BedrockClient

logger = logging.getLogger(__name__)


class DeepSeekAgent:
    """
    Demo-only DeepSeek-style agent.

    This agent is not registered with the orchestrator and is not invoked by
    the standard application flow.
    """

    PRIVILEGE_LEVEL = "low"
    DEFAULT_MODEL = "BEDROCK_MODEL_ID"

    def __init__(self, llm_client: Optional[BedrockClient] = None):
        self.llm_client = llm_client or BedrockClient()
        self.agent_id = "deepseek_demo"
        self.agent_name = "DeepSeek Demo Agent"
        self.model_id = (
            os.getenv("DEEPSEEK_MODEL_ID")
            or os.getenv(self.DEFAULT_MODEL)
            or self.llm_client.model_id
        )

    async def handle(
        self,
        context: dict[str, Any],
        caller: Optional[AgentIdentity] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        """
        Process a demo request through the shared Bedrock-backed LLM client.

        Args:
            context: Request context containing the user message
            caller: Optional caller identity for parity with other agents
            headers: Optional request headers for parity with other agents

        Returns:
            Response payload for manual demos
        """
        del headers  # This demo agent does not use request headers.

        user_message = context.get("user_message", "")
        prompt = self._build_system_prompt(caller)

        logger.info(
            "DeepSeek demo agent processing request",
            extra={
                "caller": caller.agent_id if caller else "direct",
                "model": self.model_id,
                "message_length": len(user_message),
            },
        )

        response = await self.llm_client.chat(
            model=self.model_id,
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": user_message},
            ],
        )

        return {
            "response": response,
            "agent": self.agent_id,
            "agent_name": self.agent_name,
            "privilege_level": self.PRIVILEGE_LEVEL,
            "demo_only": True,
            "model": self.model_id,
        }

    def _build_system_prompt(self, caller: Optional[AgentIdentity]) -> str:
        caller_name = caller.agent_name if caller else "a direct demo caller"
        return f"""You are a demo DeepSeek-style assistant inside PolicyProbe.
You are being used for a standalone demo and are not part of the normal
orchestrated application flow.

Respond clearly and concisely. Assume the request came from {caller_name}."""
