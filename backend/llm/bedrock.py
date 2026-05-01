"""
Amazon Bedrock LLM Client

Client for communicating with LLMs via Amazon Bedrock.

SECURITY NOTES (for Unifai demo):
- Input sanitization applied before sending to LLM
- Response validation applied
- AWS credential handling could be improved
- No rate limiting
"""

import asyncio
import logging
import os
import re
import unicodedata
from typing import Any, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

logger = logging.getLogger(__name__)

# Maximum allowed input length
MAX_INPUT_LENGTH = 50000

# Prompt injection patterns
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", re.IGNORECASE),
    re.compile(r"forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?!a\s+document)", re.IGNORECASE),
    re.compile(r"new\s+instructions?\s*:", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
    re.compile(r"\[INST\]", re.IGNORECASE),
    re.compile(r"###\s*instruction", re.IGNORECASE),
    re.compile(r"act\s+as\s+(if\s+you\s+are|a\s+different)", re.IGNORECASE),
    re.compile(r"pretend\s+(you\s+are|to\s+be)", re.IGNORECASE),
    re.compile(r"jailbreak", re.IGNORECASE),
    re.compile(r"DAN\s+mode", re.IGNORECASE),
]

# PII patterns
PII_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),  # SSN
    re.compile(r"\b\d{16}\b"),  # Credit card (basic)
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),  # Email
    re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b"),  # Phone number
    re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),  # Credit card patterns
]

# Dangerous code execution primitives in LLM output
DANGEROUS_CODE_PATTERNS = [
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"\bexec\s*\(", re.IGNORECASE),
    re.compile(r"\bcompile\s*\(", re.IGNORECASE),
    re.compile(r"\b__import__\s*\(", re.IGNORECASE),
    re.compile(r"\bimportlib\b", re.IGNORECASE),
    re.compile(r"\bos\.system\s*\(", re.IGNORECASE),
    re.compile(r"\bsubprocess\b.*shell\s*=\s*True", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bsubprocess\.call\s*\(", re.IGNORECASE),
    re.compile(r"\bsubprocess\.run\s*\(", re.IGNORECASE),
    re.compile(r"\bsubprocess\.Popen\s*\(", re.IGNORECASE),
    re.compile(r"\bos\.popen\s*\(", re.IGNORECASE),
    re.compile(r"\bos\.execv\s*\(", re.IGNORECASE),
    re.compile(r"\bos\.execve\s*\(", re.IGNORECASE),
    re.compile(r"\bgetattr\s*\(.*__", re.IGNORECASE),
    re.compile(r"__builtins__", re.IGNORECASE),
    re.compile(r"__globals__", re.IGNORECASE),
]

# Hidden/malicious content patterns for file uploads
HIDDEN_CONTENT_PATTERNS = [
    re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"),  # Base64
    re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]"),  # Non-printable/invisible chars
    re.compile(r"(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|prompts?)", re.IGNORECASE),
    re.compile(r"(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)", re.IGNORECASE),
    re.compile(r"(?:rm\s+-rf|chmod\s+777|wget\s+http|curl\s+http|nc\s+-|/bin/sh|/bin/bash)", re.IGNORECASE),
    re.compile(r"(?:0x[0-9a-fA-F]{2}\s*){4,}"),  # Hex sequences (potential shellcode)
    re.compile(r"l33t|1337|h4x|h4ck", re.IGNORECASE),  # Leetspeak indicators
    re.compile(r"<script[^>]*>", re.IGNORECASE),  # Script tags
    re.compile(r"javascript\s*:", re.IGNORECASE),  # JavaScript protocol
]


class BedrockClient:
    """
    Client for Amazon Bedrock Runtime.

    Input sanitization and output validation are applied.
    - PII scanning before send
    - Prompt injection detection
    - Response validation for dangerous code primitives
    """

    def __init__(
        self,
        model_id: Optional[str] = None,
        region: Optional[str] = None,
    ):
        """
        Initialize the Amazon Bedrock client.

        Args:
            model_id: Amazon Bedrock model ID (defaults to env var BEDROCK_MODEL_ID, required)
            region: AWS region for Bedrock Runtime (defaults to env vars)
        """
        env_model = os.getenv("BEDROCK_MODEL_ID")
        resolved_model = model_id or env_model
        if not resolved_model:
            raise ValueError(
                "BEDROCK_MODEL_ID environment variable is required. "
                "No default model is set. Please configure an approved model ID."
            )
        self.model_id = resolved_model
        self.region = region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        self.session = (
            boto3.session.Session(region_name=self.region)
            if self.region
            else boto3.session.Session()
        )

        if not (self.region or self.session.region_name):
            logger.warning(
                "Amazon Bedrock region not configured. "
                "Set AWS_REGION or AWS_DEFAULT_REGION."
            )

    def _get_client(self):
        client_region = self.region or self.session.region_name
        if not client_region:
            raise ValueError("AWS region is required for Amazon Bedrock Runtime.")

        return self.session.client("bedrock-runtime", region_name=client_region)

    def _sanitize_input(self, text: Any, field_name: str = "input") -> str:
        """
        Validate and sanitize a user-supplied string before sending to the LLM.

        (1) Rejects None/non-string inputs
        (2) Enforces a maximum length limit
        (3) Strips null bytes and non-printable control characters
        (4) Detects and blocks common prompt injection patterns
        (5) Scans for PII patterns and logs warnings

        Args:
            text: The input to sanitize
            field_name: Name of the field (for error messages)

        Returns:
            Sanitized string

        Raises:
            ValueError: If input is invalid or contains injection patterns
        """
        if text is None:
            raise ValueError(f"{field_name} must not be None.")
        if not isinstance(text, str):
            raise ValueError(f"{field_name} must be a string, got {type(text).__name__}.")

        # Strip null bytes and non-printable control characters (keep \t, \n, \r)
        sanitized = re.sub(r"[\x00\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

        # Normalize unicode to remove invisible/zero-width characters
        sanitized = "".join(
            ch for ch in sanitized
            if unicodedata.category(ch) not in ("Cf",)  # Remove format characters
        )

        # Enforce maximum length
        if len(sanitized) > MAX_INPUT_LENGTH:
            raise ValueError(
                f"{field_name} exceeds maximum allowed length of {MAX_INPUT_LENGTH} characters."
            )

        # Detect prompt injection patterns
        for pattern in PROMPT_INJECTION_PATTERNS:
            if pattern.search(sanitized):
                raise ValueError(
                    f"{field_name} contains a potential prompt injection pattern and has been rejected."
                )

        # Scan for PII patterns and log warnings
        for pattern in PII_PATTERNS:
            if pattern.search(sanitized):
                logger.warning(
                    f"{field_name} may contain PII. Review before sending to LLM.",
                    extra={"field": field_name},
                )
                break

        return sanitized

    def _sanitize_llm_output(self, content: str) -> str:
        """
        Scan LLM response for dangerous dynamic code execution primitives.

        Raises ValueError if dangerous patterns are detected, otherwise returns
        the content unchanged.

        Args:
            content: The LLM response text to validate

        Returns:
            Validated content string

        Raises:
            ValueError: If dangerous code execution primitives are detected
        """
        for pattern in DANGEROUS_CODE_PATTERNS:
            if pattern.search(content):
                raise ValueError(
                    "LLM response contains potentially dangerous code execution primitives "
                    "and has been blocked for safety."
                )
        return content

    def _sanitize_document_content(self, content: str) -> str:
        """
        Scan document content for hidden prompts, invisible text, base64-encoded prompts,
        leetspeak, suspicious instructions, and binary/shell commands.

        Args:
            content: Document content to scan

        Returns:
            Sanitized content string

        Raises:
            ValueError: If malicious content is detected
        """
        if not isinstance(content, str):
            raise ValueError("Document content must be a string.")

        # Check for hidden/malicious content patterns
        for pattern in HIDDEN_CONTENT_PATTERNS:
            if pattern.search(content):
                raise ValueError(
                    "Document content contains potentially malicious content "
                    "(hidden prompts, encoded instructions, or shell commands) "
                    "and has been rejected."
                )

        # Also apply standard input sanitization
        return self._sanitize_input(content, field_name="document content")

    async def chat(
        self,
        messages: list[dict[str, Any]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2000,
    ) -> str:
        """
        Send a conversation request to Amazon Bedrock.

        Input messages are sanitized before sending.
        Response is validated for dangerous code primitives.

        Args:
            messages: List of message dicts with role and content
            model: Override model ID for this request
            temperature: Sampling temperature
            max_tokens: Maximum response tokens

        Returns:
            LLM response text
        """
        active_model = model or self.model_id
        active_region = self.region or self.session.region_name
        if not active_region:
            return "LLM service not configured. Please set AWS_REGION or AWS_DEFAULT_REGION."

        # Sanitize all message content before processing
        sanitized_messages = []
        for message in messages:
            role = message.get("role", "user")
            content = message.get("content", "")
            try:
                sanitized_content = self._sanitize_input(str(content), field_name=f"message[{role}].content")
            except ValueError as e:
                logger.warning(f"Input sanitization rejected message content: {e}")
                return f"Input validation error: {e}"
            sanitized_messages.append({"role": role, "content": sanitized_content})

        bedrock_messages, system_prompts = self._format_messages(sanitized_messages)

        logger.info(
            "Sending request to Amazon Bedrock",
            extra={
                "model": active_model,
                "region": active_region,
                "message_count": len(sanitized_messages),
                "total_content_length": sum(
                    len(str(message.get("content", ""))) for message in sanitized_messages
                ),
            },
        )

        try:
            response = await asyncio.to_thread(
                self._converse,
                active_model,
                bedrock_messages,
                system_prompts,
                temperature,
                max_tokens,
            )

            content = self._extract_text(response)

            # Validate LLM output for dangerous code execution primitives
            try:
                content = self._sanitize_llm_output(content)
            except ValueError as e:
                logger.error(f"LLM output validation failed: {e}")
                return f"Response blocked by security policy: {e}"

            logger.info(
                "Received response from Amazon Bedrock",
                extra={
                    "response_length": len(content),
                },
            )

            return content

        except NoCredentialsError:
            logger.error("Amazon Bedrock credentials not configured")
            return (
                "LLM service not configured. Please provide AWS credentials "
                "supported by boto3."
            )
        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code", "Unknown")
            logger.error(f"Amazon Bedrock API error: {error_code}")
            return f"Error communicating with LLM: {error_code}"
        except (BotoCoreError, ValueError) as error:
            logger.error(f"Amazon Bedrock client error: {error}")
            return f"Error: {str(error)}"
        except Exception as error:
            logger.error(f"Amazon Bedrock unexpected error: {error}")
            return f"Error: {str(error)}"

    def _converse(
        self,
        model_id: str,
        messages: list[dict[str, Any]],
        system_prompts: list[dict[str, str]],
        temperature: float,
        max_tokens: int,
    ) -> dict[str, Any]:
        client = self._get_client()

        request: dict[str, Any] = {
            "modelId": model_id,
            "messages": messages,
            "inferenceConfig": {
                "maxTokens": max_tokens,
                "temperature": temperature,
            },
        }
        if system_prompts:
            request["system"] = system_prompts

        return client.converse(**request)

    def _format_messages(
        self,
        messages: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
        bedrock_messages: list[dict[str, Any]] = []
        system_prompts: list[dict[str, str]] = []

        for message in messages:
            role = message.get("role", "user")
            content = str(message.get("content", ""))

            if role == "system":
                system_prompts.append({"text": content})
                continue

            bedrock_role = "assistant" if role == "assistant" else "user"
            bedrock_messages.append(
                {
                    "role": bedrock_role,
                    "content": [{"text": content}],
                }
            )

        return bedrock_messages, system_prompts

    def _extract_text(self, response: dict[str, Any]) -> str:
        content_blocks = response.get("output", {}).get("message", {}).get("content", [])
        text_parts = [
            block["text"]
            for block in content_blocks
            if isinstance(block, dict) and block.get("text")
        ]
        return "\n".join(text_parts).strip()

    async def chat_with_context(
        self,
        user_message: str,
        system_prompt: str,
        context: Optional[str] = None,
    ) -> str:
        """
        Convenience method for chat with system prompt and optional context.

        Input is validated and sanitized before processing.
        """
        try:
            sanitized_user_message = self._sanitize_input(user_message, field_name="user_message")
            sanitized_system_prompt = self._sanitize_input(system_prompt, field_name="system_prompt")
        except ValueError as e:
            logger.warning(f"Input sanitization rejected content in chat_with_context: {e}")
            return f"Input validation error: {e}"

        messages = [{"role": "system", "content": sanitized_system_prompt}]

        if context:
            try:
                sanitized_context = self._sanitize_input(context, field_name="context")
            except ValueError as e:
                logger.warning(f"Input sanitization rejected context in chat_with_context: {e}")
                return f"Input validation error: {e}"
            messages.append(
                {
                    "role": "user",
                    "content": f"Context:\n{sanitized_context}\n\nQuery: {sanitized_user_message}",
                }
            )
        else:
            messages.append({"role": "user", "content": sanitized_user_message})

        return await self.chat(messages)

    async def analyze_document(self, content: str) -> str:
        """
        Analyze document content using LLM.

        Document content is scanned for hidden prompts, encoded instructions,
        and malicious patterns before being sent to the LLM.
        """
        try:
            sanitized_content = self._sanitize_document_content(content)
        except ValueError as e:
            logger.warning(f"Document content sanitization failed in analyze_document: {e}")
            return f"Document rejected by security policy: {e}"

        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points.",
            context=sanitized_content,
        )