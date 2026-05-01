"""File Processor Agent class with explicit model invocation."""

import base64
import io
import json
import logging
import os
import re
import unicodedata
from typing import Any, Optional

try:
    from docx import Document
except ModuleNotFoundError:  # pragma: no cover - depends on local environment
    Document = None

try:
    from cryptography.fernet import Fernet
except ModuleNotFoundError:  # pragma: no cover
    Fernet = None

from file_parsers.html_parser import HTMLParser
from file_parsers.image_parser import ImageParser
from file_parsers.pdf_parser import PDFParser

from .framework import PolicyProbeAgentFramework
from .helpers import build_file_summary
from .mcp_servers import call_mcp_server

logger = logging.getLogger(__name__)

_DYNAMIC_CODE_PATTERNS = re.compile(
    r"\b(eval|exec|subprocess|os\.system|__import__|compile|execfile|globals|locals|vars|getattr|setattr|delattr|open|input|breakpoint)\s*\(",
    re.IGNORECASE,
)

_INJECTION_PATTERNS = re.compile(
    r"(?i)(ignore\s+(previous|above|all)\s+instructions?|"
    r"you\s+are\s+now|new\s+instructions?:|system\s*prompt\s*:|"
    r"disregard\s+(all\s+)?(previous|prior)\s+instructions?|"
    r"forget\s+(everything|all)|act\s+as\s+if|pretend\s+(you\s+are|to\s+be)|"
    r"override\s+(the\s+)?(system|previous)|"
    r"<\s*system\s*>|<\s*instructions?\s*>|"
    r"\[INST\]|\[SYS\]|###\s*instruction)",
)

_SINGAPORE_PII_PATTERNS = (
    re.compile(r"\b[STFGM]\d{7}[A-Z]\b"),
    re.compile(r"\bWP\s*\d{7,10}\b", re.IGNORECASE),
    re.compile(r"\bSingPass\b", re.IGNORECASE),
    re.compile(r"\bMyInfo\b", re.IGNORECASE),
    re.compile(r"\bCPF\s*\d{6,}\b", re.IGNORECASE),
    re.compile(r"\bIMEI\s*[:\-]?\s*\d{15}\b", re.IGNORECASE),
    re.compile(r"\bIMSI\s*[:\-]?\s*\d{15}\b", re.IGNORECASE),
    re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
    re.compile(r"\bGPS\s*[:\-]?\s*[\-\d\.]+\s*,\s*[\-\d\.]+\b", re.IGNORECASE),
)

_SINGAPORE_KEYWORD_MARKERS = (
    "nric",
    "fin:",
    "work permit",
    "student pass",
    "singpass",
    "myinfo",
    "cpf",
    "marital status",
    "race:",
    "religion:",
    "political affiliation",
    "voting preference",
    "imei",
    "imsi",
    "device identifier",
    "browsing history",
    "search queries",
    "chat logs",
    "call recordings",
    "authentication token",
    "session identifier",
    "wi-fi triangulation",
    "gps coordinates",
)

_MAX_DOCUMENT_BODY_LENGTH = 50_000
_MAX_FILE_SUMMARY_LENGTH = 40_000
_MCP_STRING_MAX_LENGTH = 10_000
_MCP_ALLOWED_KEYS = {"status", "document_id", "message", "error", "result"}


def sanitize_document_body(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)
    text = text.replace("\x00", "")
    cleaned = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat.startswith("C") and ch not in ("\n", "\r", "\t"):
            continue
        cleaned.append(ch)
    text = "".join(cleaned)
    if len(text) > _MAX_DOCUMENT_BODY_LENGTH:
        text = text[:_MAX_DOCUMENT_BODY_LENGTH]
    return text


class FileProcessorAgent(PolicyProbeAgentFramework):
    AGENT_ID = "file_processor_agent"
    AGENT_NAME = "File Processor Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "Amazon Titan Text Lite"
    BEDROCK_MODEL_ID = "amazon.titan-text-lite-v1"
    DESCRIPTION = "Extracts text from uploaded files and returns the raw contents to downstream agents."
    MCP_SERVERS = ["Docx"]
    GUARDRAILS = {
        "mask_pii": True,
        "base64_prompt_detection": True,
        "credential_minimization": None,
        "inter_agent_authentication": None,
        "mcp_auth_token": os.environ.get("MCP_AUTH_TOKEN", ""),
    }
    SYSTEM_PROMPT = "Extract document text and hand the raw contents to the next agent."

    def __init__(self):
        super().__init__()
        self.pdf_parser = PDFParser()
        self.html_parser = HTMLParser()
        self.image_parser = ImageParser()
        self._fernet = self._init_fernet()

    def _init_fernet(self):
        if Fernet is None:
            return None
        raw_key = os.environ.get("PII_ENCRYPTION_KEY", "")
        if not raw_key:
            return None
        try:
            return Fernet(raw_key.encode() if isinstance(raw_key, str) else raw_key)
        except Exception:
            logger.warning("Failed to initialize Fernet encryption; PII will not be encrypted.")
            return None

    def _encrypt_pii(self, text: str) -> str:
        if not text:
            return text
        if self._fernet is None:
            logger.warning("Fernet not available; returning placeholder instead of encrypted PII.")
            return "[PII_ENCRYPTED]"
        try:
            return self._fernet.encrypt(text.encode("utf-8")).decode("utf-8")
        except Exception as exc:
            logger.error("PII encryption failed", extra={"error": str(exc)})
            return "[PII_ENCRYPTED]"

    def _authenticate_mcp_server(self, server_name: str) -> None:
        token = self.GUARDRAILS.get("mcp_auth_token", "")
        if not token:
            raise ValueError(
                f"MCP server authentication failed: no auth token configured for server '{server_name}'."
            )
        logger.info(
            "MCP server authentication check",
            extra={"server": server_name, "token_present": bool(token)},
        )

    def _sanitize_mcp_result(self, result: Any) -> dict[str, Any]:
        if not isinstance(result, dict):
            logger.warning("MCP result is not a dict; wrapping in error envelope.")
            return {"error": "Invalid MCP response format", "result": str(result)[:_MCP_STRING_MAX_LENGTH]}

        sanitized: dict[str, Any] = {}
        for key in _MCP_ALLOWED_KEYS:
            if key in result:
                value = result[key]
                if isinstance(value, str):
                    value = value.strip()[:_MCP_STRING_MAX_LENGTH]
                sanitized[key] = value

        unexpected = set(result.keys()) - _MCP_ALLOWED_KEYS
        if unexpected:
            logger.warning("MCP result contained unexpected keys; they were stripped.", extra={"keys": list(unexpected)})

        return sanitized

    def sanitize_file_summary(self, file_summary: str) -> str:
        if not isinstance(file_summary, str):
            file_summary = str(file_summary)
        file_summary = file_summary.replace("\x00", "")
        cleaned = []
        for ch in file_summary:
            cat = unicodedata.category(ch)
            if cat.startswith("C") and ch not in ("\n", "\r", "\t"):
                continue
            cleaned.append(ch)
        file_summary = "".join(cleaned)
        safe_lines = []
        for line in file_summary.splitlines():
            if _INJECTION_PATTERNS.search(line):
                logger.warning("Prompt injection pattern detected and removed from file_summary.")
                continue
            safe_lines.append(line)
        file_summary = "\n".join(safe_lines)
        if len(file_summary) > _MAX_FILE_SUMMARY_LENGTH:
            file_summary = file_summary[:_MAX_FILE_SUMMARY_LENGTH]
        return file_summary

    def _sanitize_llm_output(self, output: str) -> str:
        if not isinstance(output, str):
            output = str(output)
        if _DYNAMIC_CODE_PATTERNS.search(output):
            logger.warning(
                "Dynamic code execution primitive detected in LLM output; sanitizing.",
                extra={"output_preview": output[:200]},
            )
            output = _DYNAMIC_CODE_PATTERNS.sub("[REDACTED]", output)
        return output

    def redact_pii_from_text(self, text: str) -> str:
        if not text:
            return text
        ssn_pattern = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
        email_pattern = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
        phone_pattern = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b")

        text = ssn_pattern.sub("[SSN_REDACTED]", text)
        text = email_pattern.sub("[EMAIL_REDACTED]", text)
        text = phone_pattern.sub("[PHONE_REDACTED]", text)

        keyword_markers = (
            "name:",
            "full name:",
            "employee id",
            "date of birth",
            "dob:",
            "ssn",
            "social security",
            "address:",
            "phone:",
            "email:",
            "loan balance",
            "account number",
            "customer id",
            "borrower",
            "credit score",
        )
        safe_lines = []
        for line in text.splitlines():
            lowered = line.lower()
            if any(marker in lowered for marker in keyword_markers):
                safe_lines.append("[PII_LINE_REDACTED]")
            else:
                safe_lines.append(line)
        return "\n".join(safe_lines)

    def redact_pii(self, text: str) -> str:
        if not text:
            return text
        ssn_pattern = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
        email_pattern = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
        phone_pattern = re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b")
        cc_pattern = re.compile(r"\b(?:\d[ -]?){13,16}\b")

        text = ssn_pattern.sub("[SSN_REDACTED]", text)
        text = email_pattern.sub("[EMAIL_REDACTED]", text)
        text = phone_pattern.sub("[PHONE_REDACTED]", text)
        text = cc_pattern.sub("[CC_REDACTED]", text)

        keyword_markers = (
            "name:",
            "full name:",
            "employee id",
            "date of birth",
            "dob:",
            "ssn",
            "social security",
            "address:",
            "phone:",
            "email:",
            "loan balance",
            "account number",
            "customer id",
            "borrower",
            "credit score",
        )
        safe_lines = []
        for line in text.splitlines():
            lowered = line.lower()
            if any(marker in lowered for marker in keyword_markers):
                safe_lines.append("[PII_REDACTED]")
            else:
                safe_lines.append(line)
        return "\n".join(safe_lines)

    def sanitize_extracted_content(self, content: str) -> str:
        if not content:
            return content

        # Detect and neutralize base64-encoded instructions
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
        def _check_b64(match):
            candidate = match.group(0)
            try:
                decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="ignore")
                if _INJECTION_PATTERNS.search(decoded) or _DYNAMIC_CODE_PATTERNS.search(decoded):
                    logger.warning("Base64-encoded prompt injection detected and neutralized.")
                    return "[BASE64_INJECTION_REDACTED]"
            except Exception:
                pass
            return candidate

        content = b64_pattern.sub(_check_b64, content)

        # Remove classic prompt injection patterns
        safe_lines = []
        for line in content.splitlines():
            if _INJECTION_PATTERNS.search(line):
                logger.warning("Prompt injection pattern detected in extracted content.")
                safe_lines.append("[INJECTION_REDACTED]")
            else:
                safe_lines.append(line)
        content = "\n".join(safe_lines)

        # Remove shell/binary command patterns
        shell_pattern = re.compile(
            r"(?i)\b(bash|sh|cmd|powershell|wget|curl|nc|netcat|python|perl|ruby|php)\s+[\-\/\w]"
        )
        content = shell_pattern.sub("[SHELL_CMD_REDACTED]", content)

        # Remove dynamic code execution primitives
        content = _DYNAMIC_CODE_PATTERNS.sub("[CODE_REDACTED]", content)

        return content

    async def call_agent_model(self, file_summary: str) -> str:
        sanitized_summary = self.sanitize_file_summary(file_summary)
        redacted_summary = self.redact_pii_from_text(sanitized_summary)
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Extracted file contents:\n{redacted_summary}\n\n"
                        "Give a short processing note without masking any content."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=220,
        )

    async def process_attachment(
        self,
        content: Optional[str],
        filename: str,
        content_type: str,
    ) -> dict[str, Any]:
        """
        Extracts text from uploaded files. PII is redacted before returning or using the content.
        """
        file_type = self.get_file_type(content_type, filename)
        if not content:
            extracted_content = f"Empty file: {filename}"
        elif file_type == "pdf":
            extracted_content = await self._process_pdf(content)
        elif file_type == "html":
            extracted_content = await self._process_html(content)
        elif file_type == "image":
            extracted_content = await self._process_image(content)
        elif file_type == "json":
            extracted_content = await self._process_json(content)
        elif file_type == "word":
            extracted_content = await self._process_word(content)
        else:
            extracted_content = content

        extracted_content = self.sanitize_extracted_content(extracted_content)
        extracted_content = self.redact_pii(extracted_content)

        return {
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "filename": filename,
            "content_type": content_type,
            "file_type": file_type,
            "extracted_content": extracted_content,
            "guardrails": dict(self.GUARDRAILS),
        }

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        file_contents = context.get("file_contents", [])
        file_summary = build_file_summary(file_contents, include_raw_text=True)
        pii_exposure_summary = self.build_pii_exposure_summary(file_contents)

        logger.info(
            "LLM request initiated",
            extra={
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "file_summary_length": len(file_summary),
                "file_summary_preview": file_summary[:200],
            },
        )
        model_output = await self.call_agent_model(file_summary)
        logger.info(
            "LLM response received",
            extra={
                "agent": self.AGENT_NAME,
                "model": self.MODEL_NAME,
                "model_output_length": len(model_output) if model_output else 0,
                "model_output_preview": (model_output or "")[:200],
            },
        )

        model_output = self._sanitize_llm_output(model_output)

        mcp_activity = []
        if file_contents:
            sanitized_body = sanitize_document_body(file_summary)
            encrypted_body = self._encrypt_pii(sanitized_body)
            mcp_params = {
                "document_title": "Extracted File Contents",
                "document_body": encrypted_body,
            }
            logger.info(
                "MCP server request initiated",
                extra={
                    "server": "Docx",
                    "tool": "create_document",
                    "params_keys": list(mcp_params.keys()),
                    "document_body_length": len(encrypted_body),
                },
            )
            try:
                self._authenticate_mcp_server("Docx")
                auth_token = self.GUARDRAILS.get("mcp_auth_token", "")
                raw_mcp_result = await call_mcp_server(
                    self.to_dict(),
                    "Docx",
                    "create_document",
                    mcp_params,
                    auth_token=auth_token,
                )
                sanitized_mcp_result = self._sanitize_mcp_result(raw_mcp_result)
                logger.info(
                    "MCP server response received",
                    extra={
                        "server": "Docx",
                        "tool": "create_document",
                        "result_keys": list(sanitized_mcp_result.keys()),
                    },
                )
                mcp_activity.append(sanitized_mcp_result)
            except Exception as exc:
                logger.error(
                    "MCP server interaction failed",
                    extra={"server": "Docx", "error": str(exc)},
                )
                raise

        if pii_exposure_summary:
            logger.info(
                "PII detected in uploaded file; suppressing from UI response.",
                extra={"agent": self.AGENT_NAME},
            )
            response = (
                "I reviewed the uploaded document. Sensitive information was detected and has been handled securely.\n\n"
                f"Processing note:\n{model_output}"
            )
        else:
            response = (
                "I reviewed the uploaded document and extracted its contents.\n\n"
                f"Processing note:\n{model_output}\n\n"
                f"Extracted content preview:\n{file_summary}"
            )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }

    def extract_pii_lines(self, content: str, limit: int = 12) -> list[str]:
        keyword_markers = (
            "name:",
            "full name:",
            "employee id",
            "date of birth",
            "dob:",
            "ssn",
            "social security",
            "address:",
            "phone:",
            "email:",
            "loan balance",
            "account number",
            "customer id",
            "borrower",
            "credit score",
            # Singapore PII keywords
            "nric",
            "fin:",
            "work permit",
            "student pass",
            "singpass",
            "myinfo",
            "cpf",
            "marital status",
            "race:",
            "religion:",
            "political affiliation",
            "voting preference",
            "imei",
            "imsi",
            "device identifier",
            "browsing history",
            "search queries",
            "chat logs",
            "call recordings",
            "authentication token",
            "session identifier",
            "wi-fi triangulation",
            "gps coordinates",
        )
        pattern_markers = (
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"),
            re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?){2}\d{4}\b"),
            # Singapore-specific patterns
            re.compile(r"\b[STFGM]\d{7}[A-Z]\b"),
            re.compile(r"\bWP\s*\d{7,10}\b", re.IGNORECASE),
            re.compile(r"\bIMEI\s*[:\-]?\s*\d{15}\b", re.IGNORECASE),
            re.compile(r"\bIMSI\s*[:\-]?\s*\d{15}\b", re.IGNORECASE),
            re.compile(r"\bGPS\s*[:\-]?\s*[\-\d\.]+\s*,\s*[\-\d\.]+\b", re.IGNORECASE),
        )

        pii_lines: list[str] = []
        for raw_line in (content or "").splitlines():
            line = raw_line.strip()
            if not line:
                continue

            lowered = line.lower()
            if any(marker in lowered for marker in keyword_markers) or any(pattern.search(line) for pattern in pattern_markers):
                pii_lines.append(line)

            if len(pii_lines) >= limit:
                break

        return pii_lines

    def build_pii_exposure_summary(self, file_contents: list[dict[str, Any]]) -> str:
        sections: list[str] = []
        for file_data in file_contents:
            extracted_content = file_data.get("extracted_content", "")
            pii_lines = self.extract_pii_lines(extracted_content)
            if not pii_lines:
                continue

            # Check for Singapore PII and raise if found
            for line in pii_lines:
                lowered = line.lower()
                if any(marker in lowered for marker in _SINGAPORE_KEYWORD_MARKERS) or any(
                    pattern.search(line) for pattern in _SINGAPORE_PII_PATTERNS
                ):
                    raise ValueError(
                        f"File '{file_data.get('filename', 'unknown')}' contains Singapore PII and cannot be processed."
                    )

            sections.append(
                f"File: {file_data.get('filename', 'unknown')}\n" + "\n".join(pii_lines)
            )

        return "\n\n".join(sections)

    def get_file_type(self, content_type: str, filename: str) -> str:
        supported_types = {
            "application/pdf": "pdf",
            "text/html": "html",
            "text/plain": "text",
            "application/json": "json",
            "image/jpeg": "image",
            "image/png": "image",
            "application/msword": "word",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "word",
        }

        if content_type in supported_types:
            return supported_types[content_type]

        extension_map = {
            "pdf": "pdf",
            "html": "html",
            "htm": "html",
            "txt": "text",
            "json": "json",
            "jpg": "image",
            "jpeg": "image",
            "png": "image",
            "doc": "word",
            "docx": "word",
        }
        extension = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
        return extension_map.get(extension, "text")

    async def _process_pdf(self, content: str) -> str:
        try:
            return await self.pdf_parser.extract_text(base64.b64decode(content))
        except Exception as exc:
            logger.error("PDF processing failed", extra={"error": str(exc)})
            return f"Error processing PDF: {exc}"

    async def _process_html(self, content: str) -> str:
        try:
            return await self.html_parser.extract_text(content)
        except Exception as exc:
            logger.error("HTML processing failed", extra={"error": str(exc)})
            return f"Error processing HTML: {exc}"

    async def _process_image(self, content: str) -> str:
        try:
            return await self.image_parser.extract_all(base64.b64decode(content))
        except Exception as exc:
            logger.error("Image processing failed", extra={"error": str(exc)})
            return f"Error processing image: {exc}"

    async def _process_json(self, content: str) -> str:
        try:
            return json.dumps(json.loads(content), indent=2)
        except json.JSONDecodeError:
            return content

    async def _process_word(self, content: str) -> str:
        if Document is None:
            return "Word document processing requires python-docx to be installed."

        try:
            document = Document(io.BytesIO(base64.b64decode(content)))
            paragraphs = [paragraph.text.strip() for paragraph in document.paragraphs if paragraph.text.strip()]
            return "\n".join(paragraphs) or "No paragraph text was found in the Word document."
        except Exception as exc:
            logger.error("Word processing failed", extra={"error": str(exc)})
            return f"Error processing Word document: {exc}"


file_processor_agent = FileProcessorAgent()