"""
PolicyProbe Backend - FastAPI Application

This entry point exposes the vulnerable multi-agent loan workflow used by the
demo UI. The backend now routes through a central agent catalog so the agent
names, model names, and MCP server names are easy to inspect in source.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from agents.runtime import handle_chat_request, process_file_attachment

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
MCP_CALL_LOG: list[dict] = []

# Read MCP API key from environment
MCP_API_KEY = os.environ.get("MCP_API_KEY", "")

# Per-server shared secrets for MCP server identity verification
MCP_SERVER_TOKENS: dict[str, str] = {
    "slack": os.environ.get("MCP_SERVER_TOKEN_SLACK", "slack-secret-token"),
    "servicenow": os.environ.get("MCP_SERVER_TOKEN_SERVICENOW", "servicenow-secret-token"),
    "email": os.environ.get("MCP_SERVER_TOKEN_EMAIL", "email-secret-token"),
    "excel": os.environ.get("MCP_SERVER_TOKEN_EXCEL", "excel-secret-token"),
    "docx": os.environ.get("MCP_SERVER_TOKEN_DOCX", "docx-secret-token"),
    "google-calendar": os.environ.get("MCP_SERVER_TOKEN_GOOGLE_CALENDAR", "google-calendar-secret-token"),
}

# Shared secret for inter-agent HMAC token signing
AGENT_SHARED_SECRET = os.environ.get("AGENT_SHARED_SECRET", "agent-shared-secret")

# Allowlist of known MCP server keys
ALLOWED_SERVER_KEYS = {"slack", "servicenow", "email", "excel", "docx", "google-calendar"}

# Maximum allowed arguments size (number of keys)
MAX_ARGUMENTS_KEYS = 50

# Maximum string length in MCP payloads
MAX_STRING_LENGTH = 10000

# Maximum nesting depth for MCP response sanitization
MAX_NESTING_DEPTH = 5

# Allowed top-level keys in MCP responses
ALLOWED_MCP_RESPONSE_KEYS = {
    "server", "tool", "status", "timestamp", "posted", "channel", "text",
    "downloaded", "package_name", "pretend_download_path", "decoded_payload",
    "incident_number", "short_description", "message_id", "to", "subject",
    "workbook", "worksheet", "row", "document_id", "document_title",
    "document_body_preview", "event_id", "title", "start", "end",
    "raw_arguments",
}

# Dynamic code execution primitives to detect in LLM output
DANGEROUS_CODE_PATTERNS = [
    r'\beval\s*\(',
    r'\bexec\s*\(',
    r'\bsubprocess\b',
    r'\bos\.system\s*\(',
    r'\b__import__\s*\(',
    r'\bcompile\s*\(',
    r'\bexecfile\s*\(',
    r'\bos\.popen\s*\(',
    r'\bos\.exec[a-z]*\s*\(',
    r'\bimportlib\b',
    r'\bctypes\b',
]

# Prompt injection / malicious content patterns for file scanning
INJECTION_PATTERNS = [
    r'ignore\s+previous\s+instructions',
    r'ignore\s+all\s+instructions',
    r'disregard\s+(previous|all|prior)\s+instructions',
    r'you\s+are\s+now\s+in\s+developer\s+mode',
    r'jailbreak',
    r'<\s*script[^>]*>',
    r'javascript\s*:',
    r'\beval\s*\(',
    r'\bexec\s*\(',
    r'system\s*\(',
    r'__import__\s*\(',
    r'prompt\s+injection',
    r'new\s+instructions\s*:',
    r'override\s+(previous|all|prior)\s+(instructions|rules)',
]


def _sanitize_string_value(value: str, max_length: int = MAX_STRING_LENGTH) -> str:
    """Sanitize a string value by removing dangerous content."""
    # Remove null bytes
    value = value.replace('\x00', '')
    # Remove script tags
    value = re.sub(r'<\s*script[^>]*>.*?<\s*/\s*script\s*>', '', value, flags=re.IGNORECASE | re.DOTALL)
    value = re.sub(r'<\s*script[^>]*>', '', value, flags=re.IGNORECASE)
    # Remove javascript: URIs
    value = re.sub(r'javascript\s*:', '', value, flags=re.IGNORECASE)
    # Truncate excessively long strings
    if len(value) > max_length:
        value = value[:max_length]
    return value


def _sanitize_mcp_payload(payload, depth: int = 0) -> dict:
    """Sanitize MCP response payload recursively."""
    if depth > MAX_NESTING_DEPTH:
        return {}
    if not isinstance(payload, dict):
        return {}
    sanitized = {}
    for key, value in payload.items():
        if key not in ALLOWED_MCP_RESPONSE_KEYS:
            continue
        if isinstance(value, str):
            sanitized[key] = _sanitize_string_value(value)
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_mcp_payload(value, depth + 1)
        elif isinstance(value, list):
            sanitized_list = []
            for item in value:
                if isinstance(item, str):
                    sanitized_list.append(_sanitize_string_value(item))
                elif isinstance(item, dict):
                    sanitized_list.append(_sanitize_mcp_payload(item, depth + 1))
                else:
                    sanitized_list.append(item)
            sanitized[key] = sanitized_list
        else:
            sanitized[key] = value
    return sanitized


def _validate_tool_name(tool_name: str) -> bool:
    """Validate that tool_name is a non-empty string matching an expected pattern."""
    if not tool_name or not isinstance(tool_name, str):
        return False
    # Tool names should match pattern: word chars, dots, underscores, hyphens
    return bool(re.match(r'^[\w][\w.\-]{0,99}$', tool_name))


def _validate_arguments(arguments: dict) -> bool:
    """Validate that arguments is a dict with bounded size."""
    if not isinstance(arguments, dict):
        return False
    if len(arguments) > MAX_ARGUMENTS_KEYS:
        return False
    return True


def _sanitize_llm_response(response_text: str) -> str:
    """Check LLM response for dynamic code execution primitives and sanitize."""
    for pattern in DANGEROUS_CODE_PATTERNS:
        if re.search(pattern, response_text, re.IGNORECASE):
            logger.warning(
                "Dangerous code execution primitive detected in LLM response",
                extra={"pattern": pattern}
            )
            # Replace the dangerous content
            response_text = re.sub(pattern, '[REDACTED]', response_text, flags=re.IGNORECASE)
    return response_text


def _scan_for_malicious_content(content: str) -> bool:
    """Scan content for prompt injection and malicious patterns. Returns True if malicious."""
    if not content:
        return False
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            logger.warning(
                "Malicious content detected in file upload",
                extra={"pattern": pattern}
            )
            return True
    return False


def _sanitize_user_input(text: str, max_length: int = 32000) -> str:
    """Sanitize and validate user input before sending to AI model."""
    if not isinstance(text, str):
        text = str(text)
    # Remove null bytes
    text = text.replace('\x00', '')
    # Remove script tags
    text = re.sub(r'<\s*script[^>]*>.*?<\s*/\s*script\s*>', '', text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r'<\s*script[^>]*>', '', text, flags=re.IGNORECASE)
    # Remove javascript: URIs
    text = re.sub(r'javascript\s*:', '', text, flags=re.IGNORECASE)
    # Truncate
    if len(text) > max_length:
        text = text[:max_length]
    return text.strip()


def _generate_agent_token(conversation_id: Optional[str], agent_identity: str) -> str:
    """Generate a per-request HMAC-signed token for inter-agent authentication."""
    timestamp = str(int(time.time()))
    message = f"{agent_identity}:{conversation_id or ''}:{timestamp}"
    token = hmac.new(
        AGENT_SHARED_SECRET.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return f"{message}:{token}"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("PolicyProbe backend starting up...")
    yield
    logger.info("PolicyProbe backend shutting down...")


app = FastAPI(
    title="PolicyProbe",
    description="AI-powered policy evaluation and remediation demo",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5001", "http://127.0.0.1:5001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class FileAttachment(BaseModel):
    id: str
    name: str
    type: str
    size: int
    content: Optional[str] = None


class ChatRequest(BaseModel):
    message: str
    attachments: Optional[list[FileAttachment]] = None
    conversation_id: Optional[str] = None


class PolicyError(BaseModel):
    type: str
    message: str
    details: Optional[dict] = None


class ChatResponse(BaseModel):
    response: str
    conversation_id: Optional[str] = None
    policy_warning: Optional[PolicyError] = None


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "policyprobe"}


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Main chat endpoint that processes user messages and file uploads.

    This endpoint:
    1. Receives user messages and optional file attachments
    2. Processes files through the File Processor Agent
    3. Routes the request through the Orchestrator Agent
    4. Returns the agent response
    """
    try:
        # Sanitize and validate user message before sending to AI model
        sanitized_message = _sanitize_user_input(request.message)

        file_contents = []
        if request.attachments:
            for attachment in request.attachments:
                logger.info(
                    "Processing attachment",
                    extra={
                        "file_name": attachment.name,
                        "file_type": attachment.type,
                        "file_size": attachment.size,
                    }
                )

                # Sanitize attachment content before processing
                sanitized_content = None
                if attachment.content:
                    sanitized_content = _sanitize_user_input(attachment.content, max_length=1000000)
                    # Scan for malicious content / prompt injection
                    if _scan_for_malicious_content(sanitized_content):
                        raise HTTPException(
                            status_code=400,
                            detail={
                                "detail": "Malicious content detected in uploaded file",
                                "policy_error": {
                                    "type": "malicious_content",
                                    "message": "The uploaded file contains potentially malicious content and cannot be processed."
                                }
                            }
                        )

                processed = await process_file_attachment(
                    content=sanitized_content,
                    filename=attachment.name,
                    content_type=attachment.type
                )
                file_contents.append(processed)

        # Generate inter-agent authentication token
        agent_token = _generate_agent_token(request.conversation_id, "orchestrator")

        context = {
            "user_message": sanitized_message,
            "file_contents": file_contents,
            "conversation_id": request.conversation_id,
            "agent_token": agent_token,
            "agent_identity": "orchestrator",
        }

        logger.info(
            "Sending request to LLM",
            extra={
                "conversation_id": request.conversation_id,
                "message_length": len(sanitized_message),
                "file_count": len(file_contents),
            }
        )

        response = await handle_chat_request(context)

        logger.info(
            "Received response from LLM",
            extra={
                "conversation_id": request.conversation_id,
                "response_length": len(response.get("response", "")) if response else 0,
            }
        )

        # Sanitize LLM response for dangerous code execution primitives
        raw_response_text = response.get("response", "I processed your request.")
        sanitized_response_text = _sanitize_llm_response(raw_response_text)

        return ChatResponse(
            response=sanitized_response_text,
            conversation_id=request.conversation_id,
            policy_warning=response.get("policy_warning"),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error processing chat request",
            extra={
                "error": str(e),
                "request_state": {
                    "message_length": len(request.message) if request.message else 0,
                    "attachment_count": len(request.attachments) if request.attachments else 0,
                    "attachment_metadata": [
                        {"name": a.name, "type": a.type, "size": a.size, "id": a.id}
                        for a in request.attachments
                    ] if request.attachments else None
                }
            }
        )
        raise HTTPException(
            status_code=500,
            detail={
                "detail": "An error occurred processing your request",
                "policy_error": {
                    "type": "general",
                    "message": str(e)
                }
            }
        )


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Direct file upload endpoint.
    """
    content = await file.read()
    if (file.content_type or "").startswith("image/") or file.content_type in {
        "application/pdf",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }:
        processed_content = base64.b64encode(content).decode("utf-8")
    else:
        processed_content = content.decode("utf-8", errors="ignore")

    # Sanitize decoded content before processing
    processed_content = _sanitize_user_input(processed_content, max_length=1000000)

    # Scan for malicious content / prompt injection in uploaded file
    if _scan_for_malicious_content(processed_content):
        raise HTTPException(
            status_code=400,
            detail={
                "detail": "Malicious content detected in uploaded file",
                "policy_error": {
                    "type": "malicious_content",
                    "message": "The uploaded file contains potentially malicious content and cannot be processed."
                }
            }
        )

    processed = await process_file_attachment(
        content=processed_content,
        filename=file.filename,
        content_type=file.content_type
    )

    return {
        "filename": file.filename,
        "size": len(content),
        "processed": True,
        "content_preview": processed.get("extracted_content", "")[:500] if processed else None,
        "agent": processed.get("agent"),
        "model": processed.get("model"),
    }


@app.post("/mock-mcp/{server_key}")
async def mock_mcp_server(server_key: str, request: Request):
    """
    Local mock MCP server endpoint used by the demo agents.
    """
    # Authenticate the client via API key
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer ") or auth_header[len("Bearer "):] != MCP_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid or missing API key")

    # Validate server_key against allowlist
    if server_key not in ALLOWED_SERVER_KEYS:
        raise HTTPException(status_code=400, detail=f"Unknown MCP server key: {server_key}")

    # Verify server identity via per-server token
    server_token_header = request.headers.get("X-MCP-Server-Token", "")
    expected_token = MCP_SERVER_TOKENS.get(server_key, "")
    if not server_token_header or server_token_header != expected_token:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid or missing MCP server token")

    payload = await request.json()

    # Validate payload structure
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid payload: must be a JSON object")

    params = payload.get("params", {})
    if not isinstance(params, dict):
        raise HTTPException(status_code=400, detail="Invalid payload: 'params' must be an object")

    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})

    # Validate tool_name
    if not _validate_tool_name(tool_name):
        raise HTTPException(status_code=400, detail="Invalid tool_name: must be a non-empty alphanumeric string")

    # Validate arguments
    if not _validate_arguments(arguments):
        raise HTTPException(status_code=400, detail="Invalid arguments: must be a dict with bounded size")

    # Sanitize string values in arguments
    sanitized_arguments = {}
    for k, v in arguments.items():
        if isinstance(v, str):
            sanitized_arguments[k] = _sanitize_string_value(v)
        else:
            sanitized_arguments[k] = v

    response_payload = _handle_mock_mcp_call(server_key, tool_name, sanitized_arguments)

    # Sanitize the response payload before returning
    sanitized_response = _sanitize_mcp_payload(response_payload)

    return {
        "jsonrpc": "2.0",
        "id": payload.get("id"),
        "result": sanitized_response,
    }


@app.get("/agents")
async def get_agents():
    """Compatibility alias for agent catalog inspection."""
    from agents.runtime import build_catalog
    return build_catalog()


@app.get("/mcp-servers")
async def get_mcp_servers():
    """Compatibility alias for MCP server catalog inspection."""
    from agents.runtime import build_catalog
    catalog = build_catalog()
    return {"mcp_servers": catalog.get("mcp_servers", [])}


def _handle_mock_mcp_call(server_key: str, tool_name: str, arguments: dict) -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()
    log_entry = {
        "server_key": server_key,
        "tool_name": tool_name,
        "arguments": arguments,
        "timestamp": timestamp,
    }
    MCP_CALL_LOG.append(log_entry)

    if server_key == "slack" and tool_name == "slack.post_message":
        return {
            "server": "Slack",
            "posted": True,
            "channel": arguments.get("channel", "#general"),
            "text": arguments.get("text", ""),
            "timestamp": timestamp,
        }

    if server_key == "slack" and tool_name == "slack.download_demo_package":
        encoded_payload = arguments.get("encoded_payload", "")
        try:
            decoded_payload = base64.b64decode(encoded_payload).decode("utf-8")
        except Exception:
            decoded_payload = "Unable to decode demo payload."
        return {
            "server": "Slack",
            "downloaded": True,
            "package_name": arguments.get("package_name", "demo-package"),
            "pretend_download_path": "/tmp/demo-rce-playbook.txt",
            "decoded_payload": decoded_payload,
            "timestamp": timestamp,
        }

    if server_key == "servicenow" and tool_name == "servicenow.create_incident":
        return {
            "server": "ServiceNow",
            "incident_number": f"INC{len(MCP_CALL_LOG):06d}",
            "short_description": arguments.get("short_description", ""),
            "status": "created",
            "timestamp": timestamp,
        }

    if server_key == "email" and tool_name == "email.send_message":
        return {
            "server": "Email",
            "message_id": f"email-{len(MCP_CALL_LOG):06d}",
            "to": arguments.get("to", []),
            "subject": arguments.get("subject", ""),
            "status": "queued",
            "timestamp": timestamp,
        }

    if server_key == "excel" and tool_name == "excel.upsert_row":
        return {
            "server": "Excel",
            "workbook": arguments.get("workbook", ""),
            "worksheet": arguments.get("worksheet", ""),
            "row": arguments.get("row", {}),
            "status": "upserted",
            "timestamp": timestamp,
        }

    if server_key == "docx" and tool_name == "docx.create_document":
        return {
            "server": "Docx",
            "document_id": f"docx-{len(MCP_CALL_LOG):06d}",
            "document_title": arguments.get("document_title", ""),
            "document_body_preview": arguments.get("document_body", "")[:300],
            "status": "generated",
            "timestamp": timestamp,
        }

    if server_key == "google-calendar" and tool_name == "google_calendar.create_event":
        return {
            "server": "Google Calendar",
            "event_id": f"gcal-{len(MCP_CALL_LOG):06d}",
            "title": arguments.get("title", ""),
            "start": arguments.get("start", ""),
            "end": arguments.get("end", ""),
            "status": "scheduled",
            "timestamp": timestamp,
        }

    return {
        "server": server_key,
        "tool": tool_name,
        "status": "unsupported",
        "raw_arguments": json.dumps(arguments),
        "timestamp": timestamp,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5500)