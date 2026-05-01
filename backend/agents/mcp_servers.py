"""Central MCP server catalog and call helpers for PolicyProbe."""

import asyncio
import logging
import os
import re
import unicodedata
from typing import Any
from uuid import uuid4

import requests

logger = logging.getLogger(__name__)

MCP_BASE_URL = os.getenv("MCP_BASE_URL", "https://127.0.0.1:5500/mock-mcp")
MCP_AUTH_TOKEN = os.getenv("MCP_AUTH_TOKEN", "")
MCP_SERVER_TOKEN = os.getenv("MCP_SERVER_TOKEN", "")

_MAX_ARGS_KEYS = 64
_MAX_KEY_LENGTH = 128
_MAX_VALUE_LENGTH = 4096
_MAX_BODY_SIZE = 1_048_576  # 1 MB
_MAX_BODY_DEPTH = 8
_SAFE_KEY_RE = re.compile(r'^[A-Za-z0-9_]+$')


def _sanitize_arguments(arguments: Any, _depth: int = 0) -> dict[str, Any]:
    if not isinstance(arguments, dict):
        raise ValueError("MCP arguments must be a dict.")
    if len(arguments) > _MAX_ARGS_KEYS:
        raise ValueError(
            f"MCP arguments exceed maximum key count ({_MAX_ARGS_KEYS})."
        )
    sanitized: dict[str, Any] = {}
    for key, value in arguments.items():
        if not isinstance(key, str):
            raise ValueError(f"MCP argument key must be a string, got {type(key)}.")
        if len(key) > _MAX_KEY_LENGTH:
            raise ValueError(
                f"MCP argument key '{key[:32]}...' exceeds maximum length ({_MAX_KEY_LENGTH})."
            )
        if not _SAFE_KEY_RE.match(key):
            raise ValueError(
                f"MCP argument key '{key}' contains unsafe characters."
            )
        if isinstance(value, dict):
            value = _sanitize_arguments(value, _depth=_depth + 1)
        elif isinstance(value, str):
            if len(value) > _MAX_VALUE_LENGTH:
                value = value[:_MAX_VALUE_LENGTH]
        sanitized[key] = value
    return sanitized


def _sanitize_mcp_body(body: Any, _depth: int = 0) -> dict[str, Any]:
    if not isinstance(body, dict):
        if isinstance(body, str):
            body = {"raw": body}
        else:
            body = {"raw": str(body)}

    if _depth > _MAX_BODY_DEPTH:
        return {}

    sanitized: dict[str, Any] = {}
    for key, value in body.items():
        if not isinstance(key, str):
            continue
        # Remove keys that look like script injection
        lower_key = key.lower()
        if any(bad in lower_key for bad in ("<script", "javascript:", "onerror", "onload")):
            continue
        if isinstance(value, str):
            # Strip control characters
            cleaned = "".join(
                ch for ch in value
                if unicodedata.category(ch) not in ("Cc", "Cf") or ch in ("\n", "\r", "\t")
            )
            if len(cleaned) > _MAX_VALUE_LENGTH:
                cleaned = cleaned[:_MAX_VALUE_LENGTH]
            sanitized[key] = cleaned
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_mcp_body(value, _depth=_depth + 1)
        else:
            sanitized[key] = value
    return sanitized


def _get_default_headers() -> dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if MCP_AUTH_TOKEN:
        headers["Authorization"] = f"Bearer {MCP_AUTH_TOKEN}"
    return headers


MCP_SERVERS: dict[str, dict[str, Any]] = {
    "Slack": {
        "name": "Slack",
        "server_key": "slack",
        "version": "1.0.0",
        "description": "Slack workspace messaging for agent alerts and coordination.",
        "transport": "streamable-http",
        "endpoint": f"{MCP_BASE_URL}/slack",
        "tools": {
            "post_message": "slack.post_message",
            "download_demo_package": "slack.download_demo_package",
        },
        "default_headers": _get_default_headers(),
        "timeout_seconds": 8,
    },
    "ServiceNow": {
        "name": "ServiceNow",
        "server_key": "servicenow",
        "version": "1.0.0",
        "description": "ServiceNow incident and case management for support workflows.",
        "transport": "streamable-http",
        "endpoint": f"{MCP_BASE_URL}/servicenow",
        "tools": {
            "create_incident": "servicenow.create_incident",
        },
        "default_headers": _get_default_headers(),
        "timeout_seconds": 8,
    },
    "Email": {
        "name": "Email",
        "server_key": "email",
        "version": "1.0.0",
        "description": "Email delivery for borrower communication and status updates.",
        "transport": "streamable-http",
        "endpoint": f"{MCP_BASE_URL}/email",
        "tools": {
            "send_email": "email.send_message",
        },
        "default_headers": _get_default_headers(),
        "timeout_seconds": 8,
    },
    "Excel": {
        "name": "Excel",
        "server_key": "excel",
        "version": "1.0.0",
        "description": "Excel workbook updates for pipeline tracking and credit worksheets.",
        "transport": "streamable-http",
        "endpoint": f"{MCP_BASE_URL}/excel",
        "tools": {
            "upsert_row": "excel.upsert_row",
        },
        "default_headers": _get_default_headers(),
        "timeout_seconds": 8,
    },
    "Docx": {
        "name": "Docx",
        "server_key": "docx",
        "version": "1.0.0",
        "description": "Docx document generation for loan summaries and borrower packets.",
        "transport": "streamable-http",
        "endpoint": f"{MCP_BASE_URL}/docx",
        "tools": {
            "create_document": "docx.create_document",
        },
        "default_headers": _get_default_headers(),
        "timeout_seconds": 8,
    },
    "Google Calendar": {
        "name": "Google Calendar",
        "server_key": "google_calendar",
        "version": "1.0.0",
        "description": "Google Calendar scheduling for underwriting and borrower meetings.",
        "transport": "streamable-http",
        "endpoint": f"{MCP_BASE_URL}/google-calendar",
        "tools": {
            "create_event": "google_calendar.create_event",
        },
        "default_headers": _get_default_headers(),
        "timeout_seconds": 8,
    },
}


async def call_mcp_server(
    agent: dict[str, Any],
    server_name: str,
    tool_alias: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    # Validate authentication token before making any call
    auth_token = MCP_AUTH_TOKEN
    if not auth_token:
        raise ValueError(
            "MCP_AUTH_TOKEN is not set. Client authentication is required before calling any MCP server."
        )

    # Sanitize and validate arguments
    sanitized_arguments = _sanitize_arguments(arguments)

    server = MCP_SERVERS[server_name]
    tool_name = server["tools"][tool_alias]
    headers = dict(server.get("default_headers", {}))

    # Ensure Authorization header is always present
    if "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {auth_token}"

    for header_name, header_value in agent.get("external_system_credentials", {}).get(server_name, {}).items():
        headers[header_name] = header_value

    payload = {
        "jsonrpc": "2.0",
        "id": str(uuid4()),
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": sanitized_arguments,
        },
    }

    logger.info(
        "MCP outgoing request: server=%s tool=%s arguments=%s",
        server["name"],
        tool_name,
        sanitized_arguments,
    )

    def _post() -> dict[str, Any]:
        try:
            response = requests.post(
                server["endpoint"],
                json=payload,
                headers=headers,
                timeout=server.get("timeout_seconds", 8),
                verify=True,
            )

            # Validate server identity token if configured
            if MCP_SERVER_TOKEN:
                server_token_header = response.headers.get("X-MCP-Server-Token", "")
                if server_token_header != MCP_SERVER_TOKEN:
                    raise ValueError(
                        f"MCP server identity validation failed for '{server['name']}': "
                        "server did not present the expected token."
                    )

            try:
                raw_body = response.json()
            except ValueError:
                raw_body = {"raw": response.text}

            # Enforce maximum body size
            import json as _json
            raw_body_str = _json.dumps(raw_body)
            if len(raw_body_str) > _MAX_BODY_SIZE:
                raw_body = {"error": "Response body exceeds maximum allowed size."}

            body = _sanitize_mcp_body(raw_body)

            logger.info(
                "MCP response: server=%s tool=%s status_code=%s ok=%s body=%s",
                server["name"],
                tool_name,
                response.status_code,
                response.ok,
                body,
            )

            return {
                "server": server["name"],
                "endpoint": server["endpoint"],
                "tool": tool_name,
                "ok": response.ok,
                "status_code": response.status_code,
                "body": body,
            }
        except requests.RequestException as exc:
            logger.error(
                "MCP request error: server=%s tool=%s error=%s",
                server["name"],
                tool_name,
                str(exc),
            )
            return {
                "server": server["name"],
                "endpoint": server["endpoint"],
                "tool": tool_name,
                "ok": False,
                "error": str(exc),
            }

    return await asyncio.to_thread(_post)


def format_mcp_activity(mcp_activity: list[dict[str, Any]]) -> str:
    if not mcp_activity:
        return "No MCP server was called."

    lines = []
    for item in mcp_activity:
        if item.get("ok"):
            lines.append(
                f"- {item['server']} -> {item['tool']} ({item.get('status_code', 'ok')})"
            )
        else:
            lines.append(
                f"- {item['server']} -> {item['tool']} failed ({item.get('error', item.get('status_code', 'unknown error'))})"
            )
    return "\n".join(lines)