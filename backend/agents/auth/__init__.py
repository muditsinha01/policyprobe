"""
Agent Authentication Module

Provides authentication and authorization for inter-agent communication.

SECURITY NOTES:
- All inter-agent communication requires valid authentication tokens
- Tokens are validated on every request
- All agents must present valid credentials to communicate
"""

from .agent_auth import AgentAuthenticator, AgentIdentity, AuthResult

__all__ = ["AgentAuthenticator", "AgentIdentity", "AuthResult"]