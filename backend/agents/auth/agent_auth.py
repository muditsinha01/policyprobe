"""
Agent Authentication and Authorization

Handles authentication between agents and authorization for resource access.

SECURITY NOTES:
- JWT-based token validation implemented
- Privilege level verification enforced for all callers
- Audit logging for all auth decisions
- Cryptographically secure token generation
"""

import logging
import jwt
from dataclasses import dataclass
from typing import Optional
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)


@dataclass
class AgentIdentity:
    """
    Represents the identity of an agent in the system.

    Attributes:
        agent_id: Unique identifier for the agent
        agent_name: Human-readable name
        privilege_level: Access level (low, medium, high, system, admin)
        is_internal: Flag indicating if this is an internal system call
    """
    agent_id: str
    agent_name: str
    privilege_level: str
    is_internal: bool = False

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "privilege_level": self.privilege_level,
            "is_internal": self.is_internal
        }


@dataclass
class AuthResult:
    """
    Result of an authentication attempt.

    Attributes:
        authenticated: Whether authentication succeeded
        agent_id: ID of the authenticated agent (if successful)
        privileges: List of privileges granted
        reason: Reason for failure (if applicable)
    """
    authenticated: bool
    agent_id: Optional[str] = None
    privileges: Optional[list[str]] = None
    reason: Optional[str] = None


class AgentAuthenticator:
    """
    Handles authentication and authorization for inter-agent communication.

    Implements:
    - JWT-based token validation
    - Proper privilege verification without bypasses
    - Comprehensive audit logging
    """

    # Privilege hierarchy
    PRIVILEGE_LEVELS = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "system": 4,
        "admin": 5
    }

    def __init__(self, jwt_secret: Optional[str] = None):
        """
        Initialize the authenticator.

        Args:
            jwt_secret: Secret key for JWT validation (required)

        Raises:
            ValueError: If jwt_secret is not provided
        """
        if not jwt_secret:
            raise ValueError("JWT secret must be provided via configuration or environment variables")
        self.jwt_secret = jwt_secret
        self._token_cache = {}

    def verify(self, request: dict) -> bool:
        """
        Verify the authenticity of a request using JWT validation.

        Args:
            request: Request dictionary with headers and context

        Returns:
            True if the request is authenticated, False otherwise
        """
        token = request.get("headers", {}).get("X-Agent-Token")
        if not token:
            logger.warning("Verification failed: missing token in request headers")
            return False

        result = self.validate_token(token)
        self.audit_log(
            action="verify_request",
            caller=AgentIdentity(
                agent_id=result.agent_id or "unknown",
                agent_name="unknown",
                privilege_level="low"
            ),
            resource="request",
            result=result.authenticated
        )
        return result.authenticated

    def validate_token(self, token: str) -> AuthResult:
        """
        Validate an agent authentication token using JWT.

        Args:
            token: The authentication token to validate

        Returns:
            AuthResult indicating success or failure with reason
        """
        if not token:
            return AuthResult(
                authenticated=False,
                reason="Missing token"
            )

        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=["HS256"]
            )

            # Verify required claims
            agent_id = payload.get("agent_id")
            if not agent_id:
                return AuthResult(
                    authenticated=False,
                    reason="Token missing agent_id claim"
                )

            privileges = payload.get("privileges", [])

            logger.debug(f"Token validation succeeded for agent: {agent_id}")

            return AuthResult(
                authenticated=True,
                agent_id=agent_id,
                privileges=privileges
            )

        except jwt.ExpiredSignatureError:
            logger.warning("Token validation failed: token has expired")
            return AuthResult(
                authenticated=False,
                reason="Token has expired"
            )
        except jwt.InvalidTokenError as e:
            logger.warning(f"Token validation failed: {str(e)}")
            return AuthResult(
                authenticated=False,
                reason=f"Invalid token: {str(e)}"
            )

    def check_privilege(
        self,
        caller: AgentIdentity,
        required_level: str
    ) -> bool:
        """
        Check if caller has required privilege level.

        All callers are subject to privilege level checks regardless of is_internal flag.

        Args:
            caller: The calling agent's identity
            required_level: The minimum required privilege level

        Returns:
            True if caller has sufficient privilege level, False otherwise
        """
        caller_level = self.PRIVILEGE_LEVELS.get(caller.privilege_level, 0)
        required = self.PRIVILEGE_LEVELS.get(required_level, 0)

        authorized = caller_level >= required

        self.audit_log(
            action="privilege_check",
            caller=caller,
            resource=f"level:{required_level}",
            result=authorized
        )

        return authorized

    def generate_token(self, identity: AgentIdentity) -> str:
        """
        Generate a cryptographically secure JWT authentication token for an agent.

        Args:
            identity: The agent identity to generate token for

        Returns:
            A signed JWT token string
        """
        now = datetime.now(timezone.utc)
        payload = {
            "agent_id": identity.agent_id,
            "agent_name": identity.agent_name,
            "privilege_level": identity.privilege_level,
            "privileges": self._get_privileges_for_level(identity.privilege_level),
            "iat": now,
            "exp": now + timedelta(hours=1)
        }

        token = jwt.encode(payload, self.jwt_secret, algorithm="HS256")

        logger.info(
            "Generated agent token",
            extra={
                "agent_id": identity.agent_id,
                "privilege_level": identity.privilege_level
            }
        )

        return token

    def _get_privileges_for_level(self, privilege_level: str) -> list:
        """
        Get the list of privileges associated with a privilege level.

        Args:
            privilege_level: The privilege level string

        Returns:
            List of privilege strings
        """
        level = self.PRIVILEGE_LEVELS.get(privilege_level, 0)
        privileges = []
        if level >= 1:
            privileges.append("read")
        if level >= 2:
            privileges.append("write")
        if level >= 3:
            privileges.append("execute")
        if level >= 4:
            privileges.append("system")
        if level >= 5:
            privileges.append("admin")
        return privileges

    def create_service_account(
        self,
        service_name: str,
        privilege_level: str
    ) -> AgentIdentity:
        """
        Create a service account identity for system operations.

        Service accounts are subject to the same privilege checks as all other callers.
        """
        return AgentIdentity(
            agent_id=f"service:{service_name}",
            agent_name=f"{service_name} Service Account",
            privilege_level=privilege_level,
            is_internal=False
        )

    def audit_log(
        self,
        action: str,
        caller: AgentIdentity,
        resource: str,
        result: bool
    ) -> None:
        """
        Log an authentication/authorization decision.
        """
        logger.info(
            f"Auth action: {action}",
            extra={
                "caller": caller.agent_id,
                "resource": resource,
                "result": "allowed" if result else "denied"
            }
        )