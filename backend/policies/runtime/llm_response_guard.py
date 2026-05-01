"""
LLM Response Guard

Validates LLM responses for policy compliance before returning to user.

SECURITY NOTES:
- validate() performs actual validation checks
- PII leakage detection in responses
- Harmful content filtering
- Dynamic code execution primitive detection
"""

import logging
import re
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Result of response validation."""
    is_valid: bool
    violations: list[str]
    filtered_response: Optional[str] = None
    original_response: Optional[str] = None


# Patterns for dynamic code execution primitives
CODE_EXECUTION_PATTERNS = [
    (r'\beval\s*\(', 'eval() dynamic code execution primitive detected'),
    (r'\bexec\s*\(', 'exec() dynamic code execution primitive detected'),
    (r'\bos\.system\s*\(', 'os.system() dynamic code execution primitive detected'),
    (r'\bos\.popen\s*\(', 'os.popen() dynamic code execution primitive detected'),
    (r'\bsubprocess\.(call|run|Popen|check_output|check_call)\s*\(.*shell\s*=\s*True', 'subprocess with shell=True dynamic code execution primitive detected'),
    (r'\bsubprocess\.(call|run|Popen|check_output|check_call)\s*\(', 'subprocess dynamic code execution primitive detected'),
    (r'\b__import__\s*\(', '__import__() dynamic code execution primitive detected'),
    (r'\bcompile\s*\(', 'compile() dynamic code execution primitive detected'),
    (r'\bexecfile\s*\(', 'execfile() dynamic code execution primitive detected'),
    (r'\bgetattr\s*\(.*__', 'getattr with dunder attribute detected'),
    (r'\bsetattr\s*\(', 'setattr() potentially dangerous call detected'),
    (r'\bdelattr\s*\(', 'delattr() potentially dangerous call detected'),
    (r'\bglobals\s*\(\s*\)', 'globals() introspection primitive detected'),
    (r'\blocals\s*\(\s*\)', 'locals() introspection primitive detected'),
    (r'\bvars\s*\(\s*\)', 'vars() introspection primitive detected'),
    (r'\b__builtins__\b', '__builtins__ access detected'),
    (r'\b__class__\b.*\b__bases__\b', 'class hierarchy traversal detected'),
    (r'\bpickle\.(loads|load|dumps|dump)\s*\(', 'pickle serialization primitive detected'),
    (r'\bmarshal\.(loads|load)\s*\(', 'marshal deserialization primitive detected'),
    (r'\bctypes\b', 'ctypes foreign function interface detected'),
    (r'\bcmd\s*=.*shell', 'shell command construction detected'),
]

# PII patterns
PII_PATTERNS = [
    (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN pattern detected in response'),
    (r'\b\d{3}\.\d{2}\.\d{4}\b', 'SSN pattern (dot format) detected in response'),
    (r'\b4[0-9]{12}(?:[0-9]{3})?\b', 'Visa card number detected in response'),
    (r'\b5[1-5][0-9]{14}\b', 'Mastercard number detected in response'),
    (r'\b3[47][0-9]{13}\b', 'Amex card number detected in response'),
    (r'\b6(?:011|5[0-9]{2})[0-9]{12}\b', 'Discover card number detected in response'),
    (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email address detected in response'),
    (r'\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', 'Phone number detected in response'),
    (r'\b\d{5}(?:-\d{4})?\b', 'ZIP code detected in response'),
    (r'\b(?:password|passwd|pwd)\s*[:=]\s*\S+', 'Password value detected in response'),
    (r'\b(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*\S+', 'API key detected in response'),
    (r'\b(?:token|auth[_-]?token|access[_-]?token)\s*[:=]\s*\S+', 'Auth token detected in response'),
    (r'\b[A-Z]{2}\d{6,9}\b', 'Passport number pattern detected in response'),
    (r'\b\d{10,16}\b', 'Potential account/ID number detected in response'),
]

# Sensitive data leakage patterns
SENSITIVE_DATA_PATTERNS = [
    (r'(?i)\b(?:secret|private[_-]?key|private_key)\s*[:=]\s*\S+', 'Private key/secret detected in response'),
    (r'(?i)\b(?:aws|azure|gcp)[_-]?(?:access[_-]?key|secret[_-]?key|account[_-]?key)\s*[:=]\s*\S+', 'Cloud provider credentials detected in response'),
    (r'(?i)(?:BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY)', 'Private key block detected in response'),
    (r'(?i)(?:BEGIN\s+CERTIFICATE)', 'Certificate block detected in response'),
    (r'(?i)\b(?:db|database)[_-]?(?:password|passwd|pwd)\s*[:=]\s*\S+', 'Database password detected in response'),
    (r'(?i)\b(?:connection[_-]?string|conn[_-]?str)\s*[:=]\s*\S+', 'Connection string detected in response'),
    (r'(?i)\b(?:internal|confidential|proprietary|classified)\b.*\b(?:data|information|document)\b', 'Potentially confidential data reference detected'),
    (r'(?i)(?:salary|compensation|ssn|social.security)\s*[:=]?\s*\$?\d+', 'Sensitive financial/personal data detected in response'),
    (r'(?i)\b(?:medical|health|diagnosis|prescription)\s+(?:record|data|information)\b', 'Medical/health data reference detected in response'),
    (r'(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s+.*(?:FROM|INTO|TABLE|DATABASE)', 'SQL query detected in response'),
    (r'(?i)\b(?:stack.?trace|traceback|exception)\b.*\b(?:line|file|module)\b', 'Stack trace/error details detected in response'),
    (r'(?i)(?:/etc/passwd|/etc/shadow|/proc/self)', 'System file path detected in response'),
    (r'(?i)(?:127\.0\.0\.1|localhost|0\.0\.0\.0)\s*:\s*\d+', 'Internal network address detected in response'),
]

# Bias and harmful content patterns
BIAS_HARMFUL_PATTERNS = [
    (r'(?i)\b(?:all|every|most)\s+(?:women|men|blacks|whites|asians|hispanics|muslims|jews|christians)\s+(?:are|were|should|must|can\'t|cannot|don\'t)\b', 'Potentially biased generalization detected'),
    (r'(?i)\b(?:inferior|superior)\s+(?:race|gender|religion|ethnicity)\b', 'Harmful racial/gender/religious content detected'),
    (r'(?i)\b(?:kill|murder|harm|attack|destroy)\s+(?:yourself|themselves|people|humans)\b', 'Harmful content suggesting violence detected'),
    (r'(?i)\b(?:how\s+to\s+(?:make|build|create|synthesize))\s+(?:bomb|explosive|weapon|poison|drug)\b', 'Harmful instructions detected in response'),
    (r'(?i)\b(?:suicide|self-harm)\s+(?:method|way|how|instruction)\b', 'Harmful self-harm content detected'),
    (r'(?i)\b(?:child|minor|underage)\s+(?:porn|pornography|sexual|nude|naked)\b', 'CSAM-related content detected'),
    (r'(?i)\b(?:hack|exploit|bypass|crack)\s+(?:into|the|this|a)\s+(?:system|server|database|account|network)\b', 'Hacking instructions detected in response'),
    (r'(?i)\b(?:phishing|scam|fraud|deceive|manipulate)\s+(?:users|people|victims|customers)\b', 'Fraud/deception instructions detected in response'),
]


def _redact_match(text: str, pattern: str, replacement: str = '[REDACTED]') -> str:
    """Redact matches of a pattern in text."""
    return re.sub(pattern, replacement, text)


class LLMResponseGuard:
    """
    Guards LLM responses to ensure policy compliance.

    Validates:
    - No PII in responses
    - No harmful/biased content
    - No sensitive data leakage
    - No dynamic code execution primitives
    - Compliance with content policies
    """

    def __init__(self):
        self.validation_count = 0

    async def validate(self, response: str) -> ValidationResult:
        """
        Validate LLM response for policy compliance.
        """
        self.validation_count += 1

        logger.debug(
            "Response validation requested",
            extra={
                "response_length": len(response),
                "validation_count": self.validation_count
            }
        )

        all_violations = []
        filtered = response

        # Check for dynamic code execution primitives
        code_violations = await self.check_code_execution(response)
        all_violations.extend(code_violations)

        # Check for PII leakage
        pii_violations = await self.check_pii_leakage(response)
        all_violations.extend(pii_violations)

        # Check for sensitive data leakage
        data_violations = await self.check_data_leakage(response)
        all_violations.extend(data_violations)

        # Check for bias/harmful content
        bias_violations = await self.check_bias(response)
        all_violations.extend(bias_violations)

        is_valid = len(all_violations) == 0

        if not is_valid:
            logger.warning(
                "LLM response validation failed",
                extra={
                    "violations": all_violations,
                    "validation_count": self.validation_count
                }
            )
            # Apply redaction for PII and sensitive data
            for pattern, _ in PII_PATTERNS:
                filtered = _redact_match(filtered, pattern)
            for pattern, _ in SENSITIVE_DATA_PATTERNS:
                filtered = _redact_match(filtered, pattern)
            for pattern, _ in CODE_EXECUTION_PATTERNS:
                filtered = _redact_match(filtered, pattern, '[CODE_EXECUTION_REMOVED]')
            # For bias/harmful content, replace entire response
            for pattern, _ in BIAS_HARMFUL_PATTERNS:
                if re.search(pattern, filtered):
                    filtered = '[Response filtered due to policy violation]'
                    break

        return ValidationResult(
            is_valid=is_valid,
            violations=all_violations,
            filtered_response=filtered,
            original_response=response
        )

    async def check_code_execution(self, response: str) -> list[str]:
        """
        Check if response contains dynamic code execution primitives.
        """
        violations = []
        for pattern, description in CODE_EXECUTION_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE | re.DOTALL):
                violations.append(description)
                logger.warning(
                    "Code execution primitive detected in LLM response",
                    extra={"violation": description}
                )
        return violations

    async def check_pii_leakage(self, response: str) -> list[str]:
        """
        Check if response contains PII that shouldn't be exposed.
        """
        violations = []
        for pattern, description in PII_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE):
                violations.append(description)
                logger.warning(
                    "PII detected in LLM response",
                    extra={"violation": description}
                )
        return violations

    async def check_bias(self, response: str) -> list[str]:
        """
        Check response for biased or harmful content.
        """
        violations = []
        for pattern, description in BIAS_HARMFUL_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE):
                violations.append(description)
                logger.warning(
                    "Bias/harmful content detected in LLM response",
                    extra={"violation": description}
                )
        return violations

    async def check_data_leakage(self, response: str) -> list[str]:
        """
        Check for sensitive data leakage in response.
        """
        violations = []
        for pattern, description in SENSITIVE_DATA_PATTERNS:
            if re.search(pattern, response, re.IGNORECASE | re.DOTALL):
                violations.append(description)
                logger.warning(
                    "Sensitive data leakage detected in LLM response",
                    extra={"violation": description}
                )
        return violations