"""
LLM Response Guard

Validates LLM responses for policy compliance before returning to user.
"""

import re
import logging
import html
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


# Patterns for dynamic code execution primitives that must be removed
_DANGEROUS_LINE_PATTERNS = [
    re.compile(r'\beval\s*\(', re.IGNORECASE),
    re.compile(r'\bexec\s*\(', re.IGNORECASE),
    re.compile(r'\bsubprocess\s*\(', re.IGNORECASE),
    re.compile(r'subprocess\.(?:call|run|Popen|check_output|check_call)\s*\(.*shell\s*=\s*True', re.IGNORECASE | re.DOTALL),
    re.compile(r'\bos\.system\s*\(', re.IGNORECASE),
    re.compile(r'\bos\.popen\s*\(', re.IGNORECASE),
    re.compile(r'\b__import__\s*\(', re.IGNORECASE),
    re.compile(r'\bcompile\s*\(', re.IGNORECASE),
    re.compile(r'\bexecfile\s*\(', re.IGNORECASE),
    # JavaScript eval
    re.compile(r'\beval\s*`', re.IGNORECASE),
    re.compile(r'\bnew\s+Function\s*\(', re.IGNORECASE),
    re.compile(r'\bsetTimeout\s*\(\s*["\']', re.IGNORECASE),
    re.compile(r'\bsetInterval\s*\(\s*["\']', re.IGNORECASE),
    # Bash eval
    re.compile(r'\beval\s+"', re.IGNORECASE),
    re.compile(r'\beval\s+\'', re.IGNORECASE),
    re.compile(r'\$\(.*\)', re.IGNORECASE),
    re.compile(r'`[^`]+`'),
]

# PII patterns
_PII_PATTERNS = [
    re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),                          # SSN
    re.compile(r'\b(?:\d[ -]?){13,16}\b'),                          # Credit card
    re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),  # Email
    re.compile(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b'),              # Phone
    re.compile(r'\b(?:password|passwd|secret|api[_\s]?key|token)\s*[:=]\s*\S+', re.IGNORECASE),  # Credentials
]

# Sensitive data / data leakage patterns
_SENSITIVE_PATTERNS = [
    re.compile(r'(?:BEGIN|END)\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY', re.IGNORECASE),
    re.compile(r'(?:aws|azure|gcp)[_\s]?(?:access|secret|key)[_\s]?(?:id|key)?\s*[:=]\s*\S+', re.IGNORECASE),
    re.compile(r'\b(?:connection[_\s]?string|jdbc:[^\s]+)', re.IGNORECASE),
]

# Harmful / biased content indicators (basic keyword list)
_HARMFUL_PATTERNS = [
    re.compile(r'\b(?:kill|murder|bomb|attack|exploit|hack)\b', re.IGNORECASE),
]


def _remove_dangerous_lines(response: str) -> tuple[str, list[str]]:
    """Remove lines containing dynamic code-execution primitives."""
    violations = []
    cleaned_lines = []
    for line in response.splitlines():
        dangerous = False
        for pattern in _DANGEROUS_LINE_PATTERNS:
            if pattern.search(line):
                violations.append(
                    f"Removed dangerous code-execution primitive from response line: {line[:80]!r}"
                )
                dangerous = True
                break
        if not dangerous:
            cleaned_lines.append(line)
    return "\n".join(cleaned_lines), violations


def _encode_output(response: str) -> str:
    """Encode HTML special characters to prevent XSS in responses."""
    return html.escape(response, quote=True)


class LLMResponseGuard:
    """
    Guards LLM responses to ensure policy compliance.

    Validates:
    - No dynamic code-execution primitives (eval, exec, subprocess shell=True, etc.)
    - No PII in responses
    - No harmful/biased content
    - No sensitive data leakage
    - Output encoding to prevent XSS
    """

    def __init__(self):
        self.validation_count = 0

    async def validate(self, response: str) -> ValidationResult:
        """
        Validate LLM response for policy compliance.
        Removes dangerous lines and checks for PII, bias, and data leakage.
        """
        if not isinstance(response, str):
            logger.warning("Non-string response received; coercing to string.")
            response = str(response)

        self.validation_count += 1

        logger.debug(
            "Response validation requested",
            extra={
                "response_length": len(response),
                "validation_count": self.validation_count
            }
        )

        original_response = response
        all_violations: list[str] = []

        # Step 1: Remove dangerous code-execution primitives line by line
        filtered, code_violations = _remove_dangerous_lines(response)
        all_violations.extend(code_violations)

        # Step 2: Check for PII leakage
        pii_violations = await self.check_pii_leakage(filtered)
        all_violations.extend(pii_violations)

        # Step 3: Check for bias / harmful content
        bias_violations = await self.check_bias(filtered)
        all_violations.extend(bias_violations)

        # Step 4: Check for sensitive data leakage
        leakage_violations = await self.check_data_leakage(filtered)
        all_violations.extend(leakage_violations)

        # Step 5: Output encoding to prevent XSS
        encoded = _encode_output(filtered)

        is_valid = len(all_violations) == 0

        if all_violations:
            logger.warning(
                "LLM response validation violations detected",
                extra={
                    "violation_count": len(all_violations),
                    "violations": all_violations,
                    "validation_count": self.validation_count
                }
            )

        return ValidationResult(
            is_valid=is_valid,
            violations=all_violations,
            filtered_response=encoded,
            original_response=original_response
        )

    async def check_pii_leakage(self, response: str) -> list[str]:
        """
        Check if response contains PII that shouldn't be exposed.
        """
        violations = []
        for pattern in _PII_PATTERNS:
            matches = pattern.findall(response)
            if matches:
                violations.append(
                    f"Potential PII detected in response matching pattern {pattern.pattern!r}: "
                    f"{len(matches)} occurrence(s)"
                )
        return violations

    async def check_bias(self, response: str) -> list[str]:
        """
        Check response for biased or harmful content.
        """
        violations = []
        for pattern in _HARMFUL_PATTERNS:
            matches = pattern.findall(response)
            if matches:
                violations.append(
                    f"Potentially harmful content detected matching pattern {pattern.pattern!r}: "
                    f"{matches[:5]}"
                )
        return violations

    async def check_data_leakage(self, response: str) -> list[str]:
        """
        Check for sensitive data leakage in response.
        """
        violations = []
        for pattern in _SENSITIVE_PATTERNS:
            matches = pattern.findall(response)
            if matches:
                violations.append(
                    f"Sensitive data leakage detected matching pattern {pattern.pattern!r}: "
                    f"{len(matches)} occurrence(s)"
                )
        return violations