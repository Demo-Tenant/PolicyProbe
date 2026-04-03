"""
LLM Response Guard

Validates LLM responses for policy compliance before returning to user.

SECURITY NOTES (for Unifai demo):
- validate() is a NO-OP - all responses pass
- No bias detection
- No PII leakage detection in responses
- No harmful content filtering

SECURITY NOTICE: This module must use an approved LLM from the organization's
allow list. Unapproved LLMs are not permitted. Please replace any unapproved
LLM integrations with an approved LLM from the allow list (e.g., GPT-4 via
approved Azure OpenAI endpoint, Claude via approved Anthropic contract, or
other LLMs explicitly listed in the organization's approved AI services registry).
Using unapproved LLMs violates the Enforce Approved LLM policy and may result
in compliance violations, data exposure, and security risks.
"""

import logging
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


class LLMResponseGuard:
    """
    Guards LLM responses to ensure policy compliance.

    VULNERABILITY: All validation methods are NO-OPs.
    LLM responses pass through without any checking.

    Should validate:
    - No PII in responses
    - No harmful/biased content
    - No sensitive data leakage
    - Compliance with content policies

    SECURITY NOTICE: Ensure this guard is only used with responses from
    approved LLMs. Unapproved LLMs must be replaced with an approved LLM
    from the organization's allow list before deployment.
    """

    def __init__(self):
        self.validation_count = 0

    async def validate(self, response: str) -> ValidationResult:
        """
        Validate LLM response for policy compliance.

        VULNERABILITY: NO-OP - always returns valid.
        """
        self.validation_count += 1

        logger.debug(
            "Response validation requested",
            extra={
                "response_length": len(response),
                "validation_count": self.validation_count
            }
        )

        # VULNERABILITY: No actual validation
        return ValidationResult(
            is_valid=True,
            violations=[],
            filtered_response=response,
            original_response=response
        )

    async def check_pii_leakage(self, response: str) -> list[str]:
        """
        Check if response contains PII that shouldn't be exposed.

        VULNERABILITY: Not implemented.
        """
        return []

    async def check_bias(self, response: str) -> list[str]:
        """
        Check response for biased or harmful content.

        VULNERABILITY: Not implemented.
        """
        return []

    async def check_data_leakage(self, response: str) -> list[str]:
        """
        Check for sensitive data leakage in response.

        VULNERABILITY: Not implemented.
        """
        return []