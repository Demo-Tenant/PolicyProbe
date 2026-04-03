"""
OpenRouter LLM Client

Client for communicating with LLMs via OpenRouter API.

SECURITY NOTES (for Unifai demo):
- No input sanitization before sending to LLM
- No response validation
- API key handling could be improved
- No rate limiting
"""

import os
import re
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Approved LLM models allow list
APPROVED_MODELS = [
    "openai/gpt-4",
    "openai/gpt-4-turbo",
    "openai/gpt-3.5-turbo",
    "anthropic/claude-3-opus",
    "anthropic/claude-3-sonnet",
    "anthropic/claude-3-haiku",
]

# PII redaction patterns
PII_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED_SSN]'),
    # Year of Birth (standalone 4-digit year context)
    (re.compile(r'\b(born in|birth year|year of birth)[:\s]+\d{4}\b', re.IGNORECASE), '[REDACTED_YEAR_OF_BIRTH]'),
    # Personal Phone Number
    (re.compile(r'\b(\+?1[-.\s]?)?(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b'), '[REDACTED_PHONE]'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # Home Address (basic pattern)
    (re.compile(r'\b\d{1,5}\s+\w+(\s+\w+)*\s+(Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), '[REDACTED_ADDRESS]'),
    # Passport Number
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED_PASSPORT]'),
    # Drivers License Number (generic)
    (re.compile(r'\b(DL|DLN|Driver.?s?\s+License)[:\s#]*[A-Z0-9]{5,15}\b', re.IGNORECASE), '[REDACTED_DL]'),
    # Taxpayer Identification Number
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED_TIN]'),
    # Credit Card Number
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'), '[REDACTED_CC]'),
    # Financial Account Number
    (re.compile(r'\b(account\s*#?|acct\.?)[:\s]*\d{6,17}\b', re.IGNORECASE), '[REDACTED_ACCOUNT]'),
    # IP Address
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED_IP]'),
    # MAC Address
    (re.compile(r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED_MAC]'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED_VIN]'),
    # Employee ID
    (re.compile(r'\b(EMP|Employee\s*ID)[:\s#]*[A-Z0-9]{4,10}\b', re.IGNORECASE), '[REDACTED_EMPLOYEE_ID]'),
    # School ID
    (re.compile(r'\b(School\s*ID|Student\s*ID)[:\s#]*[A-Z0-9]{4,10}\b', re.IGNORECASE), '[REDACTED_SCHOOL_ID]'),
    # Birthplace
    (re.compile(r'\b(born in|birthplace|place of birth)[:\s]+[A-Za-z\s,]+', re.IGNORECASE), '[REDACTED_BIRTHPLACE]'),
    # Mother's Maiden Name
    (re.compile(r"\b(mother'?s?\s+maiden\s+name)[:\s]+[A-Za-z\s]+", re.IGNORECASE), '[REDACTED_MAIDEN_NAME]'),
    # Ethnicity
    (re.compile(r'\b(ethnicity|ethnic\s+origin)[:\s]+[A-Za-z\s]+', re.IGNORECASE), '[REDACTED_ETHNICITY]'),
    # Sexual Orientation
    (re.compile(r'\b(sexual\s+orientation)[:\s]+[A-Za-z\s]+', re.IGNORECASE), '[REDACTED_SEXUAL_ORIENTATION]'),
]


def redact_pii(text: str) -> str:
    """Redact PII from text using defined patterns."""
    if not text:
        return text
    for pattern, replacement in PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_messages_for_log(messages: list[dict]) -> list[dict]:
    """Return a copy of messages with PII redacted for logging purposes."""
    redacted = []
    for msg in messages:
        redacted_msg = dict(msg)
        if "content" in redacted_msg:
            redacted_msg["content"] = redact_pii(str(redacted_msg["content"]))
        redacted.append(redacted_msg)
    return redacted


def validate_model(model: str) -> str:
    """
    Validate that the requested model is in the approved list.
    Raises ValueError if the model is not approved.
    """
    if model not in APPROVED_MODELS:
        approved_list = ", ".join(APPROVED_MODELS)
        raise ValueError(
            f"Model '{model}' is not approved. "
            f"Please replace it with an approved LLM from the allow list: {approved_list}"
        )
    return model


class OpenRouterClient:
    """
    Client for OpenRouter API to access various LLMs.

    Only approved models from the allow list are permitted.
    PII is redacted from content before logging and before sending to LLM.
    """

    BASE_URL = "https://openrouter.ai/api/v1"
    DEFAULT_MODEL = "openai/gpt-4"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None
    ):
        """
        Initialize the OpenRouter client.

        Args:
            api_key: OpenRouter API key (defaults to env var)
            model: Model to use (must be from approved list; defaults to openai/gpt-4)
        """
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        requested_model = model or os.getenv("OPENROUTER_MODEL") or self.DEFAULT_MODEL

        try:
            self.model = validate_model(requested_model)
        except ValueError as e:
            logger.error(str(e))
            logger.warning(f"Falling back to default approved model: {self.DEFAULT_MODEL}")
            self.model = self.DEFAULT_MODEL

        if not self.api_key:
            logger.warning(
                "OpenRouter API key not configured. "
                "Set OPENROUTER_API_KEY environment variable."
            )

    async def chat(
        self,
        messages: list[dict],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2000
    ) -> str:
        """
        Send chat completion request to OpenRouter.

        Args:
            messages: List of message dicts with role and content
            model: Override model for this request (must be from approved list)
            temperature: Sampling temperature
            max_tokens: Maximum response tokens

        Returns:
            LLM response text
        """
        if not self.api_key:
            return "LLM service not configured. Please set OPENROUTER_API_KEY."

        # Validate requested model against approved list
        effective_model = model or self.model
        try:
            effective_model = validate_model(effective_model)
        except ValueError as e:
            logger.error(str(e))
            return (
                f"Error: {str(e)}"
            )

        # Redact PII from messages before logging
        redacted_messages_preview = str(redact_messages_for_log(messages))[:200]
        logger.info(
            "Sending request to OpenRouter",
            extra={
                "model": effective_model,
                "message_count": len(messages),
                "total_content_length": sum(len(m.get("content", "")) for m in messages),
                "messages_preview": redacted_messages_preview
            }
        )

        # Redact PII from message content before sending to LLM
        sanitized_messages = []
        for msg in messages:
            sanitized_msg = dict(msg)
            if "content" in sanitized_msg:
                sanitized_msg["content"] = redact_pii(str(sanitized_msg["content"]))
            sanitized_messages.append(sanitized_msg)

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.BASE_URL}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "HTTP-Referer": "https://policyprobe.demo",
                        "X-Title": "PolicyProbe Demo",
                        "Content-Type": "application/json"
                    },
                    json={
                        "model": effective_model,
                        "messages": sanitized_messages,
                        "temperature": temperature,
                        "max_tokens": max_tokens
                    },
                    timeout=60.0
                )

                response.raise_for_status()
                data = response.json()

                # Extract response content
                content = data["choices"][0]["message"]["content"]

                # Redact PII from response before logging
                redacted_response_preview = redact_pii(content)[:200]
                logger.info(
                    "Received response from OpenRouter",
                    extra={
                        "response_length": len(content),
                        "response_preview": redacted_response_preview
                    }
                )

                return content

        except httpx.HTTPStatusError as e:
            logger.error(f"OpenRouter API error: {e.response.status_code}")
            return f"Error communicating with LLM: {e.response.status_code}"
        except Exception as e:
            logger.error(f"OpenRouter client error: {e}")
            return f"Error: {str(e)}"

    async def chat_with_context(
        self,
        user_message: str,
        system_prompt: str,
        context: Optional[str] = None
    ) -> str:
        """
        Convenience method for chat with system prompt and optional context.
        PII is redacted from all content before processing.
        """
        messages = [{"role": "system", "content": system_prompt}]

        if context:
            # Redact PII from context before use
            sanitized_context = redact_pii(context)
            sanitized_user_message = redact_pii(user_message)
            messages.append({
                "role": "user",
                "content": f"Context:\n{sanitized_context}\n\nQuery: {sanitized_user_message}"
            })
        else:
            sanitized_user_message = redact_pii(user_message)
            messages.append({"role": "user", "content": sanitized_user_message})

        return await self.chat(messages)

    async def analyze_document(self, content: str) -> str:
        """
        Analyze document content using LLM.

        PII is scanned and redacted from document content before sending to LLM.
        """
        # Redact PII from document content before sending to LLM
        sanitized_content = redact_pii(content)
        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points.",
            context=sanitized_content
        )