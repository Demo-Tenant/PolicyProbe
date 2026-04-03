"""
OpenRouter LLM Client

Client for communicating with LLMs via OpenRouter API.

SECURITY NOTES (for Unifai demo):
- Input sanitization applied before sending to LLM
- Response validation applied
- API key handling improved
- Rate limiting recommended at infrastructure level
"""

import os
import re
import base64
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Approved LLM models allowlist
APPROVED_MODELS = {
    "meta-llama/llama-3-70b-instruct",
    "meta-llama/llama-3-8b-instruct",
    "anthropic/claude-3-opus",
    "anthropic/claude-3-sonnet",
    "anthropic/claude-3-haiku",
    "openai/gpt-4o",
    "openai/gpt-4-turbo",
    "openai/gpt-3.5-turbo",
    "google/gemini-pro",
    "google/gemini-pro-1.5",
}

# PII redaction patterns for zero-tolerance PII categories
PII_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED-SSN]'),
    (re.compile(r'\b\d{9}\b(?=\s|$)'), '[REDACTED-SSN]'),
    # Personal Phone Number
    (re.compile(r'\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), '[REDACTED-PHONE]'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED-EMAIL]'),
    # Credit Card Number
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'), '[REDACTED-CC]'),
    # IP Address
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED-IP]'),
    # MAC Address
    (re.compile(r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[REDACTED-MAC]'),
    # Passport Number (generic alphanumeric 6-9 chars)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED-PASSPORT]'),
    # Drivers License (common US formats)
    (re.compile(r'\b[A-Z]\d{7}\b'), '[REDACTED-DL]'),
    # Taxpayer Identification Number
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED-TIN]'),
    # Financial Account Number (8-17 digits)
    (re.compile(r'\b\d{8,17}\b'), '[REDACTED-ACCOUNT]'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED-VIN]'),
    # Year of Birth patterns (e.g., "born in 1985", "DOB: 1990")
    (re.compile(r'\b(?:born\s+in|dob[:\s]+|date\s+of\s+birth[:\s]+)\s*\d{4}\b', re.IGNORECASE), '[REDACTED-YOB]'),
    # Home Address (basic pattern: number + street)
    (re.compile(r'\b\d+\s+[A-Za-z]+\s+(?:St|Ave|Blvd|Rd|Dr|Ln|Way|Ct|Pl|Street|Avenue|Boulevard|Road|Drive|Lane|Court|Place)\b', re.IGNORECASE), '[REDACTED-ADDRESS]'),
]

# Prompt injection / suspicious content patterns
SUSPICIOUS_PROMPT_PATTERNS = [
    # Hidden prompt injection keywords
    re.compile(r'ignore\s+(previous|all|above|prior)\s+(instructions?|prompts?|context)', re.IGNORECASE),
    re.compile(r'disregard\s+(previous|all|above|prior)\s+(instructions?|prompts?|context)', re.IGNORECASE),
    re.compile(r'forget\s+(previous|all|above|prior)\s+(instructions?|prompts?|context)', re.IGNORECASE),
    re.compile(r'you\s+are\s+now\s+(?:a\s+)?(?:an?\s+)?(?:different|new|another|evil|unrestricted)', re.IGNORECASE),
    re.compile(r'act\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:a\s+)?(?:different|new|another|evil|unrestricted|jailbreak)', re.IGNORECASE),
    re.compile(r'pretend\s+(?:you\s+are|to\s+be)\s+(?:a\s+)?(?:different|new|another|evil|unrestricted)', re.IGNORECASE),
    re.compile(r'jailbreak', re.IGNORECASE),
    re.compile(r'DAN\s+mode', re.IGNORECASE),
    # Shell commands
    re.compile(r'\b(?:rm\s+-rf|chmod\s+777|wget\s+http|curl\s+http|nc\s+-|netcat|/bin/sh|/bin/bash|cmd\.exe|powershell)', re.IGNORECASE),
    # Binary/executable indicators
    re.compile(r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){3,}'),
    re.compile(r'\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07'),
    # Leetspeak for common injection phrases
    re.compile(r'1gn0r3|d1sr3g4rd|f0rg3t', re.IGNORECASE),
]

# Dynamic code execution patterns for response validation
CODE_EXECUTION_PATTERNS = [
    re.compile(r'^\s*eval\s*\(', re.MULTILINE),
    re.compile(r'^\s*exec\s*\(', re.MULTILINE),
    re.compile(r'^\s*subprocess\s*\.\s*\w+\s*\(.*shell\s*=\s*True', re.MULTILINE),
    re.compile(r'^\s*os\s*\.\s*system\s*\(', re.MULTILINE),
    re.compile(r'^\s*os\s*\.\s*popen\s*\(', re.MULTILINE),
    re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
    re.compile(r'javascript\s*:', re.IGNORECASE),
    re.compile(r'^\s*`[^`]*`', re.MULTILINE),  # backtick shell execution
    re.compile(r'^\s*\$\([^)]*\)', re.MULTILINE),  # bash $() execution
    re.compile(r'^\s*bash\s+-c\s+', re.MULTILINE | re.IGNORECASE),
    re.compile(r'^\s*sh\s+-c\s+', re.MULTILINE | re.IGNORECASE),
]


def _redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from text."""
    if not text:
        return text
    for pattern, replacement in PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _is_base64_encoded(text: str) -> bool:
    """Check if a string segment appears to be base64 encoded content."""
    # Look for base64 patterns that are suspiciously long
    b64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
    matches = b64_pattern.findall(text)
    for match in matches:
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            # Check if decoded content contains suspicious patterns
            for pattern in SUSPICIOUS_PROMPT_PATTERNS:
                if pattern.search(decoded):
                    return True
        except Exception:
            pass
    return False


def _has_invisible_text(text: str) -> bool:
    """Detect invisible/hidden text techniques."""
    # Zero-width characters
    invisible_chars = ['\u200b', '\u200c', '\u200d', '\u200e', '\u200f',
                       '\u00ad', '\ufeff', '\u2060', '\u2061', '\u2062',
                       '\u2063', '\u2064']
    for char in invisible_chars:
        if char in text:
            return True
    # Check for very small font indicators (HTML style)
    if re.search(r'font-size\s*:\s*[01]px', text, re.IGNORECASE):
        return True
    # White on white color
    if re.search(r'color\s*:\s*(?:white|#fff(?:fff)?|rgb\(255,\s*255,\s*255\))', text, re.IGNORECASE):
        return True
    return False


def _check_prompt_injection(text: str) -> bool:
    """
    Check for prompt injection, hidden prompts, base64 encoded prompts,
    leetspeak, suspicious content, and binary/shell commands.
    Returns True if suspicious content is detected.
    """
    if not text:
        return False

    # Check for invisible/hidden text
    if _has_invisible_text(text):
        logger.warning("Invisible/hidden text detected in prompt input.")
        return True

    # Check for base64 encoded suspicious content
    if _is_base64_encoded(text):
        logger.warning("Base64 encoded suspicious content detected in prompt input.")
        return True

    # Check for known suspicious patterns
    for pattern in SUSPICIOUS_PROMPT_PATTERNS:
        if pattern.search(text):
            logger.warning("Suspicious prompt pattern detected in input.")
            return True

    return False


def _sanitize_input(text: str) -> str:
    """Sanitize input text before sending to LLM."""
    if not text:
        return text
    # Remove null bytes and non-printable control characters (except newlines/tabs)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    # Remove zero-width and invisible unicode characters
    invisible_chars = ['\u200b', '\u200c', '\u200d', '\u200e', '\u200f',
                       '\u00ad', '\ufeff', '\u2060', '\u2061', '\u2062',
                       '\u2063', '\u2064']
    for char in invisible_chars:
        text = text.replace(char, '')
    return text


def _validate_and_sanitize_messages(messages: list[dict]) -> tuple[list[dict], bool]:
    """
    Validate and sanitize all messages before sending to LLM.
    Returns sanitized messages and a flag indicating if suspicious content was found.
    """
    sanitized = []
    suspicious_found = False
    for msg in messages:
        content = msg.get("content", "")
        role = msg.get("role", "")
        # Check for prompt injection in user messages
        if role in ("user", "system") and _check_prompt_injection(content):
            suspicious_found = True
            logger.warning(f"Suspicious content detected in '{role}' message. Blocking request.")
        # Sanitize input
        sanitized_content = _sanitize_input(content)
        # Redact PII before sending to LLM
        sanitized_content = _redact_pii(sanitized_content)
        sanitized.append({**msg, "content": sanitized_content})
    return sanitized, suspicious_found


def _validate_llm_response(response_text: str) -> str:
    """
    Validate LLM response and remove lines containing dynamic code execution primitives.
    """
    if not response_text:
        return response_text

    lines = response_text.splitlines(keepends=True)
    safe_lines = []
    for line in lines:
        line_flagged = False
        for pattern in CODE_EXECUTION_PATTERNS:
            if pattern.search(line):
                logger.warning("Removed potentially dangerous code execution line from LLM response.")
                line_flagged = True
                break
        if not line_flagged:
            safe_lines.append(line)

    return ''.join(safe_lines)


def _check_model_approved(model: str) -> bool:
    """Check if the model is in the approved allowlist."""
    return model in APPROVED_MODELS


class OpenRouterClient:
    """
    Client for OpenRouter API to access various LLMs.
    """

    BASE_URL = "https://openrouter.ai/api/v1"
    DEFAULT_MODEL = "meta-llama/llama-3-70b-instruct"

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None
    ):
        """
        Initialize the OpenRouter client.

        Args:
            api_key: OpenRouter API key (defaults to env var)
            model: Model to use (defaults to Llama 3 70B, can be overridden via OPENROUTER_MODEL env var)
        """
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        self.model = model or os.getenv("OPENROUTER_MODEL") or self.DEFAULT_MODEL

        if not self.api_key:
            logger.warning(
                "OpenRouter API key not configured. "
                "Set OPENROUTER_API_KEY environment variable."
            )

        # Enforce approved model
        if not _check_model_approved(self.model):
            logger.warning(
                f"Model '{self.model}' is not in the approved LLM allowlist. "
                f"Please replace it with an approved model from the allowlist: "
                f"{sorted(APPROVED_MODELS)}. "
                f"Falling back to default approved model: {self.DEFAULT_MODEL}."
            )
            self.model = self.DEFAULT_MODEL

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
            model: Override model for this request
            temperature: Sampling temperature
            max_tokens: Maximum response tokens

        Returns:
            LLM response text
        """
        if not self.api_key:
            return "LLM service not configured. Please set OPENROUTER_API_KEY."

        # Enforce approved model for per-request override
        effective_model = model or self.model
        if not _check_model_approved(effective_model):
            logger.warning(
                f"Requested model '{effective_model}' is not in the approved LLM allowlist. "
                f"Please replace it with an approved model from the allowlist: "
                f"{sorted(APPROVED_MODELS)}. "
                f"Falling back to default approved model: {self.DEFAULT_MODEL}."
            )
            effective_model = self.DEFAULT_MODEL

        # Validate and sanitize messages (prompt injection check + PII redaction)
        sanitized_messages, suspicious_found = _validate_and_sanitize_messages(messages)
        if suspicious_found:
            return "Request blocked: suspicious or potentially malicious content detected in input."

        logger.info(
            "Sending request to OpenRouter",
            extra={
                "model": effective_model,
                "message_count": len(sanitized_messages),
                "total_content_length": sum(len(m.get("content", "")) for m in sanitized_messages),
            }
        )

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

                # Validate and sanitize LLM response
                content = _validate_llm_response(content)

                logger.info(
                    "Received response from OpenRouter",
                    extra={
                        "response_length": len(content),
                    }
                )

                return content

        except httpx.HTTPStatusError as e:
            logger.error(f"OpenRouter API error: {e.response.status_code}")
            return f"Error communicating with LLM: {e.response.status_code}"
        except Exception as e:
            logger.error("OpenRouter client error occurred.")
            return "Error: An internal error occurred while communicating with the LLM."

    async def chat_with_context(
        self,
        user_message: str,
        system_prompt: str,
        context: Optional[str] = None
    ) -> str:
        """
        Convenience method for chat with system prompt and optional context.
        """
        messages = [{"role": "system", "content": system_prompt}]

        if context:
            messages.append({
                "role": "user",
                "content": f"Context:\n{context}\n\nQuery: {user_message}"
            })
        else:
            messages.append({"role": "user", "content": user_message})

        return await self.chat(messages)

    async def analyze_document(self, content: str) -> str:
        """
        Analyze document content using LLM.
        """
        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points.",
            context=content
        )