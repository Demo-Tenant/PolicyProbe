"""
OpenRouter LLM Client

Client for communicating with LLMs via OpenRouter API.

SECURITY NOTES:
- Input sanitization applied before sending to LLM
- Response validation applied
- PII redaction applied before sending to LLM and in logs
- Prompt injection and suspicious content detection applied
- Dynamic code execution primitives removed from LLM responses

WARNING: Direct invocation of LLM from the MCP server creates security and
data exposure risks. It is strongly recommended to use sampling instead of
directly calling the LLM API. Direct access bypasses MCP's built-in safety
controls and may expose sensitive data to the LLM without proper oversight.
"""

import os
import re
import base64
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PII redaction helpers
# ---------------------------------------------------------------------------

# Patterns for zero-tolerance PII categories
_PII_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[REDACTED_SSN]'),
    (re.compile(r'\b\d{9}\b'), '[REDACTED_SSN]'),
    # Year of Birth (standalone 4-digit year 1900-2099)
    (re.compile(r'\b(19|20)\d{2}\b'), '[REDACTED_YOB]'),
    # Personal Phone Number
    (re.compile(r'\b(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b'), '[REDACTED_PHONE]'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
    # Passport Number (generic alphanumeric 6-9 chars)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[REDACTED_PASSPORT]'),
    # Drivers License (common US formats)
    (re.compile(r'\b[A-Z]\d{7}\b'), '[REDACTED_DL]'),
    # Taxpayer Identification Number (EIN format)
    (re.compile(r'\b\d{2}-\d{7}\b'), '[REDACTED_TIN]'),
    # Credit Card Number
    (re.compile(r'\b(?:\d[ \-]?){13,16}\b'), '[REDACTED_CC]'),
    # IP Address (v4)
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[REDACTED_IP]'),
    # IP Address (v6)
    (re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'), '[REDACTED_IPV6]'),
    # MAC Address
    (re.compile(r'\b([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b'), '[REDACTED_MAC]'),
    # Vehicle Identification Number (17 chars)
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[REDACTED_VIN]'),
    # Financial Account Number (8-17 digits)
    (re.compile(r'\b\d{8,17}\b'), '[REDACTED_ACCOUNT]'),
    # Employee/School ID (common patterns)
    (re.compile(r'\b(EMP|SCH|ID)[#\-]?\d{4,10}\b', re.IGNORECASE), '[REDACTED_ID]'),
]

_ETHNICITY_TERMS = re.compile(
    r'\b(caucasian|african american|hispanic|latino|latina|asian|native american|'
    r'pacific islander|middle eastern|multiracial|biracial)\b',
    re.IGNORECASE
)

_SEXUAL_ORIENTATION_TERMS = re.compile(
    r'\b(heterosexual|homosexual|bisexual|gay|lesbian|queer|pansexual|asexual|'
    r'straight|lgbtq)\b',
    re.IGNORECASE
)


def _redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from text."""
    if not isinstance(text, str):
        return text
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    text = _ETHNICITY_TERMS.sub('[REDACTED_ETHNICITY]', text)
    text = _SEXUAL_ORIENTATION_TERMS.sub('[REDACTED_SEXUAL_ORIENTATION]', text)
    return text


def _redact_messages_for_log(messages: list[dict]) -> list[dict]:
    """Return a copy of messages with PII redacted for logging."""
    redacted = []
    for m in messages:
        redacted.append({
            k: (_redact_pii(v) if k == 'content' and isinstance(v, str) else v)
            for k, v in m.items()
        })
    return redacted


# ---------------------------------------------------------------------------
# Input sanitization / prompt injection / suspicious content detection
# ---------------------------------------------------------------------------

_BASE64_PATTERN = re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

_LEET_PATTERN = re.compile(r'[4@][5$][5$]|[3][x][3][c]|[5$][h][3][l][l]|[1][gG][n][oO][rR][eE]', re.IGNORECASE)

_SHELL_CMD_PATTERN = re.compile(
    r'\b(rm\s+-rf|chmod|chown|wget|curl\s+.*\|.*sh|nc\s+-|ncat|bash\s+-[ci]|'
    r'python\s+-c|perl\s+-e|ruby\s+-e|powershell|cmd\.exe|/bin/sh|/bin/bash)\b',
    re.IGNORECASE
)

_BINARY_PATTERN = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\xff]')

_INVISIBLE_CHARS_PATTERN = re.compile(r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\u00ad]')

_HIDDEN_PROMPT_PATTERN = re.compile(
    r'(ignore\s+(previous|above|all)\s+instructions?|'
    r'disregard\s+(previous|above|all)\s+instructions?|'
    r'forget\s+(previous|above|all)\s+instructions?|'
    r'you\s+are\s+now\s+|act\s+as\s+if\s+|pretend\s+(you\s+are|to\s+be)|'
    r'new\s+instructions?:|system\s*:\s*|<\s*system\s*>)',
    re.IGNORECASE
)

_SUSPICIOUS_CONTENT_PATTERN = re.compile(
    r'(jailbreak|bypass\s+(safety|filter|restriction)|'
    r'do\s+anything\s+now|dan\s+mode|developer\s+mode\s+enabled)',
    re.IGNORECASE
)


def _is_likely_base64_payload(text: str) -> bool:
    """Check if text contains suspicious base64-encoded content."""
    matches = _BASE64_PATTERN.findall(text)
    for match in matches:
        if len(match) < 20:
            continue
        try:
            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
            if _SHELL_CMD_PATTERN.search(decoded) or _HIDDEN_PROMPT_PATTERN.search(decoded):
                return True
        except Exception:
            pass
    return False


def _sanitize_input(text: str) -> tuple[str, list[str]]:
    """
    Sanitize input text. Returns (sanitized_text, list_of_warnings).
    Raises ValueError if the input should be rejected outright.
    """
    warnings = []

    if not isinstance(text, str):
        raise ValueError("Input must be a string.")

    # Remove invisible/hidden characters
    cleaned = _INVISIBLE_CHARS_PATTERN.sub('', text)
    if cleaned != text:
        warnings.append("Invisible/hidden characters removed from input.")
    text = cleaned

    # Check for binary executables / shell commands
    if _BINARY_PATTERN.search(text):
        raise ValueError("Input contains binary data or non-printable characters and has been rejected.")

    if _SHELL_CMD_PATTERN.search(text):
        raise ValueError("Input contains shell commands and has been rejected.")

    # Check for base64-encoded payloads
    if _is_likely_base64_payload(text):
        raise ValueError("Input contains suspicious base64-encoded content and has been rejected.")

    # Check for hidden/injected prompts
    if _HIDDEN_PROMPT_PATTERN.search(text):
        raise ValueError("Input contains prompt injection patterns and has been rejected.")

    # Check for suspicious jailbreak content
    if _SUSPICIOUS_CONTENT_PATTERN.search(text):
        raise ValueError("Input contains suspicious content and has been rejected.")

    # Check for leetspeak obfuscation
    if _LEET_PATTERN.search(text):
        raise ValueError("Input contains obfuscated (leetspeak) content and has been rejected.")

    return text, warnings


def _sanitize_messages(messages: list[dict]) -> list[dict]:
    """Sanitize all message contents and redact PII before sending to LLM."""
    sanitized = []
    for m in messages:
        content = m.get('content', '')
        if isinstance(content, str):
            # Sanitize for injection / suspicious content
            content, warnings = _sanitize_input(content)
            for w in warnings:
                logger.warning("Input sanitization warning: %s", w)
            # Redact PII before sending to LLM
            content = _redact_pii(content)
        sanitized.append({**m, 'content': content})
    return sanitized


# ---------------------------------------------------------------------------
# Response validation helpers
# ---------------------------------------------------------------------------

_DYNAMIC_EXEC_LINE_PATTERN = re.compile(
    r'^\s*.*\b(eval\s*\(|exec\s*\(|subprocess\s*\(.*shell\s*=\s*True|'
    r'os\.system\s*\(|__import__\s*\(|compile\s*\(|execfile\s*\(|'
    r'Runtime\.exec\s*\(|ProcessBuilder|shell_exec\s*\(|'
    r'system\s*\(|popen\s*\(|passthru\s*\()\s*.*$',
    re.IGNORECASE
)


def _validate_and_sanitize_response(response: str) -> str:
    """
    Validate LLM response and remove lines containing dynamic code-execution
    primitives (eval, exec, subprocess(shell=True), bash eval, JS eval, etc.).
    """
    if not isinstance(response, str):
        return response

    lines = response.splitlines(keepends=True)
    safe_lines = []
    for line in lines:
        if _DYNAMIC_EXEC_LINE_PATTERN.search(line):
            logger.warning(
                "Removed potentially dangerous line from LLM response containing "
                "dynamic code execution primitive."
            )
        else:
            safe_lines.append(line)
    return ''.join(safe_lines)


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

class OpenRouterClient:
    """
    Client for OpenRouter API to access various LLMs.

    SECURITY WARNING: Direct invocation of LLM from the MCP server creates
    security and data exposure risks. Use sampling instead of direct LLM API
    calls to leverage MCP's built-in safety controls.

    Security controls applied:
    - PII redacted from all content sent to LLM
    - PII redacted from all log output
    - Input sanitized and validated for prompt injection, hidden prompts,
      base64 payloads, shell commands, binary data, and leetspeak obfuscation
    - LLM responses validated; dynamic code-execution primitives removed
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

    async def chat(
        self,
        messages: list[dict],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2000
    ) -> str:
        """
        Send chat completion request to OpenRouter.

        All message content is sanitized for prompt injection and suspicious
        content, PII is redacted before sending, and the response is validated
        to remove dynamic code-execution primitives.

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

        # Sanitize inputs and redact PII before sending to LLM
        try:
            sanitized_messages = _sanitize_messages(messages)
        except ValueError as exc:
            logger.warning("Input rejected by security sanitization: %s", exc)
            return f"Request rejected: {exc}"

        # Log with PII redacted — never log raw message content
        redacted_for_log = _redact_messages_for_log(sanitized_messages)
        logger.info(
            "Sending request to OpenRouter",
            extra={
                "model": model or self.model,
                "message_count": len(sanitized_messages),
                "total_content_length": sum(
                    len(m.get("content", "")) for m in sanitized_messages
                ),
                "messages_preview": str(redacted_for_log)[:200]
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
                        "model": model or self.model,
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

                # Validate response: remove dynamic code-execution primitives
                content = _validate_and_sanitize_response(content)

                # Log response length only; redact content preview
                redacted_preview = _redact_pii(content[:200])
                logger.info(
                    "Received response from OpenRouter",
                    extra={
                        "response_length": len(content),
                        "response_preview": redacted_preview
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

        Input is sanitized and PII is redacted before sending to LLM.
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

        Document content is sanitized and PII is redacted before sending to LLM.
        """
        return await self.chat_with_context(
            user_message="Please analyze this document and provide a summary.",
            system_prompt="You are a document analyst. Analyze the provided content and summarize key points.",
            context=content
        )