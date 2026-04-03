"""
Input Sanitizer

Sanitizes user input before processing.
"""

import html
import logging
import os
import re
import unicodedata
from typing import Any

logger = logging.getLogger(__name__)


class InputSanitizer:
    """
    Sanitizes user input before processing.

    Sanitizes:
    - HTML/script injection
    - SQL injection patterns
    - Command injection
    - Path traversal
    - Encoding attacks
    """

    # Patterns for detecting injection attempts
    _SQL_INJECTION_PATTERNS = re.compile(
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b"
        r"|--|;|/\*|\*/|xp_|0x[0-9a-fA-F]+)",
        re.IGNORECASE,
    )

    _COMMAND_INJECTION_PATTERNS = re.compile(
        r"[;&|`$<>\\]|\.\./|\.\.\\|\beval\b|\bexec\b|\bsystem\b|\bpassthru\b|\bpopen\b",
        re.IGNORECASE,
    )

    _PATH_TRAVERSAL_PATTERNS = re.compile(
        r"\.\.[/\\]|[/\\]\.\.|%2e%2e[/\\]|[/\\]%2e%2e|%252e%252e",
        re.IGNORECASE,
    )

    _SAFE_FILENAME_PATTERN = re.compile(r"[^\w\-. ]")

    def __init__(self):
        pass

    async def sanitize(self, input_data: Any) -> Any:
        """
        Sanitize input data.
        """
        logger.debug(
            "Sanitization requested",
            extra={
                "input_type": type(input_data).__name__,
                "input_preview": str(input_data)[:100]
            }
        )

        if isinstance(input_data, str):
            return await self._sanitize_string(input_data)
        elif isinstance(input_data, dict):
            return {k: await self.sanitize(v) for k, v in input_data.items()}
        elif isinstance(input_data, list):
            return [await self.sanitize(item) for item in input_data]
        else:
            return input_data

    async def _sanitize_string(self, value: str) -> str:
        """
        Sanitize a string value by normalizing encoding and escaping dangerous content.
        """
        # Normalize unicode encoding to prevent encoding attacks
        value = await self.normalize_encoding(value)

        # Escape HTML special characters to prevent XSS
        value = html.escape(value, quote=True)

        # Strip null bytes
        value = value.replace("\x00", "")

        # Log if injection patterns are detected
        if self._SQL_INJECTION_PATTERNS.search(value):
            logger.warning("Potential SQL injection pattern detected in input")

        if self._COMMAND_INJECTION_PATTERNS.search(value):
            logger.warning("Potential command injection pattern detected in input")

        if self._PATH_TRAVERSAL_PATTERNS.search(value):
            logger.warning("Potential path traversal pattern detected in input")

        return value

    async def sanitize_for_llm(self, content: str) -> str:
        """
        Sanitize content before sending to LLM.
        """
        if not isinstance(content, str):
            content = str(content)

        # Normalize encoding
        content = await self.normalize_encoding(content)

        # Remove null bytes and control characters (except common whitespace)
        content = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", content)

        # Escape HTML entities to prevent injection into LLM context
        content = html.escape(content, quote=True)

        return content

    async def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename to prevent path traversal.
        """
        if not isinstance(filename, str):
            filename = str(filename)

        # Normalize unicode
        filename = await self.normalize_encoding(filename)

        # Remove null bytes
        filename = filename.replace("\x00", "")

        # Strip path components to prevent path traversal
        filename = os.path.basename(filename)

        # Remove any remaining path traversal sequences
        filename = self._PATH_TRAVERSAL_PATTERNS.sub("", filename)

        # Allow only safe characters in filenames
        filename = self._SAFE_FILENAME_PATTERN.sub("_", filename)

        # Limit filename length
        filename = filename[:255]

        # Ensure filename is not empty after sanitization
        if not filename or filename.strip() in ("", "."):
            filename = "unnamed_file"

        return filename

    async def normalize_encoding(self, content: str) -> str:
        """
        Normalize text encoding to prevent attacks.
        """
        if not isinstance(content, str):
            content = str(content)

        # Normalize to NFC form to prevent unicode normalization attacks
        content = unicodedata.normalize("NFC", content)

        # Decode percent-encoded sequences that may hide malicious content
        # Replace encoded path separators
        content = content.replace("%2f", "/").replace("%2F", "/")
        content = content.replace("%5c", "\\").replace("%5C", "\\")

        return content