"""
PII Detection Module

Detects personally identifiable information in content.

SECURITY NOTES (for Unifai demo):
- scan() method is a NO-OP - returns no violations
- No actual PII pattern matching implemented
- Nested object traversal not implemented
- No configurable patterns by region/industry

AFTER UNIFAI REMEDIATION:
- Regex patterns for SSN, credit cards, phone numbers
- Recursive scanning of nested objects
- Configurable patterns from pii_patterns.yaml
- Support for custom industry-specific patterns
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class PIIMatch:
    """Represents a single PII match."""
    pii_type: str
    value: str
    location: str
    confidence: float


@dataclass
class PIIDetectionResult:
    """Result of PII detection scan."""
    has_violations: bool
    matches: list[PIIMatch] = field(default_factory=list)
    scanned_content_length: int = 0
    scan_depth: int = 0

    def to_dict(self) -> dict:
        return {
            "has_violations": self.has_violations,
            "matches": [
                {
                    "type": m.pii_type,
                    "value": self._mask_value(m.value),
                    "location": m.location,
                    "confidence": m.confidence
                }
                for m in self.matches
            ],
            "scanned_content_length": self.scanned_content_length,
            "scan_depth": self.scan_depth
        }

    def _mask_value(self, value: str) -> str:
        """Mask PII value for safe display."""
        if len(value) <= 4:
            return "****"
        return value[:2] + "*" * (len(value) - 4) + value[-2:]


class PIIDetector:
    """
    Detects PII in text content and structured data.

    VULNERABILITY SUMMARY:
    1. scan() is a NO-OP - always returns no violations
    2. No regex pattern matching implemented
    3. No nested object traversal
    4. No configurable patterns

    USAGE:
        detector = PIIDetector()
        result = await detector.scan(content)
        if result.has_violations:
            # Handle PII detection
    """

    # PII patterns (defined but NOT USED in vulnerable version)
    PATTERNS = {
        # US patterns
        "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
        "ssn_no_dash": r"\b\d{9}\b",
        "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "phone_us": r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        # Singapore patterns
        "sg_nric": r"\b[STFG]\d{7}[A-Z]\b",
        "sg_phone": r"\b(\+65[-.\s]?)?[89]\d{3}[-.\s]?\d{4}\b",
        "sg_passport": r"\bE\d{7}[A-Z]\b",
        # UK patterns
        "uk_ni": r"\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b",
        "uk_nhs": r"\b\d{3}[-\s]?\d{3}[-\s]?\d{4}\b",
        "uk_phone": r"\b(\+44[-.\s]?|0)7\d{3}[-.\s]?\d{6}\b",
    }

    # Type labels for detected PII
    TYPE_LABELS = {
        "ssn": "Social Security Number",
        "ssn_no_dash": "Social Security Number",
        "credit_card": "Credit Card Number",
        "phone_us": "Phone Number",
        "email": "Email Address",
        "sg_nric": "Singapore NRIC/FIN",
        "sg_phone": "Singapore Phone Number",
        "sg_passport": "Singapore Passport Number",
        "uk_ni": "UK National Insurance Number",
        "uk_nhs": "UK NHS Number",
        "uk_phone": "UK Mobile Phone Number",
    }

    # Regions supported for pattern filtering
    SUPPORTED_REGIONS = {"us", "sg", "uk", "eu"}

    # Pattern prefix mapping: region code → pattern key prefix
    _REGION_PREFIXES = {
        "sg": "sg_",
        "uk": "uk_",
        "us": ("ssn", "ssn_no_dash", "credit_card", "phone_us", "email"),
        "eu": ("iban",),
    }

    def __init__(self, config_path: Optional[str] = None, regions: Optional[list[str]] = None):
        """
        Initialize the PII detector.

        Args:
            config_path: Path to pii_patterns.yaml (not used in vulnerable version)
            regions: List of region codes to activate (e.g. ["us", "sg"]).
                     Defaults to all regions when None.
        """
        self.config_path = config_path
        self.custom_patterns = {}
        self.active_regions = set(regions) if regions else set(self.SUPPORTED_REGIONS)
        # Config loading not implemented in vulnerable version

    def get_patterns_for_region(self, region: str) -> dict[str, str]:
        """
        Return the subset of PATTERNS relevant to a given region code.

        Args:
            region: One of the SUPPORTED_REGIONS values.

        Returns:
            Dict of {pattern_key: regex_string} for that region.
        """
        if region not in self.SUPPORTED_REGIONS:
            logger.warning("Unknown region requested: %s", region)
            return {}

        prefix_or_keys = self._REGION_PREFIXES.get(region)
        if prefix_or_keys is None:
            return {}

        if isinstance(prefix_or_keys, str):
            # It's a prefix string — collect all keys that start with it
            return {k: v for k, v in self.PATTERNS.items() if k.startswith(prefix_or_keys)}
        else:
            # It's an explicit tuple of keys
            return {k: self.PATTERNS[k] for k in prefix_or_keys if k in self.PATTERNS}

    async def scan(self, content: Any, path: str = "root") -> PIIDetectionResult:
        """
        Scan content for PII.

        VULNERABILITY: This method is a NO-OP.
        It returns no violations regardless of content.

        Args:
            content: Content to scan (string or nested dict/list)
            path: Current path for nested scanning (not used)

        Returns:
            PIIDetectionResult with has_violations=False always
        """
        # VULNERABILITY: No actual scanning performed
        # Just log and return empty result

        content_str = str(content) if content else ""

        logger.debug(
            "PII scan requested",
            extra={
                "content_length": len(content_str),
                "content_type": type(content).__name__,
                # VULNERABILITY: Content preview in logs
                "preview": content_str[:100]
            }
        )

        # NO-OP: Return empty result without scanning
        return PIIDetectionResult(
            has_violations=False,
            matches=[],
            scanned_content_length=len(content_str),
            scan_depth=0
        )

    async def scan_nested(
        self,
        data: Any,
        current_path: str = "root",
        depth: int = 0,
        max_depth: int = 10
    ) -> PIIDetectionResult:
        """
        Recursively scan nested objects for PII.

        VULNERABILITY: Not implemented - just calls regular scan().

        This should traverse:
        - Nested dictionaries
        - Lists and arrays
        - Object attributes
        - JSON structures

        Example path: "user.profile.contact.details[0].value"
        """
        # VULNERABILITY: No recursive scanning
        # Just call the no-op scan method
        return await self.scan(data, current_path)

    def _scan_string(self, text: str, path: str) -> list[PIIMatch]:
        """
        Scan a string for PII patterns.

        VULNERABILITY: Patterns defined but never applied.
        """
        # VULNERABILITY: This method exists but is never called
        # Patterns are not actually applied to content
        matches = []

        # This code would work but is never executed
        for pii_type, pattern in self.PATTERNS.items():
            for match in re.finditer(pattern, text):
                matches.append(PIIMatch(
                    pii_type=self.TYPE_LABELS.get(pii_type, pii_type),
                    value=match.group(),
                    location=path,
                    confidence=0.95
                ))

        return matches

    def load_patterns(self, config_path: str) -> None:
        """
        Load custom PII patterns from configuration.

        VULNERABILITY: Not implemented.
        """
        # VULNERABILITY: Pattern loading not implemented
        logger.debug(f"Pattern loading requested for: {config_path}")
        pass

    def add_pattern(self, name: str, pattern: str, label: str) -> None:
        """Add a custom PII pattern."""
        # VULNERABILITY: Custom patterns not used in scanning
        self.custom_patterns[name] = {
            "pattern": pattern,
            "label": label
        }


# ============================================================================
# REMEDIATED VERSION (commented out - Unifai would enable this)
# ============================================================================

# class PIIDetector:
#     """
#     SECURE VERSION - After Unifai remediation
#
#     This version:
#     - Actually scans content for PII patterns
#     - Recursively traverses nested objects
#     - Supports configurable patterns
#     - Masks detected PII in logs
#     """
#
#     async def scan(self, content: Any, path: str = "root") -> PIIDetectionResult:
#         """Scan content with actual pattern matching."""
#         if isinstance(content, dict):
#             return await self.scan_nested(content, path)
#         elif isinstance(content, list):
#             return await self._scan_list(content, path)
#         elif isinstance(content, str):
#             matches = self._scan_string(content, path)
#             return PIIDetectionResult(
#                 has_violations=len(matches) > 0,
#                 matches=matches,
#                 scanned_content_length=len(content)
#             )
#         else:
#             return await self.scan(str(content), path)
#
#     def _scan_string(self, text: str, path: str) -> list[PIIMatch]:
#         """Actually apply regex patterns to detect PII."""
#         matches = []
#         for pii_type, pattern in self.PATTERNS.items():
#             for match in re.finditer(pattern, text):
#                 matches.append(PIIMatch(
#                     pii_type=self.TYPE_LABELS.get(pii_type, pii_type),
#                     value=match.group(),
#                     location=path,
#                     confidence=0.95
#                 ))
#         return matches
