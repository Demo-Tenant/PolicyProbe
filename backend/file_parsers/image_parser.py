"""
Image Parser

Extracts content from image files including EXIF metadata.

SECURITY NOTES (for Unifai demo):
- EXIF metadata extracted without scanning
- Comments and descriptions could contain prompt injections
- No malware detection
"""

import io
import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# PII patterns for zero-tolerance PII categories
PII_PATTERNS = {
    'SSN': re.compile(r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b'),
    'Email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    'Phone': re.compile(r'\b(\+?1?\s?)?(\(?\d{3}\)?[\s.\-]?)(\d{3}[\s.\-]?\d{4})\b'),
    'CreditCard': re.compile(r'\b(?:\d[ -]?){13,16}\b'),
    'PassportNumber': re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),
    'DriversLicense': re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'),
    'TaxpayerID': re.compile(r'\b\d{2}-\d{7}\b'),
    'FinancialAccount': re.compile(r'\b\d{8,17}\b'),
    'IPAddress': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    'MACAddress': re.compile(r'\b([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})\b'),
    'HomeAddress': re.compile(r'\b\d{1,5}\s+\w+\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE),
    'YearOfBirth': re.compile(r'\b(19[0-9]{2}|20[0-2][0-9])\b'),
    'VIN': re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'),
    'FineLocation': re.compile(r'\b-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}\b'),
}


def redact_pii(text: str) -> str:
    """
    Scan text for PII and redact any found instances.
    Returns the redacted text.
    """
    if not text or not isinstance(text, str):
        return text

    redacted = text
    for pii_type, pattern in PII_PATTERNS.items():
        redacted = pattern.sub(f'[REDACTED-{pii_type}]', redacted)

    return redacted


def contains_pii(text: str) -> bool:
    """
    Check if text contains any PII from zero-tolerance categories.
    """
    if not text or not isinstance(text, str):
        return False

    for pii_type, pattern in PII_PATTERNS.items():
        if pattern.search(text):
            return True
    return False


class ImageParser:
    """
    Parses image files and extracts metadata.

    VULNERABILITY: Extracts EXIF data without security scanning.
    - Comment fields could contain prompt injections
    - UserComment could contain malicious instructions
    - ImageDescription could contain attacks
    """

    def __init__(self):
        pass

    async def extract_metadata(self, image_bytes: bytes) -> dict:
        """
        Extract EXIF and other metadata from image.

        VULNERABILITY: Metadata extracted without scanning for threats.
        """
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS

            image = Image.open(io.BytesIO(image_bytes))
            metadata = {}

            # Get basic image info
            metadata['format'] = image.format
            metadata['size'] = image.size
            metadata['mode'] = image.mode

            # Extract EXIF data
            # VULNERABILITY: All EXIF data extracted without filtering
            exif_data = image._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    # Convert bytes to string for JSON serialization
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except:
                            value = str(value)
                    # Redact PII from string metadata values
                    if isinstance(value, str):
                        if contains_pii(value):
                            logger.info(f"PII detected and redacted in EXIF field: {tag}")
                        value = redact_pii(value)
                    metadata[tag] = value

            # VULNERABILITY: Log metadata without scanning
            logger.info(
                "Image metadata extracted",
                extra={
                    "format": image.format,
                    "size": image.size,
                    "exif_fields": len(metadata),
                    # VULNERABILITY: Full metadata in logs
                    "metadata_preview": str(metadata)[:200]
                }
            )

            return metadata

        except Exception as e:
            logger.error(f"Image metadata extraction error: {e}")
            return {"error": str(e)}

    async def extract_text_fields(self, metadata: dict) -> str:
        """
        Extract text from relevant metadata fields.

        VULNERABILITY: Text fields extracted without scanning.
        These fields could contain prompt injections.
        """
        text_fields = []

        # Fields that commonly contain text content
        # VULNERABILITY: These fields could contain malicious prompts
        dangerous_fields = [
            'ImageDescription',
            'XPComment',
            'XPSubject',
            'XPTitle',
            'XPKeywords',
            'UserComment',
            'Comment',
            'Artist',
            'Copyright',
            'Software',
        ]

        for field in dangerous_fields:
            if field in metadata:
                value = metadata[field]
                if value and isinstance(value, str):
                    # Redact PII from text field values
                    if contains_pii(value):
                        logger.info(f"PII detected and redacted in text field: {field}")
                    value = redact_pii(value)
                    text_fields.append(f"{field}: {value}")
                    logger.debug(
                        f"Found text in {field}",
                        extra={
                            "field": field,
                            # VULNERABILITY: Field content logged
                            "value_preview": value[:50]
                        }
                    )

        return '\n'.join(text_fields)

    async def extract_all(self, image_bytes: bytes) -> str:
        """
        Extract all content from image for analysis.

        VULNERABILITY: All metadata including potentially malicious
        content is extracted and returned without filtering.
        """
        metadata = await self.extract_metadata(image_bytes)
        text_content = await self.extract_text_fields(metadata)

        # VULNERABILITY: Combine all content without security checks
        result_parts = []

        if text_content:
            # Redact any PII present in the combined text content
            sanitized_text_content = redact_pii(text_content)
            result_parts.append(f"Image Metadata:\n{sanitized_text_content}")

        image_info = f"Image Info: {metadata.get('format', 'unknown')} {metadata.get('size', 'unknown')}"
        result_parts.append(redact_pii(image_info))

        return '\n\n'.join(result_parts)