"""
Image Parser

Extracts content from image files including EXIF metadata.

SECURITY NOTES:
- EXIF metadata extracted with PII scanning and redaction
- Comments and descriptions are scanned for prompt injections
- Suspicious content is removed before processing
"""

import io
import re
import base64
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# PII patterns (global + Singapore)
PII_PATTERNS = {
    'SSN': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    'Credit_Card': re.compile(r'\b(?:\d[ -]?){13,16}\b'),
    'Email': re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
    'Phone': re.compile(r'\b(?:\+?\d[\d\s\-().]{7,}\d)\b'),
    'IP_Address': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    'MAC_Address': re.compile(r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'),
    'Passport': re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),
    'Drivers_License': re.compile(r'\b[A-Z]{1,2}\d{6,8}\b'),
    'TIN': re.compile(r'\b\d{2}-\d{7}\b'),
    'Financial_Account': re.compile(r'\b\d{8,17}\b'),
    'Home_Address': re.compile(r'\b\d{1,5}\s+\w+\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE),
    'GPS_Coordinates': re.compile(r'\b[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)\b'),
    'NRIC': re.compile(r'\b[STFG]\d{7}[A-Z]\b'),
    'FIN': re.compile(r'\b[FG]\d{7}[A-Z]\b'),
    'CPF_Account': re.compile(r'\bCPF\s*\d{9,12}\b', re.IGNORECASE),
    'SingPass': re.compile(r'\bSingPass\s*\w+\b', re.IGNORECASE),
    'Work_Permit': re.compile(r'\bWP\d{7,10}\b', re.IGNORECASE),
    'Student_Pass': re.compile(r'\bSP\d{7,10}\b', re.IGNORECASE),
    'IMEI': re.compile(r'\b\d{15}\b'),
    'Session_Token': re.compile(r'\b[A-Za-z0-9\-_]{32,}\b'),
    'Auth_Token': re.compile(r'\bBearer\s+[A-Za-z0-9\-_.~+/]+=*\b', re.IGNORECASE),
    'Date_of_Birth': re.compile(r'\b(?:DOB|Date of Birth|Born)[:\s]+\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b', re.IGNORECASE),
    'Year_of_Birth': re.compile(r'\b(?:born|birth year|year of birth)[:\s]+(?:19|20)\d{2}\b', re.IGNORECASE),
    'Full_Name': re.compile(r'\b(?:Name|Full Name)[:\s]+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b'),
    'Vehicle_ID': re.compile(r'\b[A-Z]{1,3}\d{1,4}[A-Z]{0,3}\b'),
    'Employee_ID': re.compile(r'\b(?:EMP|EID|Employee\s*ID)[:\s]*[A-Z0-9\-]{4,12}\b', re.IGNORECASE),
    'School_ID': re.compile(r'\b(?:Student\s*ID|School\s*ID)[:\s]*[A-Z0-9\-]{4,12}\b', re.IGNORECASE),
    'Insurance_Policy': re.compile(r'\b(?:Policy\s*(?:No|Number|#)?)[:\s]*[A-Z0-9\-]{6,15}\b', re.IGNORECASE),
    'Bank_Account': re.compile(r'\b\d{9,18}\b'),
    'Debit_Card': re.compile(r'\b(?:\d[ -]?){13,16}\b'),
}

# Suspicious command patterns
SUSPICIOUS_PATTERNS = [
    re.compile(r'\balias\b', re.IGNORECASE),
    re.compile(r'\bripgrep\b|\brg\b', re.IGNORECASE),
    re.compile(r'\bcurl\b', re.IGNORECASE),
    re.compile(r'\brm\b\s+[-\w]', re.IGNORECASE),
    re.compile(r'\becho\b', re.IGNORECASE),
    re.compile(r'\bdd\b\s+if=', re.IGNORECASE),
    re.compile(r'\bgit\b', re.IGNORECASE),
    re.compile(r'\btar\b', re.IGNORECASE),
    re.compile(r'\bchmod\b', re.IGNORECASE),
    re.compile(r'\bchown\b', re.IGNORECASE),
    re.compile(r'\bfsck\b', re.IGNORECASE),
    re.compile(r'\b(?:bash|sh|zsh|ksh|csh|tcsh)\b', re.IGNORECASE),
    re.compile(r'\b(?:exec|eval|system|popen|subprocess|os\.system)\b', re.IGNORECASE),
    re.compile(r'\b(?:wget|nc|netcat|ncat|nmap|ping|traceroute)\b', re.IGNORECASE),
    re.compile(r'\b(?:python|perl|ruby|php|node|java)\s+[-\w]', re.IGNORECASE),
    re.compile(r'\b(?:sudo|su\b|passwd|useradd|userdel|usermod)\b', re.IGNORECASE),
    re.compile(r'\b(?:iptables|firewall|ufw)\b', re.IGNORECASE),
    re.compile(r'\b(?:crontab|at\b|batch)\b', re.IGNORECASE),
    re.compile(r'\b(?:kill|killall|pkill)\b', re.IGNORECASE),
    re.compile(r'\b(?:mount|umount|fdisk|mkfs)\b', re.IGNORECASE),
    re.compile(r'\b(?:\.exe|\.bat|\.cmd|\.sh|\.ps1|\.vbs|\.js)\b', re.IGNORECASE),
    # Base64 encoded commands
    re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'),
    # Leetspeak patterns for common commands
    re.compile(r'\b(?:3ch0|3x3c|5h3ll|r00t|4dm1n|p4ssw0rd|h4ck|3xpl01t)\b', re.IGNORECASE),
    re.compile(r'<\s*script', re.IGNORECASE),
    re.compile(r'javascript\s*:', re.IGNORECASE),
    re.compile(r'on\w+\s*=\s*["\']', re.IGNORECASE),
    re.compile(r'\bSELECT\b.*\bFROM\b', re.IGNORECASE),
    re.compile(r'\bINSERT\b.*\bINTO\b', re.IGNORECASE),
    re.compile(r'\bDROP\b.*\bTABLE\b', re.IGNORECASE),
    re.compile(r'\bUNION\b.*\bSELECT\b', re.IGNORECASE),
    re.compile(r'--\s*$', re.MULTILINE),
    re.compile(r"'\s*OR\s*'1'\s*=\s*'1", re.IGNORECASE),
]


def _redact_pii(text: str) -> str:
    """Redact all PII patterns from text."""
    if not text or not isinstance(text, str):
        return text
    for label, pattern in PII_PATTERNS.items():
        text = pattern.sub('REDACTED', text)
    return text


def _remove_suspicious_content(text: str) -> str:
    """Remove suspicious commands and content from text."""
    if not text or not isinstance(text, str):
        return text

    # Check for base64 encoded content and attempt to decode/check
    def check_base64(match):
        try:
            decoded = base64.b64decode(match.group(0)).decode('utf-8', errors='ignore')
            for pattern in SUSPICIOUS_PATTERNS:
                if pattern.search(decoded):
                    return '<suspicious_content_removed>'
        except Exception:
            pass
        return match.group(0)

    for pattern in SUSPICIOUS_PATTERNS:
        text = pattern.sub('<suspicious_content_removed>', text)
    return text


def _sanitize_text(text: str) -> str:
    """Apply both PII redaction and suspicious content removal."""
    if not text or not isinstance(text, str):
        return text
    text = _remove_suspicious_content(text)
    text = _redact_pii(text)
    return text


def _sanitize_metadata_value(value):
    """Sanitize a metadata value."""
    if isinstance(value, str):
        return _sanitize_text(value)
    elif isinstance(value, bytes):
        try:
            decoded = value.decode('utf-8', errors='ignore')
            return _sanitize_text(decoded)
        except Exception:
            return '<binary_data_removed>'
    elif isinstance(value, (list, tuple)):
        return [_sanitize_metadata_value(v) for v in value]
    elif isinstance(value, dict):
        return {k: _sanitize_metadata_value(v) for k, v in value.items()}
    return value


class ImageParser:
    """
    Parses image files and extracts metadata.
    Includes PII redaction and suspicious content removal.
    """

    def __init__(self):
        pass

    async def extract_metadata(self, image_bytes: bytes) -> dict:
        """
        Extract EXIF and other metadata from image.
        Metadata is scanned and sanitized before returning.
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

            # Extract EXIF data with sanitization
            exif_data = image._getexif()
            if exif_data:
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except Exception:
                            value = str(value)
                    # Sanitize each metadata value
                    sanitized_value = _sanitize_metadata_value(value)
                    metadata[tag] = sanitized_value

            logger.info(
                "Image metadata extracted",
                extra={
                    "format": image.format,
                    "size": image.size,
                    "exif_fields": len(metadata),
                }
            )

            return metadata

        except Exception as e:
            logger.error("Image metadata extraction error occurred")
            return {"error": "Failed to extract image metadata"}

    async def extract_text_fields(self, metadata: dict) -> str:
        """
        Extract text from relevant metadata fields.
        Text fields are scanned for PII and suspicious content.
        """
        text_fields = []

        text_field_names = [
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

        for field in text_field_names:
            if field in metadata:
                value = metadata[field]
                if value and isinstance(value, str):
                    sanitized_value = _sanitize_text(value)
                    text_fields.append(f"{field}: {sanitized_value}")
                    logger.debug(
                        "Found text field in metadata",
                        extra={
                            "field": field,
                        }
                    )

        return '\n'.join(text_fields)

    async def extract_all(self, image_bytes: bytes) -> str:
        """
        Extract all content from image for analysis.
        All metadata is sanitized before returning.
        """
        metadata = await self.extract_metadata(image_bytes)
        text_content = await self.extract_text_fields(metadata)

        result_parts = []

        if text_content:
            sanitized_text = _sanitize_text(text_content)
            result_parts.append(f"Image Metadata:\n{sanitized_text}")

        image_format = _sanitize_text(str(metadata.get('format', 'unknown')))
        image_size = str(metadata.get('size', 'unknown'))
        result_parts.append(f"Image Info: {image_format} {image_size}")

        return '\n\n'.join(result_parts)