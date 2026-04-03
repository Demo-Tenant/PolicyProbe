"""
HTML Parser

Extracts text content from HTML files.

SECURITY NOTES (for Unifai demo):
- Extracts text including from hidden elements
- CSS-hidden content is extracted
- Script content may be included
- No XSS sanitization
"""

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# PII patterns for zero-tolerance PII categories
PII_PATTERNS = {
    'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b'),
    'year_of_birth': re.compile(r'\b(19|20)\d{2}\b(?=\s*(birth|born|dob|date of birth))', re.IGNORECASE),
    'phone': re.compile(r'\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
    'email': re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
    'home_address': re.compile(r'\b\d{1,5}\s+\w+(\s+\w+)*\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE),
    'passport': re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),
    'drivers_license': re.compile(r'\b[A-Z]{1,2}\d{5,8}\b|\b\d{7,9}\b'),
    'tin': re.compile(r'\b\d{2}-\d{7}\b'),
    'credit_card': re.compile(r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|3(?:0[0-5]|[68]\d)\d{11}|6(?:011|5\d{2})\d{12})\b'),
    'financial_account': re.compile(r'\b\d{8,17}\b'),
    'ip_address': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    'mac_address': re.compile(r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'),
    'employee_id': re.compile(r'\b(EMP|emp|Employee\s*ID|employee\s*id)[-:\s]?\w{4,10}\b', re.IGNORECASE),
    'school_id': re.compile(r'\b(STU|stu|Student\s*ID|school\s*id)[-:\s]?\w{4,10}\b', re.IGNORECASE),
    'vin': re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'),
    'fine_location': re.compile(r'\b[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)\b'),
}

PII_REDACTION_MAP = {
    'ssn': '[REDACTED-SSN]',
    'year_of_birth': '[REDACTED-YOB]',
    'phone': '[REDACTED-PHONE]',
    'email': '[REDACTED-EMAIL]',
    'home_address': '[REDACTED-ADDRESS]',
    'passport': '[REDACTED-PASSPORT]',
    'drivers_license': '[REDACTED-DL]',
    'tin': '[REDACTED-TIN]',
    'credit_card': '[REDACTED-CC]',
    'financial_account': '[REDACTED-ACCOUNT]',
    'ip_address': '[REDACTED-IP]',
    'mac_address': '[REDACTED-MAC]',
    'employee_id': '[REDACTED-EMPID]',
    'school_id': '[REDACTED-SCHOOLID]',
    'vin': '[REDACTED-VIN]',
    'fine_location': '[REDACTED-LOCATION]',
}


def redact_pii(text: str) -> tuple:
    """
    Scan text for PII and redact any found instances.
    Returns a tuple of (redacted_text, list_of_pii_types_found).
    """
    found_pii = []
    redacted = text
    for pii_type, pattern in PII_PATTERNS.items():
        if pattern.search(redacted):
            found_pii.append(pii_type)
            redacted = pattern.sub(PII_REDACTION_MAP[pii_type], redacted)
    return redacted, found_pii


class HTMLParser:
    """
    Parses HTML files and extracts text content.

    VULNERABILITY: Extracts hidden content without flagging.
    - display:none elements are extracted
    - visibility:hidden elements are extracted
    - Off-screen positioned elements are extracted
    - White text on white background is extracted
    """

    def __init__(self):
        pass

    async def extract_text(self, html_content: str) -> str:
        """
        Extract all text from HTML content.

        VULNERABILITY: All text extracted including hidden content.
        get_text() extracts text from hidden elements.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script and style elements (but not hidden divs!)
            for element in soup(['script', 'style']):
                element.decompose()

            # VULNERABILITY: get_text() extracts from hidden elements too
            # This includes:
            # - Elements with display:none
            # - Elements with visibility:hidden
            # - Off-screen positioned elements
            # - White text on white background
            text = soup.get_text(separator='\n', strip=True)

            # PII redaction
            text, found_pii = redact_pii(text)
            if found_pii:
                logger.warning(
                    "PII detected and redacted from HTML content",
                    extra={"pii_types": found_pii}
                )

            logger.info(
                "HTML text extraction complete",
                extra={
                    "text_length": len(text),
                    # VULNERABILITY: Content preview in logs
                    "preview": text[:100]
                }
            )

            return text

        except Exception as e:
            logger.error(f"HTML extraction error: {e}")
            return f"Error extracting HTML: {str(e)}"

    async def extract_visible_only(self, html_content: str) -> str:
        """
        Extract only visible text (not implemented properly).

        VULNERABILITY: Still extracts hidden content.
        Would need CSS parsing to properly filter.
        """
        # VULNERABILITY: This method doesn't actually filter hidden content
        # It would need to parse inline styles and CSS classes
        return await self.extract_text(html_content)

    async def extract_metadata(self, html_content: str) -> dict:
        """
        Extract HTML metadata (title, meta tags).

        VULNERABILITY: Metadata extracted without scanning.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')
            metadata = {}

            # Title
            title = soup.find('title')
            if title:
                title_text, found_pii = redact_pii(title.get_text())
                if found_pii:
                    logger.warning(
                        "PII detected and redacted from HTML title",
                        extra={"pii_types": found_pii}
                    )
                metadata['title'] = title_text

            # Meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name and content:
                    redacted_content, found_pii = redact_pii(content)
                    if found_pii:
                        logger.warning(
                            "PII detected and redacted from HTML meta tag",
                            extra={"pii_types": found_pii, "meta_name": name}
                        )
                    metadata[name] = redacted_content

            return metadata

        except Exception as e:
            logger.error(f"HTML metadata extraction error: {e}")
            return {}

    async def extract_all(self, html_content: str) -> dict:
        """
        Extract all content from HTML.

        VULNERABILITY: All content extracted without security analysis.
        """
        text = await self.extract_text(html_content)
        metadata = await self.extract_metadata(html_content)

        return {
            "text": text,
            "metadata": metadata,
            "warnings": []  # VULNERABILITY: No warnings generated
        }