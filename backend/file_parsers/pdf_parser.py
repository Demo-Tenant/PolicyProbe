"""
PDF Parser

Extracts text content from PDF files.

SECURITY NOTES (for Unifai demo):
- Extracts ALL text including hidden/white text
- No detection of suspicious formatting
- No malware scanning
"""

import io
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def redact_pii(text: str) -> str:
    """
    Redact zero-tolerance PII categories from text.
    """
    if not text:
        return text

    # Social Security Number
    text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED SSN]', text)
    text = re.sub(r'\b\d{3}\s\d{2}\s\d{4}\b', '[REDACTED SSN]', text)
    text = re.sub(r'\b\d{9}\b(?=\s|$)', '[REDACTED SSN]', text)

    # Credit Card Number
    text = re.sub(r'\b(?:\d[ -]?){13,16}\b', '[REDACTED CCN]', text)

    # Email addresses
    text = re.sub(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', '[REDACTED EMAIL]', text)

    # Personal Phone Number
    text = re.sub(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', '[REDACTED PHONE]', text)

    # IP Address
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[REDACTED IP]', text)

    # MAC Address
    text = re.sub(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b', '[REDACTED MAC]', text)

    # Passport Number (generic alphanumeric 6-9 chars)
    text = re.sub(r'\b[A-Z]{1,2}[0-9]{6,9}\b', '[REDACTED PASSPORT]', text)

    # Drivers License Number (common US formats)
    text = re.sub(r'\b[A-Z]{1,2}\d{5,8}\b', '[REDACTED DL]', text)

    # Taxpayer Identification Number (EIN format)
    text = re.sub(r'\b\d{2}-\d{7}\b', '[REDACTED TIN]', text)

    # Financial Account Number (8-17 digit sequences)
    text = re.sub(r'\b\d{8,17}\b', '[REDACTED ACCOUNT]', text)

    # Vehicle Identification Number (17 chars alphanumeric)
    text = re.sub(r'\b[A-HJ-NPR-Z0-9]{17}\b', '[REDACTED VIN]', text)

    # Year of Birth patterns (e.g., "born in 1990", "DOB: 1985")
    text = re.sub(r'\b(?:born\s+in|year\s+of\s+birth|dob)[:\s]+\d{4}\b', '[REDACTED YOB]', text, flags=re.IGNORECASE)

    # Home Address (basic pattern: number + street)
    text = re.sub(r'\b\d{1,5}\s+[A-Za-z0-9\s]{3,30}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', '[REDACTED ADDRESS]', text, flags=re.IGNORECASE)

    return text


class PDFParser:
    """
    Parses PDF files and extracts text content.

    VULNERABILITY: Extracts hidden text without flagging it.
    - White text on white background is extracted
    - Zero-size font text is extracted
    - Off-page text is extracted
    - Overlapping layers are all extracted
    """

    def __init__(self):
        pass

    async def extract_text(self, pdf_bytes: bytes) -> str:
        """
        Extract all text from a PDF file.

        VULNERABILITY: All text extracted including hidden content.
        No detection or warning for suspicious formatting.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            text_parts = []
            for page_num, page in enumerate(reader.pages):
                # VULNERABILITY: Extract all text without filtering
                page_text = page.extract_text()
                if page_text:
                    page_text = redact_pii(page_text)
                    text_parts.append(page_text)

                    logger.debug(
                        f"Extracted text from page {page_num + 1}",
                        extra={
                            "page": page_num + 1,
                            "text_length": len(page_text),
                        }
                    )

            full_text = '\n\n'.join(text_parts)

            logger.info(
                "PDF text extraction complete",
                extra={
                    "total_pages": len(reader.pages),
                    "total_text_length": len(full_text)
                }
            )

            return full_text

        except Exception as e:
            logger.error(f"PDF extraction error: {e}")
            return f"Error extracting PDF: {str(e)}"

    async def extract_metadata(self, pdf_bytes: bytes) -> dict:
        """
        Extract PDF metadata.

        VULNERABILITY: Metadata extracted without scanning.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            metadata = {}
            if reader.metadata:
                for key in reader.metadata:
                    metadata[key] = redact_pii(str(reader.metadata[key])) if isinstance(reader.metadata[key], str) else reader.metadata[key]

            return metadata

        except Exception as e:
            logger.error(f"PDF metadata extraction error: {e}")
            return {}

    async def extract_all(self, pdf_bytes: bytes) -> dict:
        """
        Extract all content from PDF.

        VULNERABILITY: All content extracted without security analysis.
        """
        text = await self.extract_text(pdf_bytes)
        metadata = await self.extract_metadata(pdf_bytes)

        return {
            "text": text,
            "metadata": metadata,
            "warnings": []  # VULNERABILITY: No warnings generated
        }