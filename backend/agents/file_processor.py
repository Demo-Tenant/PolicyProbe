"""
File Processor Agent
  
"""

import base64
import logging
import re
from typing import Optional

from file_parsers.pdf_parser import PDFParser
from file_parsers.image_parser import ImageParser
from file_parsers.html_parser import HTMLParser

logger = logging.getLogger(__name__)


def _redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from text."""
    if not text:
        return text

    # Social Security Number
    text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED-SSN]', text)
    text = re.sub(r'\b\d{9}\b', '[REDACTED-SSN]', text)

    # Credit Card Number
    text = re.sub(r'\b(?:\d[ -]?){13,16}\b', '[REDACTED-CCN]', text)

    # Personal Phone Number
    text = re.sub(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', '[REDACTED-PHONE]', text)

    # Email
    text = re.sub(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', '[REDACTED-EMAIL]', text)

    # IP Address
    text = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[REDACTED-IP]', text)

    # MAC Address
    text = re.sub(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b', '[REDACTED-MAC]', text)

    # Passport Number (generic alphanumeric 6-9 chars)
    text = re.sub(r'\b[A-Z]{1,2}\d{6,9}\b', '[REDACTED-PASSPORT]', text)

    # Drivers License Number (common US formats)
    text = re.sub(r'\b[A-Z]{1,2}\d{5,8}\b', '[REDACTED-DL]', text)

    # Taxpayer Identification Number (EIN format)
    text = re.sub(r'\b\d{2}-\d{7}\b', '[REDACTED-TIN]', text)

    # Financial Account Number (8-17 digit sequences)
    text = re.sub(r'\b\d{8,17}\b', '[REDACTED-ACCOUNT]', text)

    # Vehicle Identification Number (17 chars alphanumeric)
    text = re.sub(r'\b[A-HJ-NPR-Z0-9]{17}\b', '[REDACTED-VIN]', text)

    # Year of Birth patterns (e.g., "born in 1985", "DOB: 1990")
    text = re.sub(r'\b(?:born\s+in|year\s+of\s+birth|dob|date\s+of\s+birth)\s*[:\-]?\s*\d{4}\b',
                  '[REDACTED-YOB]', text, flags=re.IGNORECASE)

    # Home Address (basic pattern: number + street)
    text = re.sub(r'\b\d+\s+[A-Za-z]+(?:\s+[A-Za-z]+)*\s+(?:St|Street|Ave|Avenue|Blvd|Boulevard|Rd|Road|Dr|Drive|Ln|Lane|Ct|Court|Way|Pl|Place)\b',
                  '[REDACTED-ADDRESS]', text, flags=re.IGNORECASE)

    # Employee ID patterns
    text = re.sub(r'\b(?:EMP|emp|employee\s*id|employee\s*#)\s*[:\-]?\s*[A-Z0-9]{4,10}\b',
                  '[REDACTED-EMPID]', text, flags=re.IGNORECASE)

    # School ID patterns
    text = re.sub(r'\b(?:student\s*id|school\s*id|student\s*#)\s*[:\-]?\s*[A-Z0-9]{4,10}\b',
                  '[REDACTED-SCHOOLID]', text, flags=re.IGNORECASE)

    return text


class FileProcessorAgent:
    """
    Agent responsible for processing uploaded files.

    Privilege Level: MEDIUM
    Capabilities:
    - Extract text from PDFs
    - Parse HTML content
    - Extract image metadata and text
    - Process Word documents
    """

    PRIVILEGE_LEVEL = "medium"
    SUPPORTED_TYPES = {
        "application/pdf": "pdf",
        "text/html": "html",
        "text/plain": "text",
        "application/json": "json",
        "image/jpeg": "image",
        "image/png": "image",
        "application/msword": "word",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "word",
    }

    def __init__(self):
        self.pdf_parser = PDFParser()
        self.image_parser = ImageParser()
        self.html_parser = HTMLParser()
        self.agent_id = "file_processor"

    async def process(
        self,
        content: Optional[str],
        filename: str,
        content_type: str
    ) -> str:
        """
        Process uploaded file and extract content.

        Args:
            content: File content (text or base64 encoded)
            filename: Original filename
            content_type: MIME type of the file

        Returns:
            Extracted text content from the file
        """
        logger.info(
            "Processing file",
            extra={
                "file_name": filename,
                "file_type": content_type,
                "content_length": len(content) if content else 0,
            }
        )

        if not content:
            return f"Empty file: {filename}"

        # Determine file type
        file_type = self._get_file_type(content_type, filename)

        # Process based on file type
        try:
            if file_type == "pdf":
                extracted = await self._process_pdf(content)
            elif file_type == "html":
                extracted = await self._process_html(content)
            elif file_type == "image":
                extracted = await self._process_image(content)
            elif file_type == "json":
                extracted = await self._process_json(content)
            elif file_type == "text":
                extracted = content  # Direct text, no processing needed
            else:
                extracted = f"Unsupported file type: {content_type}"

            # Redact PII from extracted content
            extracted = _redact_pii(extracted)

            logger.info(
                "File processing complete",
                extra={
                    "file_name": filename,
                    "extracted_length": len(extracted),
                }
            )

            return extracted

        except Exception as e:
            logger.error(
                "Error processing file",
                extra={
                    "file_name": filename,
                    "error": str(e),
                }
            )
            return f"Error processing {filename}: {str(e)}"

    def _get_file_type(self, content_type: str, filename: str) -> str:
        """Determine file type from MIME type or extension."""
        # Check MIME type first
        if content_type in self.SUPPORTED_TYPES:
            return self.SUPPORTED_TYPES[content_type]

        # Fall back to extension
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        extension_map = {
            'pdf': 'pdf',
            'html': 'html',
            'htm': 'html',
            'txt': 'text',
            'json': 'json',
            'jpg': 'image',
            'jpeg': 'image',
            'png': 'image',
            'doc': 'word',
            'docx': 'word',
        }

        return extension_map.get(ext, 'unknown')

    async def _process_pdf(self, content: str) -> str:
        """
        Process PDF file content.
        """
        # Content is base64 encoded for PDFs
        try:
            pdf_bytes = base64.b64decode(content)
            extracted_text = await self.pdf_parser.extract_text(pdf_bytes)

            return extracted_text
        except Exception as e:
            logger.error(f"PDF processing error: {e}")
            return f"Error processing PDF: {str(e)}"

    async def _process_html(self, content: str) -> str:
        """
        Process HTML content.
        """
        try:
            extracted_text = await self.html_parser.extract_text(content)

            return extracted_text
        except Exception as e:
            logger.error(f"HTML processing error: {e}")
            return f"Error processing HTML: {str(e)}"

    async def _process_image(self, content: str) -> str:
        """
        Process image file.
        """
        try:
            image_bytes = base64.b64decode(content)

            # Extract both visual text (OCR) and metadata
            extracted = await self.image_parser.extract_all(image_bytes)

            return extracted
        except Exception as e:
            logger.error(f"Image processing error: {e}")
            return f"Error processing image: {str(e)}"

    async def _process_json(self, content: str) -> str:
        """
        Process JSON content.
        """
        import json

        try:
            # Parse to validate JSON
            data = json.loads(content)

            # Convert back to formatted string for analysis
            formatted = json.dumps(data, indent=2)

            return f"JSON Content:\n{formatted}"
        except json.JSONDecodeError as e:
            return f"Invalid JSON: {str(e)}\n\nRaw content:\n{content}"

    async def validate_file(self, content: str, filename: str) -> dict:
        """
        Validate file before processing.
        """
        # Basic validation only
        validation_result = {
            "valid": True,
            "filename": filename,
            "size": len(content) if content else 0,
            "warnings": []
        }

        # Size check
        if len(content) > 10 * 1024 * 1024:  # 10MB
            validation_result["warnings"].append("Large file - processing may be slow")

        # Check for PII in content
        if content:
            redacted = _redact_pii(content)
            if redacted != content:
                validation_result["warnings"].append("File contains PII which will be redacted during processing")

        return validation_result