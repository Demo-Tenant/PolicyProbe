"""
PDF Parser

Extracts text content from PDF files.

SECURITY NOTES:
- PII detection and redaction enabled
- Singapore PII detection and redaction enabled
- Suspicious content removal enabled
- Security vulnerabilities addressed
"""

import io
import re
import base64
import logging
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PII patterns (global zero-tolerance list)
# ---------------------------------------------------------------------------
PII_PATTERNS = [
    (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN'),
    (r'\b\d{9}\b', 'SSN_COMPACT'),
    (r'\b(19|20)\d{2}\b', 'YEAR_OF_BIRTH'),
    (r'\b[A-Z][a-z]+,\s*[A-Z][a-z]+\b', 'BIRTHPLACE'),
    (r'\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b', 'PHONE'),
    (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', 'EMAIL'),
    (r'\b\d{1,5}\s+\w+(\s+\w+)*\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', 'HOME_ADDRESS'),
    (r'\b[A-Z]{1,2}\d{6,9}\b', 'PASSPORT_NUMBER'),
    (r'\b[A-Z]{1,2}\d{5,8}\b', 'DRIVERS_LICENSE'),
    (r'\b\d{2}-\d{7}\b', 'TIN'),
    (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b', 'CREDIT_CARD'),
    (r'\b\d{8,17}\b', 'FINANCIAL_ACCOUNT'),
    (r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b', 'MAC_ADDRESS'),
    (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'IP_ADDRESS'),
    (r'\b\d{17}\b', 'VIN'),
    (r'(?i)\b(fingerprint|retina scan|iris scan|voice signature|facial image|medical record|employee\s*id|school\s*id|ethnicity|sexual orientation)\b', 'SENSITIVE_CATEGORY'),
    (r'(?i)\b(fine location|precise location|gps coordinates)\b', 'FINE_LOCATION'),
]

# ---------------------------------------------------------------------------
# Singapore PII patterns
# ---------------------------------------------------------------------------
SG_PII_PATTERNS = [
    (r'\b[STFGM]\d{7}[A-Z]\b', 'NRIC_FIN'),
    (r'\b[A-Z]{1,2}\d{6,9}\b', 'PASSPORT'),
    (r'\bWP\d{7}\b', 'WORK_PERMIT'),
    (r'\bSP\d{7}\b', 'STUDENT_PASS'),
    (r'\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b', 'DATE_OF_BIRTH'),
    (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', 'EMAIL'),
    (r'\b(\+?65[-.\s]?)?\d{4}[-.\s]?\d{4}\b', 'SG_PHONE'),
    (r'\b\d{1,5}\s+\w+(\s+\w+)*\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Crescent|Cres|Close|Cl|Walk|Link|View|Rise|Grove|Park|Gardens|Heights|Hill|Mount|Terrace|Tce)\b', 'ADDRESS'),
    (r'(?i)\b(singpass|myinfo|digital identity)\b', 'DIGITAL_ID'),
    (r'(?i)\b(biometric|fingerprint|facial image|voice signature|iris scan|retina scan)\b', 'BIOMETRIC'),
    (r'(?i)\b(health record|medical history|disability|insurance policy)\b', 'HEALTH'),
    (r'\b\d{3}-\d{6}-\d{1}\b', 'BANK_ACCOUNT'),
    (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', 'CREDIT_CARD'),
    (r'\bCPF\d{7,10}\b', 'CPF_ACCOUNT'),
    (r'\b[A-Z]\d{9}[A-Z]\b', 'TAX_ID'),
    (r'(?i)\b(employee\s*id|performance review|disciplinary record)\b', 'EMPLOYMENT'),
    (r'(?i)\b(academic record|education transcript|professional certification|student\s*id|school\s*id)\b', 'ACADEMIC'),
    (r'(?i)\b(sexual orientation|marital status|ethnicity|race|religion|political affiliation|voting preference)\b', 'SENSITIVE_CATEGORY'),
    (r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b', 'MAC_ADDRESS'),
    (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'IP_ADDRESS'),
    (r'(?i)\b(imei|imsi|device identifier)\b', 'DEVICE_ID'),
    (r'(?i)\b(browsing history|search quer|chat log|call recording|call metadata)\b', 'DIGITAL_ACTIVITY'),
    (r'(?i)\b(social media handle|account username|login identifier|authentication token|session identifier)\b', 'ACCOUNT_ID'),
    (r'(?i)\b(nationality|place of birth)\b', 'NATIONALITY'),
    (r'(?i)\b(salary|income tax|cpf|financial transaction)\b', 'FINANCIAL'),
    (r'(?i)\bfull name\b', 'FULL_NAME'),
    (r'(?i)\b(wi-fi triangulation|gps coordinates|precise location)\b', 'LOCATION'),
]

# ---------------------------------------------------------------------------
# Suspicious content patterns
# ---------------------------------------------------------------------------
SUSPICIOUS_COMMANDS = [
    r'\balias\b',
    r'\bripgrep\b',
    r'\bcurl\b',
    r'\brm\b',
    r'\becho\b',
    r'\bdd\b',
    r'\bgit\b',
    r'\btar\b',
    r'\bchmod\b',
    r'\bchown\b',
    r'\bfsck\b',
    r'\bsudo\b',
    r'\bwget\b',
    r'\bnc\b',
    r'\bnetcat\b',
    r'\bpython\b',
    r'\bperl\b',
    r'\bruby\b',
    r'\bphp\b',
    r'\bbash\b',
    r'\bsh\b',
    r'\bzsh\b',
    r'\bpowershell\b',
    r'\bcmd\b',
    r'\bexec\b',
    r'\beval\b',
    r'\bsystem\b',
    r'\bpasswd\b',
    r'\bssh\b',
    r'\bscp\b',
    r'\bftp\b',
    r'\btelnet\b',
    r'\bnmap\b',
    r'\bping\b',
    r'\bifconfig\b',
    r'\bnetstat\b',
    r'\bps\b',
    r'\bkill\b',
    r'\bkillall\b',
    r'\bwhoami\b',
    r'\buname\b',
    r'\bcat\b',
    r'\bls\b',
    r'\bfind\b',
    r'\bgrep\b',
    r'\bawk\b',
    r'\bsed\b',
    r'\bxargs\b',
    r'\bmkdir\b',
    r'\btouch\b',
    r'\bcp\b',
    r'\bmv\b',
    r'\bln\b',
    r'\bchroot\b',
    r'\bmount\b',
    r'\bumount\b',
    r'\bcrontab\b',
    r'\bat\b',
    r'\bjobs\b',
    r'\bbg\b',
    r'\bfg\b',
    r'\bnohup\b',
    r'\bscreen\b',
    r'\btmux\b',
    r'\benv\b',
    r'\bexport\b',
    r'\bset\b',
    r'\bunset\b',
    r'\bsource\b',
    r'\b\.\s*/',
    r'\.exe\b',
    r'\.bat\b',
    r'\.cmd\b',
    r'\.sh\b',
    r'\.ps1\b',
    r'\.vbs\b',
    r'\.dll\b',
    r'\.so\b',
    r'/bin/',
    r'/etc/',
    r'/usr/',
    r'/var/',
    r'/tmp/',
    r'C:\\Windows',
    r'C:\\System',
    r'\$\(',
    r'`[^`]+`',
    r'&&',
    r'\|\|',
    r';\s*\w+',
    r'>\s*/dev/',
    r'<\s*/dev/',
]

LEETSPEAK_PATTERN = re.compile(
    r'\b[3e][xX][3e][cC]\b|'
    r'\b[5s][yY][5s][tT][3e][mM]\b|'
    r'\b[5s][hH][3e][lL][lL]\b|'
    r'\b[cC][uU][rR][lL]\b|'
    r'\b[rR][mM]\b|'
    r'\b[pP][hH][pP]\b'
)

BASE64_PATTERN = re.compile(r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

SUSPICIOUS_PATTERN = re.compile(
    '|'.join(SUSPICIOUS_COMMANDS),
    re.IGNORECASE
)


def _redact_pii(text: str) -> str:
    """Redact global zero-tolerance PII from text."""
    for pattern, label in PII_PATTERNS:
        text = re.sub(pattern, 'REDACTED', text, flags=re.IGNORECASE)
    return text


def _redact_sg_pii(text: str) -> str:
    """Redact Singapore PII from text."""
    for pattern, label in SG_PII_PATTERNS:
        text = re.sub(pattern, 'REDACTED', text, flags=re.IGNORECASE)
    return text


def _is_suspicious_base64(token: str) -> bool:
    """Check if a base64 token decodes to suspicious content."""
    try:
        decoded = base64.b64decode(token + '==').decode('utf-8', errors='ignore')
        if SUSPICIOUS_PATTERN.search(decoded):
            return True
    except Exception:
        pass
    return False


def _remove_suspicious_content(text: str) -> str:
    """Remove suspicious commands, executables, shell commands, binaries, leetspeak, and base64-encoded commands."""
    # Remove base64-encoded suspicious content
    def replace_base64(match):
        token = match.group(0)
        if _is_suspicious_base64(token):
            return '<suspicious_content_removed>'
        return token

    text = BASE64_PATTERN.sub(replace_base64, text)

    # Remove leetspeak suspicious content
    text = LEETSPEAK_PATTERN.sub('<suspicious_content_removed>', text)

    # Remove suspicious commands and patterns
    text = SUSPICIOUS_PATTERN.sub('<suspicious_content_removed>', text)

    return text


def _sanitize_text(text: str) -> str:
    """Apply all security sanitization steps to extracted text."""
    text = _remove_suspicious_content(text)
    text = _redact_pii(text)
    text = _redact_sg_pii(text)
    return text


class PDFParser:
    """
    Parses PDF files and extracts text content.
    Includes PII redaction, Singapore PII redaction, and suspicious content removal.
    """

    def __init__(self):
        pass

    async def extract_text(self, pdf_bytes: bytes) -> str:
        """
        Extract all text from a PDF file with PII redaction and suspicious content removal.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            text_parts = []
            for page_num, page in enumerate(reader.pages):
                page_text = page.extract_text()
                if page_text:
                    sanitized_text = _sanitize_text(page_text)
                    text_parts.append(sanitized_text)

                    logger.debug(
                        "Extracted and sanitized text from page",
                        extra={
                            "page": page_num + 1,
                            "text_length": len(sanitized_text),
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
            logger.error("PDF extraction error occurred")
            return "Error extracting PDF content"

    async def extract_metadata(self, pdf_bytes: bytes) -> dict:
        """
        Extract PDF metadata with PII redaction applied.
        """
        try:
            from PyPDF2 import PdfReader

            pdf_file = io.BytesIO(pdf_bytes)
            reader = PdfReader(pdf_file)

            metadata = {}
            if reader.metadata:
                for key in reader.metadata:
                    raw_value = reader.metadata[key]
                    if isinstance(raw_value, str):
                        sanitized_value = _sanitize_text(raw_value)
                    else:
                        sanitized_value = raw_value
                    safe_key = re.sub(r'[^A-Za-z0-9_\-]', '_', str(key))
                    metadata[safe_key] = sanitized_value

            return metadata

        except Exception as e:
            logger.error("PDF metadata extraction error occurred")
            return {}

    async def extract_all(self, pdf_bytes: bytes) -> dict:
        """
        Extract all content from PDF with security sanitization applied.
        """
        text = await self.extract_text(pdf_bytes)
        metadata = await self.extract_metadata(pdf_bytes)

        return {
            "text": text,
            "metadata": metadata,
            "warnings": [
                "Content has been scanned and sanitized for PII and suspicious content."
            ]
        }