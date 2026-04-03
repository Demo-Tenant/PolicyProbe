"""
HTML Parser

Extracts text content from HTML files.

SECURITY NOTES:
- PII detection and redaction applied
- Singapore PII detection and redaction applied
- Suspicious content removal applied
- XSS and injection protections applied
- Hidden content flagged in warnings
"""

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PII / Singapore PII patterns
# ---------------------------------------------------------------------------

PII_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), 'REDACTED'),
    # Year of Birth (standalone 4-digit year 1900-2099)
    (re.compile(r'\b(19|20)\d{2}\b'), 'REDACTED'),
    # Personal Phone Number
    (re.compile(r'\b(\+?\d[\d\s\-().]{7,}\d)\b'), 'REDACTED'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), 'REDACTED'),
    # Home Address (basic street pattern)
    (re.compile(r'\b\d+\s+[A-Za-z0-9\s,\.]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), 'REDACTED'),
    # Passport Number (generic)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), 'REDACTED'),
    # Drivers License Number
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), 'REDACTED'),
    # Taxpayer Identification Number / TIN
    (re.compile(r'\b\d{2}-\d{7}\b'), 'REDACTED'),
    # Credit Card Number
    (re.compile(r'\b(?:\d[ \-]?){13,16}\b'), 'REDACTED'),
    # Financial Account Number
    (re.compile(r'\b\d{8,17}\b'), 'REDACTED'),
    # IP Address
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 'REDACTED'),
    # MAC Address
    (re.compile(r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), 'REDACTED'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), 'REDACTED'),
    # Employee ID / School ID (generic badge patterns)
    (re.compile(r'\b(?:EMP|SCH|STU|EID|SID)[A-Z0-9\-]{4,12}\b', re.IGNORECASE), 'REDACTED'),
]

SINGAPORE_PII_PATTERNS = [
    # Full Name (heuristic: two or more capitalised words)
    (re.compile(r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,4})\b'), 'REDACTED'),
    # NRIC / FIN Number
    (re.compile(r'\b[STFGM]\d{7}[A-Z]\b'), 'REDACTED'),
    # Work Permit / Student Pass / Government ID (generic SG ID)
    (re.compile(r'\b[A-Z]{2}\d{7}\b'), 'REDACTED'),
    # Date of Birth
    (re.compile(r'\b\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}\b'), 'REDACTED'),
    # SingPass / MyInfo / Digital Identity Identifier
    (re.compile(r'\b(?:singpass|myinfo|digitalid)[_\-]?[A-Za-z0-9]{4,}\b', re.IGNORECASE), 'REDACTED'),
    # CPF Account Number
    (re.compile(r'\bCPF[A-Z0-9\-]{6,12}\b', re.IGNORECASE), 'REDACTED'),
    # Insurance Policy Number
    (re.compile(r'\b(?:POL|INS)[A-Z0-9\-]{6,14}\b', re.IGNORECASE), 'REDACTED'),
    # Bank Account Number
    (re.compile(r'\b\d{3}-\d{5,6}-\d{1,3}\b'), 'REDACTED'),
    # GPS Coordinates
    (re.compile(r'\b-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}\b'), 'REDACTED'),
    # IMEI
    (re.compile(r'\b\d{15}\b'), 'REDACTED'),
    # Session / Auth tokens (hex 32+)
    (re.compile(r'\b[0-9a-fA-F]{32,}\b'), 'REDACTED'),
    # Social Media Handles
    (re.compile(r'@[A-Za-z0-9_]{3,30}\b'), 'REDACTED'),
    # Salary patterns
    (re.compile(r'\b(?:salary|income|pay)[:\s]+\$?[\d,]+(?:\.\d{2})?\b', re.IGNORECASE), 'REDACTED'),
    # Email (duplicate for SG context)
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), 'REDACTED'),
    # IP Address
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 'REDACTED'),
    # MAC Address
    (re.compile(r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), 'REDACTED'),
    # Phone numbers
    (re.compile(r'\b(\+?65[\s\-]?)?\d{4}[\s\-]?\d{4}\b'), 'REDACTED'),
]

# ---------------------------------------------------------------------------
# Suspicious content patterns
# ---------------------------------------------------------------------------

SUSPICIOUS_COMMANDS = [
    'alias', 'ripgrep', 'curl', 'rm', 'echo', 'dd', 'git', 'tar',
    'chmod', 'chown', 'fsck', 'wget', 'nc', 'netcat', 'bash', 'sh',
    'python', 'perl', 'ruby', 'php', 'exec', 'eval', 'system',
    'popen', 'subprocess', 'os.system', 'cmd', 'powershell', 'wscript',
    'cscript', 'mshta', 'rundll32', 'regsvr32', 'certutil', 'bitsadmin',
    'schtasks', 'at ', 'cron', 'nmap', 'sqlmap', 'metasploit',
    'msfconsole', 'msfvenom', 'hydra', 'john', 'hashcat', 'aircrack',
    'tcpdump', 'wireshark', 'iptables', 'ufw', 'passwd', 'sudo', 'su ',
    'useradd', 'usermod', 'groupadd', 'mkfs', 'fdisk', 'mount', 'umount',
    'kill', 'killall', 'pkill', 'reboot', 'shutdown', 'halt', 'init',
    'systemctl', 'service', 'crontab', 'at ', 'batch', 'scp', 'sftp',
    'rsync', 'ssh', 'telnet', 'ftp', 'tftp', 'rsh', 'rlogin',
]

LEETSPEAK_MAP = {
    '4': 'a', '@': 'a', '3': 'e', '1': 'i', '!': 'i',
    '0': 'o', '5': 's', '$': 's', '7': 't', '+': 't',
}

SUSPICIOUS_PATTERN = re.compile(
    r'(?:' + '|'.join(re.escape(cmd) for cmd in SUSPICIOUS_COMMANDS) + r')\b',
    re.IGNORECASE
)

BASE64_PATTERN = re.compile(
    r'(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
)

SHELL_METACHAR_PATTERN = re.compile(
    r'(?:&&|\|\||;|\$\(|\`|>\s*/|2>&1|/dev/null|/etc/passwd|/etc/shadow|\.\./'
    r'|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})'
)


def _decode_leetspeak(text: str) -> str:
    result = []
    for ch in text:
        result.append(LEETSPEAK_MAP.get(ch, ch))
    return ''.join(result)


def _is_suspicious_base64(token: str) -> bool:
    try:
        import base64
        decoded = base64.b64decode(token + '==').decode('utf-8', errors='ignore')
        decoded_leet = _decode_leetspeak(decoded.lower())
        if SUSPICIOUS_PATTERN.search(decoded_leet) or SHELL_METACHAR_PATTERN.search(decoded):
            return True
    except Exception:
        pass
    return False


def _remove_suspicious_content(text: str) -> str:
    # Remove shell metacharacters / dangerous patterns
    text = SHELL_METACHAR_PATTERN.sub('<suspicious_content_removed>', text)

    # Remove known suspicious commands
    def _replace_cmd(m):
        return '<suspicious_content_removed>'

    text = SUSPICIOUS_PATTERN.sub(_replace_cmd, text)

    # Remove suspicious base64 blobs
    def _check_b64(m):
        token = m.group(0)
        if _is_suspicious_base64(token):
            return '<suspicious_content_removed>'
        return token

    text = BASE64_PATTERN.sub(_check_b64, text)

    # Check for leetspeak variants of suspicious commands
    decoded_leet = _decode_leetspeak(text.lower())
    if SUSPICIOUS_PATTERN.search(decoded_leet):
        # Replace word-by-word where leetspeak decodes to a command
        words = text.split()
        cleaned = []
        for word in words:
            if SUSPICIOUS_PATTERN.search(_decode_leetspeak(word.lower())):
                cleaned.append('<suspicious_content_removed>')
            else:
                cleaned.append(word)
        text = ' '.join(cleaned)

    return text


def _redact_pii(text: str) -> str:
    for pattern, replacement in PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _redact_singapore_pii(text: str) -> str:
    for pattern, replacement in SINGAPORE_PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _sanitize_content(text: str) -> str:
    """Apply all security sanitization passes."""
    text = _remove_suspicious_content(text)
    text = _redact_pii(text)
    text = _redact_singapore_pii(text)
    return text


class HTMLParser:
    """
    Parses HTML files and extracts text content.

    Security controls applied:
    - Hidden element detection and flagging
    - PII redaction (global and Singapore)
    - Suspicious command/content removal
    - Safe error handling (no raw exception messages exposed)
    """

    def __init__(self):
        pass

    async def extract_text(self, html_content: str) -> str:
        """
        Extract visible text from HTML content with security sanitization.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')

            # Remove script and style elements
            for element in soup(['script', 'style']):
                element.decompose()

            # Detect and flag hidden elements
            hidden_elements_found = []
            for tag in soup.find_all(True):
                style = tag.get('style', '')
                if style:
                    style_lower = style.lower().replace(' ', '')
                    if ('display:none' in style_lower or
                            'visibility:hidden' in style_lower):
                        hidden_elements_found.append(tag.name)
                        tag.decompose()

            text = soup.get_text(separator='\n', strip=True)

            # Apply security sanitization
            text = _sanitize_content(text)

            if hidden_elements_found:
                logger.warning(
                    "Hidden elements detected and removed during HTML extraction",
                    extra={"hidden_tags": hidden_elements_found}
                )

            logger.info(
                "HTML text extraction complete",
                extra={"text_length": len(text)}
            )

            return text

        except Exception as e:
            logger.error("HTML extraction error occurred")
            return "Error extracting HTML content"

    async def extract_visible_only(self, html_content: str) -> str:
        """
        Extract only visible text with security sanitization.
        """
        return await self.extract_text(html_content)

    async def extract_metadata(self, html_content: str) -> dict:
        """
        Extract HTML metadata (title, meta tags) with security sanitization.
        """
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(html_content, 'html.parser')
            metadata = {}

            # Title
            title = soup.find('title')
            if title:
                raw_title = title.get_text()
                metadata['title'] = _sanitize_content(raw_title)

            # Meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', meta.get('property', ''))
                content = meta.get('content', '')
                if name and content:
                    sanitized_name = _sanitize_content(str(name))
                    sanitized_content = _sanitize_content(str(content))
                    metadata[sanitized_name] = sanitized_content

            return metadata

        except Exception as e:
            logger.error("HTML metadata extraction error occurred")
            return {}

    async def extract_all(self, html_content: str) -> dict:
        """
        Extract all content from HTML with full security analysis.
        """
        text = await self.extract_text(html_content)
        metadata = await self.extract_metadata(html_content)

        warnings = []
        if 'REDACTED' in text:
            warnings.append("PII detected and redacted from text content")
        for v in metadata.values():
            if 'REDACTED' in str(v):
                warnings.append("PII detected and redacted from metadata")
                break
        if '<suspicious_content_removed>' in text:
            warnings.append("Suspicious content detected and removed from text")

        return {
            "text": text,
            "metadata": metadata,
            "warnings": warnings
        }