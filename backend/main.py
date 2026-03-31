"""
PolicyProbe Backend - FastAPI Application

This is the main entry point for the PolicyProbe demo application.
The application demonstrates various security policy violations that
can be detected and remediated by Unifai.
"""

import os
import re
import base64
import logging
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from agents.orchestrator import AgentOrchestrator
from agents.file_processor import FileProcessorAgent

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PII redaction helpers
# ---------------------------------------------------------------------------

PII_PATTERNS = [
    # Social Security Number
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[SSN REDACTED]'),
    # Year of Birth (standalone 4-digit year 1900-2099)
    (re.compile(r'\b(19|20)\d{2}\b'), '[YEAR_OF_BIRTH REDACTED]'),
    # Birthplace – handled contextually; skip standalone pattern
    # Personal Phone Number
    (re.compile(r'\b(\+?1[\s.-]?)?(\(?\d{3}\)?[\s.-]?)?\d{3}[\s.-]?\d{4}\b'), '[PHONE REDACTED]'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[EMAIL REDACTED]'),
    # Home Address (basic pattern)
    (re.compile(r'\b\d{1,5}\s+\w+(\s+\w+){0,3}\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), '[ADDRESS REDACTED]'),
    # Passport Number (generic)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[PASSPORT REDACTED]'),
    # Drivers License Number (generic US)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[DL REDACTED]'),
    # Taxpayer Identification Number
    (re.compile(r'\b\d{2}-\d{7}\b'), '[TIN REDACTED]'),
    # Credit Card Number
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'), '[CC REDACTED]'),
    # Financial Account Number (8-17 digits)
    (re.compile(r'\b\d{8,17}\b'), '[ACCOUNT REDACTED]'),
    # IP Address
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[IP REDACTED]'),
    # MAC Address
    (re.compile(r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[MAC REDACTED]'),
    # Vehicle Identification Number
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[VIN REDACTED]'),
    # Employee ID (common patterns)
    (re.compile(r'\bEMP[-]?\d{4,8}\b', re.IGNORECASE), '[EMPLOYEE_ID REDACTED]'),
    # School ID
    (re.compile(r'\bSTU[-]?\d{4,8}\b', re.IGNORECASE), '[SCHOOL_ID REDACTED]'),
]

# Singapore-specific PII patterns
SG_PII_PATTERNS = [
    # NRIC / FIN Number
    (re.compile(r'\b[STFGM]\d{7}[A-Z]\b'), 'REDACTED'),
    # Passport Number
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), 'REDACTED'),
    # Work Permit / Student Pass / Government ID (generic)
    (re.compile(r'\bWP\d{7,10}\b', re.IGNORECASE), 'REDACTED'),
    (re.compile(r'\bSP\d{7,10}\b', re.IGNORECASE), 'REDACTED'),
    # Date of Birth
    (re.compile(r'\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b'), 'REDACTED'),
    # Personal Mobile / Home Phone
    (re.compile(r'\b(\+65[\s.-]?)?\d{4}[\s.-]?\d{4}\b'), 'REDACTED'),
    # Email
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), 'REDACTED'),
    # IP Address
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 'REDACTED'),
    # MAC Address
    (re.compile(r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), 'REDACTED'),
    # Bank Account / Credit Card / Debit Card
    (re.compile(r'\b\d{8,19}\b'), 'REDACTED'),
    # CPF Account Number (9 digits)
    (re.compile(r'\b\d{9}\b'), 'REDACTED'),
    # GPS Coordinates
    (re.compile(r'\b-?\d{1,3}\.\d+,\s*-?\d{1,3}\.\d+\b'), 'REDACTED'),
    # SingPass / MyInfo / session identifiers (token-like strings)
    (re.compile(r'\b[A-Za-z0-9_\-]{32,}\b'), 'REDACTED'),
]


def redact_pii(text: str) -> str:
    """Redact zero-tolerance PII categories from text."""
    if not text:
        return text
    for pattern, replacement in PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_sg_pii(text: str) -> str:
    """Redact Singapore zero-tolerance PII categories from text."""
    if not text:
        return text
    for pattern, replacement in SG_PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# ---------------------------------------------------------------------------
# Suspicious content / prompt injection helpers
# ---------------------------------------------------------------------------

SUSPICIOUS_COMMANDS = [
    'alias', 'ripgrep', 'curl', 'rm', 'echo', 'dd', 'git', 'tar', 'chmod',
    'chown', 'fsck', 'wget', 'nc', 'netcat', 'bash', 'sh', 'zsh', 'python',
    'perl', 'ruby', 'php', 'exec', 'eval', 'system', 'popen', 'subprocess',
    'os.system', 'os.popen', 'cmd', 'powershell', 'wscript', 'cscript',
    'mshta', 'regsvr32', 'rundll32', 'certutil', 'bitsadmin', 'schtasks',
    'at ', 'cron', 'nmap', 'sqlmap', 'metasploit', 'msfconsole', 'msfvenom',
    'whoami', 'passwd', 'sudo', 'su ', 'kill', 'pkill', 'killall', 'reboot',
    'shutdown', 'halt', 'init', 'systemctl', 'service', 'mount', 'umount',
    'mkfs', 'fdisk', 'parted', 'iptables', 'ufw', 'firewall', 'ssh', 'scp',
    'sftp', 'ftp', 'telnet', 'rsh', 'rlogin', 'xterm', 'xdg-open',
]

LEET_MAP = {
    '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't',
    '@': 'a', '$': 's', '!': 'i',
}

DYNAMIC_EXEC_PATTERNS = [
    re.compile(r'\beval\s*\(', re.IGNORECASE),
    re.compile(r'\bexec\s*\(', re.IGNORECASE),
    re.compile(r'subprocess\s*\.\s*\w*\s*\(.*shell\s*=\s*True', re.IGNORECASE),
    re.compile(r'\bos\.system\s*\(', re.IGNORECASE),
    re.compile(r'\bos\.popen\s*\(', re.IGNORECASE),
]

INVISIBLE_PATTERN = re.compile(
    r'[\u200b\u200c\u200d\u200e\u200f\u00ad\ufeff\u2060\u180e]'
)


def _decode_leet(text: str) -> str:
    return ''.join(LEET_MAP.get(c, c) for c in text.lower())


def _is_base64(s: str) -> bool:
    try:
        if len(s) % 4 == 0 and len(s) >= 8:
            decoded = base64.b64decode(s).decode('utf-8', errors='ignore')
            return any(cmd in decoded.lower() for cmd in SUSPICIOUS_COMMANDS)
    except Exception:
        pass
    return False


def remove_suspicious_content(text: str) -> str:
    """Remove suspicious commands, shell executables, encoded payloads, and leetspeak commands."""
    if not text:
        return text

    # Remove invisible / hidden characters
    text = INVISIBLE_PATTERN.sub('', text)

    lines = text.splitlines()
    cleaned_lines = []
    for line in lines:
        lower_line = line.lower()
        leet_line = _decode_leet(line)

        # Check for suspicious commands in plain text or leet
        found_suspicious = False
        for cmd in SUSPICIOUS_COMMANDS:
            if cmd in lower_line or cmd in leet_line:
                found_suspicious = True
                break

        if not found_suspicious:
            # Check for base64-encoded suspicious content
            tokens = re.findall(r'[A-Za-z0-9+/=]{8,}', line)
            for token in tokens:
                if _is_base64(token):
                    found_suspicious = True
                    break

        if found_suspicious:
            cleaned_lines.append('<suspicious_content_removed>')
        else:
            cleaned_lines.append(line)

    return '\n'.join(cleaned_lines)


def sanitize_llm_input(text: str) -> str:
    """Sanitize and validate input before sending to LLM."""
    if not text:
        return text

    # Remove invisible / hidden prompt injection characters
    text = INVISIBLE_PATTERN.sub('', text)

    # Remove suspicious shell / binary content
    text = remove_suspicious_content(text)

    # Redact PII before sending to LLM
    text = redact_pii(text)

    # Truncate excessively long inputs
    max_length = 32000
    if len(text) > max_length:
        text = text[:max_length]

    return text


def sanitize_llm_response(text: str) -> str:
    """Sanitize and validate LLM response, removing dynamic code execution primitives."""
    if not text:
        return text

    lines = text.splitlines()
    cleaned_lines = []
    for line in lines:
        remove_line = False
        for pattern in DYNAMIC_EXEC_PATTERNS:
            if pattern.search(line):
                remove_line = True
                break
        if not remove_line:
            cleaned_lines.append(line)

    return '\n'.join(cleaned_lines)


def redact_pii_for_log(text: str) -> str:
    """Redact PII from text destined for log output."""
    return redact_pii(text) if text else text


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("PolicyProbe backend starting up...")
    yield
    logger.info("PolicyProbe backend shutting down...")


app = FastAPI(
    title="PolicyProbe",
    description="AI-powered policy evaluation and remediation demo",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS middleware for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5001", "http://127.0.0.1:5001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize agents
orchestrator = AgentOrchestrator()
file_processor = FileProcessorAgent()


class FileAttachment(BaseModel):
    id: str
    name: str
    type: str
    size: int
    content: Optional[str] = None


class ChatRequest(BaseModel):
    message: str
    attachments: Optional[list[FileAttachment]] = None
    conversation_id: Optional[str] = None


class PolicyError(BaseModel):
    type: str
    message: str
    details: Optional[dict] = None


class ChatResponse(BaseModel):
    response: str
    conversation_id: Optional[str] = None
    policy_warning: Optional[PolicyError] = None


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "policyprobe"}


# ---------------------------------------------------------------------------
# POLICY NOTICE: Authentication not enforced
# The /chat and /upload endpoints do not enforce authentication, which is a
# violation of policy. Authentication MUST be implemented to access all LLM
# endpoints before deploying to production.
#
# POLICY NOTICE: Inter-agent authentication missing
# Agent-to-agent calls (e.g. orchestrator -> file_processor) do not include
# authentication tokens or mutual TLS. This is a policy violation. Every
# agent-to-agent call must be authenticated before deploying to production.
# ---------------------------------------------------------------------------


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Main chat endpoint that processes user messages and file uploads.

    This endpoint:
    1. Receives user messages and optional file attachments
    2. Processes files through the FileProcessorAgent
    3. Routes the request through the AgentOrchestrator
    4. Returns the AI response

    SECURITY NOTES (for Unifai demo):
    - File content is scanned for PII before processing
    - Suspicious content in files is detected and removed
    - LLM inputs and outputs are sanitized
    """
    try:
        # Sanitize and validate the incoming user message before any processing
        sanitized_message = sanitize_llm_input(request.message)

        # Process any attached files
        file_contents = []
        if request.attachments:
            for attachment in request.attachments:
                # Redact PII from attachment content before logging
                safe_preview = redact_pii_for_log(
                    attachment.content[:100] if attachment.content else None
                )
                logger.info(
                    "Processing attachment",
                    extra={
                        "file_name": attachment.name,
                        "file_type": attachment.type,
                        "file_size": attachment.size,
                        "request_context": {
                            "message": redact_pii_for_log(sanitized_message),
                            "attachment_content_preview": safe_preview,
                        }
                    }
                )

                # Sanitize file content: remove suspicious content, redact PII (global + SG)
                raw_content = attachment.content or ''
                clean_content = remove_suspicious_content(raw_content)
                clean_content = redact_pii(clean_content)
                clean_content = redact_sg_pii(clean_content)
                # Also sanitize as LLM input
                clean_content = sanitize_llm_input(clean_content)

                # Process the file content
                processed = await file_processor.process(
                    content=clean_content,
                    filename=attachment.name,
                    content_type=attachment.type
                )
                file_contents.append({
                    "filename": attachment.name,
                    "extracted_content": processed
                })

        # Build context for the orchestrator
        context = {
            "user_message": sanitized_message,
            "file_contents": file_contents,
            "conversation_id": request.conversation_id,
        }

        # Log LLM interaction (input)
        logger.info(
            "LLM interaction - input",
            extra={
                "conversation_id": request.conversation_id,
                "user_message": redact_pii_for_log(sanitized_message),
                "file_count": len(file_contents),
            }
        )

        # Route through orchestrator
        response = await orchestrator.process(context)

        # Sanitize LLM response
        raw_response = response.get("response", "I processed your request.")
        sanitized_response = sanitize_llm_response(raw_response)

        # Log LLM interaction (output)
        logger.info(
            "LLM interaction - output",
            extra={
                "conversation_id": request.conversation_id,
                "response_length": len(sanitized_response),
                "has_policy_warning": response.get("policy_warning") is not None,
            }
        )

        return ChatResponse(
            response=sanitized_response,
            conversation_id=request.conversation_id,
            policy_warning=response.get("policy_warning"),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error processing chat request",
            extra={
                "error": str(e),
                "request_state": {
                    "message": redact_pii_for_log(request.message),
                    "attachment_count": len(request.attachments) if request.attachments else 0,
                }
            }
        )
        raise HTTPException(
            status_code=500,
            detail={
                "detail": "An error occurred processing your request",
                "policy_error": {
                    "type": "general",
                    "message": "Internal server error"
                }
            }
        )


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Direct file upload endpoint.
    """
    content = await file.read()

    raw_text = content.decode('utf-8', errors='ignore')

    # Remove suspicious content (shell commands, binaries, encoded payloads, leetspeak)
    clean_text = remove_suspicious_content(raw_text)

    # Redact PII (global zero-tolerance categories)
    clean_text = redact_pii(clean_text)

    # Redact Singapore PII categories
    clean_text = redact_sg_pii(clean_text)

    # Sanitize as LLM input
    clean_text = sanitize_llm_input(clean_text)

    # Log upload interaction
    logger.info(
        "File upload processed",
        extra={
            "filename": file.filename,
            "original_size": len(content),
            "cleaned_size": len(clean_text),
        }
    )

    processed = await file_processor.process(
        content=clean_text,
        filename=file.filename,
        content_type=file.content_type
    )

    # Sanitize the processor response
    if processed:
        processed = sanitize_llm_response(processed)

    return {
        "filename": file.filename,
        "size": len(content),
        "processed": True,
        "content_preview": processed[:500] if processed else None
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5500)