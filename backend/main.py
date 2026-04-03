"""
PolicyProbe Backend - FastAPI Application

This is the main entry point for the PolicyProbe demo application.
The application demonstrates various security policy violations that
can be detected and remediated by Unifai.
"""

import os
import re
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / '.env'
load_dotenv(env_path)

import logging
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


# PII detection patterns for zero-tolerance PII categories
PII_PATTERNS = {
    "Social Security Number": re.compile(r'\b\d{3}-\d{2}-\d{4}\b|\b\d{9}\b'),
    "Personal Phone Number": re.compile(r'\b(\+?1[-.\s]?)?(\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b'),
    "Email": re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
    "Home Address": re.compile(r'\b\d{1,5}\s+\w+(\s+\w+)*\s+(Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE),
    "Passport Number": re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),
    "Drivers License Number": re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'),
    "Taxpayer Identification Number": re.compile(r'\b\d{2}-\d{7}\b'),
    "Credit Card Number": re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
    "Financial Account Number": re.compile(r'\b\d{8,17}\b'),
    "IP Address": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    "MAC Address": re.compile(r'\b([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'),
    "Vehicle Identification Number": re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'),
    "Year of Birth": re.compile(r'\b(born|dob|date of birth|birth year)[:\s]+\d{4}\b', re.IGNORECASE),
    "Birthplace": re.compile(r'\b(born in|birthplace|place of birth)[:\s]+[A-Za-z\s,]+\b', re.IGNORECASE),
    "Mother\'s Maiden Name": re.compile(r'\b(mother\'?s?\s+maiden\s+name)[:\s]+[A-Za-z\s]+\b', re.IGNORECASE),
    "Employee Id": re.compile(r'\b(employee\s+id|emp\s+id)[:\s]+[A-Za-z0-9\-]+\b', re.IGNORECASE),
    "School Id": re.compile(r'\b(school\s+id|student\s+id)[:\s]+[A-Za-z0-9\-]+\b', re.IGNORECASE),
    "Fine Location": re.compile(r'\b(latitude|longitude|lat|lon|lng)[:\s]+[-+]?\d{1,3}\.\d+\b', re.IGNORECASE),
    "Ethnicity": re.compile(r'\b(ethnicity|ethnic\s+group|race)[:\s]+[A-Za-z\s]+\b', re.IGNORECASE),
    "Sexual Orientation": re.compile(r'\b(sexual\s+orientation|sexuality)[:\s]+[A-Za-z\s]+\b', re.IGNORECASE),
    "Medical Records": re.compile(r'\b(diagnosis|medical\s+record|patient\s+id|prescription|icd[-\s]?\d+)\b', re.IGNORECASE),
}

AGENT_AUTH_TOKEN = os.environ.get("AGENT_AUTH_TOKEN", "")


def check_and_redact_pii(content: str) -> tuple[str, list[str]]:
    """
    Check content for PII and redact any found instances.
    Returns a tuple of (redacted_content, list_of_pii_types_found).
    """
    if not content:
        return content, []

    detected_pii_types = []
    redacted_content = content

    for pii_type, pattern in PII_PATTERNS.items():
        if pattern.search(redacted_content):
            detected_pii_types.append(pii_type)
            redacted_content = pattern.sub(f"[REDACTED:{pii_type}]", redacted_content)

    return redacted_content, detected_pii_types


def verify_agent_auth_token(token: Optional[str]) -> bool:
    """
    Verify the inter-agent authentication token.
    Returns True if the token is valid, False otherwise.
    """
    if not AGENT_AUTH_TOKEN:
        logger.warning(
            "POLICY VIOLATION: Inter-agent authentication is not configured. "
            "You must implement authentication for every agent-to-agent call. "
            "Set the AGENT_AUTH_TOKEN environment variable and pass it with every agent interaction."
        )
        return False
    return token == AGENT_AUTH_TOKEN


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info("PolicyProbe backend starting up...")
    if not AGENT_AUTH_TOKEN:
        logger.warning(
            "POLICY VIOLATION: AGENT_AUTH_TOKEN is not set. "
            "Missing inter-agent authentication is a policy violation. "
            "You must implement authentication for every agent-to-agent call."
        )
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
    agent_auth_token: Optional[str] = None


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
    - File content is not scanned for PII before processing
    - Hidden content in files is not detected
    - Agent calls are not authenticated
    """
    # Enforce inter-agent authentication
    if not verify_agent_auth_token(request.agent_auth_token):
        logger.warning(
            "POLICY VIOLATION: Missing or invalid inter-agent authentication token. "
            "You must implement authentication for every agent-to-agent call."
        )
        raise HTTPException(
            status_code=401,
            detail={
                "detail": "Inter-agent authentication is required and missing or invalid. "
                          "This is a policy violation: you must implement authentication "
                          "for every agent-to-agent call.",
                "policy_error": {
                    "type": "authentication",
                    "message": "Missing inter-agent authentication is a policy violation. "
                               "Implement authentication for every agent-to-agent call."
                }
            }
        )

    try:
        # Process any attached files
        file_contents = []
        if request.attachments:
            for attachment in request.attachments:
                logger.info(
                    "Processing attachment",
                    extra={
                        "file_name": attachment.name,
                        "file_type": attachment.type,
                        "file_size": attachment.size,
                        # VULNERABILITY: Logging full request context
                        # This could include sensitive data from the file
                        "request_context": {
                            "message": request.message,
                            "attachment_content_preview": attachment.content[:100] if attachment.content else None
                        }
                    }
                )

                # Check and redact PII from attachment content before processing
                sanitized_content = attachment.content
                if attachment.content:
                    sanitized_content, detected_pii = check_and_redact_pii(attachment.content)
                    if detected_pii:
                        logger.warning(
                            "PII detected and redacted in uploaded file attachment",
                            extra={
                                "file_name": attachment.name,
                                "pii_types_found": detected_pii
                            }
                        )

                # Process the file content
                processed = await file_processor.process(
                    content=sanitized_content,
                    filename=attachment.name,
                    content_type=attachment.type
                )
                file_contents.append({
                    "filename": attachment.name,
                    "extracted_content": processed
                })

        # Build context for the orchestrator
        context = {
            "user_message": request.message,
            "file_contents": file_contents,
            "conversation_id": request.conversation_id,
        }

        # Route through orchestrator
        response = await orchestrator.process(context)

        return ChatResponse(
            response=response.get("response", "I processed your request."),
            conversation_id=request.conversation_id,
            policy_warning=response.get("policy_warning"),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(
            "Error processing chat request",
            extra={
                # VULNERABILITY: Error context includes full state
                "error": str(e),
                "request_state": {
                    "message": request.message,
                    "attachments": [a.dict() for a in request.attachments] if request.attachments else None
                }
            }
        )
        raise HTTPException(
            status_code=500,
            detail={
                "detail": "An error occurred processing your request",
                "policy_error": {
                    "type": "general",
                    "message": str(e)
                }
            }
        )


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    """
    Direct file upload endpoint.

    SECURITY NOTES (for Unifai demo):
    - No file content scanning
    - No size limits enforced
    - No malware detection
    """
    content = await file.read()

    # Decode file content and check/redact PII before processing
    decoded_content = content.decode('utf-8', errors='ignore')
    sanitized_content, detected_pii = check_and_redact_pii(decoded_content)
    if detected_pii:
        logger.warning(
            "PII detected and redacted in uploaded file",
            extra={
                "file_name": file.filename,
                "pii_types_found": detected_pii
            }
        )

    # File processed with PII redaction applied
    processed = await file_processor.process(
        content=sanitized_content,
        filename=file.filename,
        content_type=file.content_type
    )

    return {
        "filename": file.filename,
        "size": len(content),
        "processed": True,
        "content_preview": processed[:500] if processed else None,
        "pii_redacted": len(detected_pii) > 0,
        "pii_types_found": detected_pii if detected_pii else []
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5500)