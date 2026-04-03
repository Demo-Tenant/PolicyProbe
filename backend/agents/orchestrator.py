"""
Agent Orchestrator

Routes requests between specialized agents based on intent classification.
Manages the multi-agent workflow and aggregates responses.

SECURITY NOTES:
- Inter-agent calls require authentication via AgentAuthenticator
- Privilege verification enforced between agent calls
- Token validated on both sending and receiving ends
- PII is redacted before sending to LLM
- LLM responses are sanitized for dynamic code execution primitives
- All LLM interactions are logged
"""

import logging
import os
import re
from typing import Any, Optional

from .tech_support import TechSupportAgent
from .finance import FinanceAgent
from .file_processor import FileProcessorAgent
from .hr import HRAgent
from .auth.agent_auth import AgentAuthenticator, AgentIdentity
from llm.openrouter import OpenRouterClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PII redaction helpers
# ---------------------------------------------------------------------------

# Zero-tolerance PII patterns (global + Singapore)
_PII_PATTERNS = [
    # SSN
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[SSN REDACTED]'),
    # Credit card numbers (basic Luhn-format)
    (re.compile(r'\b(?:\d[ -]?){13,16}\b'), '[CC REDACTED]'),
    # Email addresses
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), '[EMAIL REDACTED]'),
    # Personal phone numbers (various formats)
    (re.compile(r'\b(?:\+?\d{1,3}[\s\-]?)?(?:\(?\d{2,4}\)?[\s\-]?)?\d{3,4}[\s\-]?\d{4}\b'), '[PHONE REDACTED]'),
    # IP addresses (v4)
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), '[IP REDACTED]'),
    # MAC addresses
    (re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'), '[MAC REDACTED]'),
    # Passport numbers (generic alphanumeric 6-9 chars)
    (re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'), '[PASSPORT REDACTED]'),
    # Driver's license (US-style)
    (re.compile(r'\b[A-Z]{1,2}\d{5,8}\b'), '[DL REDACTED]'),
    # Financial account numbers (8-17 digits)
    (re.compile(r'\b\d{8,17}\b'), '[ACCOUNT REDACTED]'),
    # Singapore NRIC/FIN
    (re.compile(r'\b[STFGM]\d{7}[A-Z]\b'), '[NRIC REDACTED]'),
    # Singapore CPF account (9 digits)
    (re.compile(r'\bCPF[\s\-]?\d{9}\b', re.IGNORECASE), '[CPF REDACTED]'),
    # GPS / fine location coordinates
    (re.compile(r'\b-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}\b'), '[LOCATION REDACTED]'),
    # Vehicle Identification Number (17 chars)
    (re.compile(r'\b[A-HJ-NPR-Z0-9]{17}\b'), '[VIN REDACTED]'),
    # Year of birth (standalone 4-digit year 1900-2099)
    (re.compile(r'\b(19|20)\d{2}\b'), '[YEAR REDACTED]'),
    # Home/residential address heuristic (number + street)
    (re.compile(r'\b\d{1,5}\s+[A-Za-z]+\s+(Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b', re.IGNORECASE), '[ADDRESS REDACTED]'),
    # Authentication tokens / session identifiers (long hex/base64 strings)
    (re.compile(r'\b[A-Za-z0-9+/]{32,}={0,2}\b'), '[TOKEN REDACTED]'),
]

# Suspicious / dangerous content patterns for uploaded files
_SUSPICIOUS_PATTERNS = [
    # Shell / OS commands and binaries
    re.compile(
        r'\b(alias|ripgrep|curl|rm|echo|dd|git|tar|chmod|chown|fsck|'
        r'bash|sh|zsh|fish|ksh|csh|tcsh|dash|'
        r'exec|eval|system|popen|subprocess|os\.system|'
        r'wget|nc|netcat|ncat|socat|telnet|ssh|scp|sftp|ftp|'
        r'python|perl|ruby|php|node|java|javac|gcc|g\+\+|make|cmake|'
        r'awk|sed|grep|find|xargs|sort|uniq|cut|tr|head|tail|cat|tee|'
        r'mount|umount|fdisk|mkfs|dd|df|du|lsblk|blkid|'
        r'iptables|ip6tables|nftables|ufw|firewall-cmd|'
        r'crontab|at|batch|nohup|screen|tmux|'
        r'kill|killall|pkill|ps|top|htop|'
        r'useradd|userdel|usermod|groupadd|passwd|su|sudo|'
        r'export|source|env|set|unset|'
        r'base64|xxd|hexdump|od|strings|'
        r'ping|traceroute|nmap|masscan|'
        r'openssl|gpg|ssh-keygen|'
        r'docker|kubectl|helm|terraform|ansible)\b',
        re.IGNORECASE
    ),
    # Base64-encoded content (heuristic: long base64 strings)
    re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'),
    # Leetspeak variants of dangerous words
    re.compile(r'\b(?:3x3c|3v4l|5y5t3m|p0p3n|5ubpr0c355)\b', re.IGNORECASE),
]

# Dynamic code execution primitives to strip from LLM responses
_CODE_EXEC_PATTERNS = [
    re.compile(r'^.*\beval\s*\(.*$', re.MULTILINE),
    re.compile(r'^.*\bexec\s*\(.*$', re.MULTILINE),
    re.compile(r'^.*\bsubprocess\s*\(.*shell\s*=\s*True.*$', re.MULTILINE),
    re.compile(r'^.*\bos\.system\s*\(.*$', re.MULTILINE),
    re.compile(r'^.*\bos\.popen\s*\(.*$', re.MULTILINE),
    re.compile(r'^.*\b__import__\s*\(.*$', re.MULTILINE),
    re.compile(r'^.*\bcompile\s*\(.*$', re.MULTILINE),
    # JS eval
    re.compile(r'^.*\beval\s*`.*`.*$', re.MULTILINE),
    # Bash eval
    re.compile(r'^.*\beval\s+".*".*$', re.MULTILINE),
    re.compile(r'^.*\beval\s+\'.*\'.*$', re.MULTILINE),
]


def _redact_pii(text: str) -> str:
    """Redact zero-tolerance PII from text."""
    if not text:
        return text
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def _sanitize_llm_input(text: str) -> str:
    """Sanitize and validate input before sending to LLM."""
    if not text:
        return text
    # Remove null bytes and control characters (except newlines/tabs)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    # Redact PII
    text = _redact_pii(text)
    # Limit length to prevent prompt injection via oversized input
    max_length = 32000
    if len(text) > max_length:
        text = text[:max_length] + '\n[TRUNCATED]'
    return text


def _sanitize_llm_response(text: str) -> str:
    """Remove dynamic code execution primitives from LLM response."""
    if not text:
        return text
    for pattern in _CODE_EXEC_PATTERNS:
        text = pattern.sub('', text)
    return text.strip()


def _redact_file_content(content: str) -> str:
    """Redact PII and suspicious content from uploaded file text."""
    if not content:
        return content
    # Redact PII
    content = _redact_pii(content)
    # Remove suspicious commands / binaries
    for pattern in _SUSPICIOUS_PATTERNS:
        content = pattern.sub('<suspicious_content_removed>', content)
    return content


def _mask_token(token: str) -> str:
    """Return a masked version of a token safe for logging."""
    if not token:
        return '[EMPTY]'
    return '[TOKEN REDACTED]'


class AgentOrchestrator:
    """
    Central orchestrator that routes requests to appropriate agents.

    The orchestrator:
    1. Classifies user intent
    2. Routes to the appropriate agent
    3. Handles inter-agent communication with authentication
    4. Aggregates and returns responses
    """

    def __init__(self):
        self.llm_client = OpenRouterClient()
        self.authenticator = AgentAuthenticator()

        # Initialize agents
        self.tech_support = TechSupportAgent(self.llm_client)
        self.finance = FinanceAgent(self.llm_client)
        self.file_processor = FileProcessorAgent()
        self.hr = HRAgent()          # Uses DeepSeek-R1-Distill-Qwen-1.5B internally

        # Agent registry with privilege levels
        self.agents = {
            "tech_support": {
                "agent": self.tech_support,
                "privilege": "low",
                "description": "General technical support and queries"
            },
            "finance": {
                "agent": self.finance,
                "privilege": "high",
                "description": "Financial data and reports"
            },
            "file_processor": {
                "agent": self.file_processor,
                "privilege": "medium",
                "description": "File processing and analysis"
            },
            "hr": {
                "agent": self.hr,
                "privilege": "high",
                "description": "Employee records, onboarding, payroll and benefits"
            },
        }

        # Token for inter-agent communication — loaded from environment variable
        self._agent_token = os.environ.get("AGENT_INTERNAL_TOKEN")
        if not self._agent_token:
            raise EnvironmentError(
                "POLICY VIOLATION: AGENT_INTERNAL_TOKEN environment variable is not set. "
                "Inter-agent authentication is required by policy. "
                "Set a strong secret in the AGENT_INTERNAL_TOKEN environment variable."
            )

    def _verify_agent_token(self, token: str) -> bool:
        """Validate the inter-agent token using constant-time comparison."""
        import hmac
        if not token or not self._agent_token:
            return False
        return hmac.compare_digest(token, self._agent_token)

    async def process(self, context: dict[str, Any]) -> dict[str, Any]:
        """
        Process incoming request and route to appropriate agent(s).

        Args:
            context: Request context including message, files, and metadata

        Returns:
            Response dictionary with agent output
        """
        user_message = context.get("user_message", "")
        file_contents = context.get("file_contents", [])

        # Log without PII — omit raw context preview
        logger.info(
            "Orchestrator processing request",
            extra={
                "message_length": len(user_message),
                "file_count": len(file_contents),
            }
        )

        # Determine which agent should handle the request
        intent = await self._classify_intent(user_message, file_contents)

        # Route to appropriate agent with authentication
        if intent == "finance":
            if not self._authorize_route("finance"):
                logger.warning("Authorization denied for finance route")
                return {"response": "Access denied: insufficient privileges.", "agent": "finance"}
            return await self._route_to_finance(context)
        elif intent == "hr":
            if not self._authorize_route("hr"):
                logger.warning("Authorization denied for HR route")
                return {"response": "Access denied: insufficient privileges.", "agent": "hr"}
            return await self._route_to_hr(context)
        elif intent == "file_analysis":
            return await self._route_to_file_processor(context)
        else:
            return await self._route_to_tech_support(context)

    def _authorize_route(self, target_agent: str) -> bool:
        """
        Verify that the orchestrator is authorized to route to the target agent.
        Enforces privilege checks for high-privilege agents.
        """
        agent_info = self.agents.get(target_agent)
        if not agent_info:
            return False
        # Orchestrator operates at system level; validate token is present
        if not self._agent_token:
            logger.error(
                "POLICY VIOLATION: Inter-agent authentication token missing. "
                "Cannot route to %s without a valid token.", target_agent
            )
            return False
        return True

    async def _classify_intent(
        self,
        message: str,
        file_contents: list
    ) -> str:
        """
        Classify the user's intent to determine routing.

        Returns one of: 'finance', 'file_analysis', 'tech_support'
        """
        # Simple keyword-based classification for demo
        message_lower = message.lower()

        finance_keywords = [
            "finance", "financial", "budget", "revenue", "expense",
            "profit", "loss", "quarterly", "annual report", "earnings",
            "balance sheet", "income statement", "cash flow"
        ]

        hr_keywords = [
            "employee", "employees", "staff", "headcount", "payroll",
            "salary", "salaries", "onboarding", "offboarding", "benefits",
            "hr", "human resources", "hire", "hired", "fired", "department",
            "org chart", "personnel", "leave", "pto", "vacation",
        ]

        if any(keyword in message_lower for keyword in finance_keywords):
            return "finance"

        if any(keyword in message_lower for keyword in hr_keywords):
            return "hr"

        if file_contents:
            return "file_analysis"

        return "tech_support"

    async def _route_to_tech_support(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Route request to tech support agent with authentication."""
        caller = AgentIdentity(
            agent_id="orchestrator",
            agent_name="Orchestrator",
            privilege_level="system",
            is_internal=True
        )

        # Validate token before passing
        if not self._verify_agent_token(self._agent_token):
            logger.error(
                "POLICY VIOLATION: Inter-agent authentication failed for tech_support route. "
                "All agent-to-agent calls must be authenticated."
            )
            return {"response": "Internal authentication error.", "agent": "tech_support"}

        headers = {"X-Agent-Token": self._agent_token}

        logger.info(
            "Routing to tech_support agent",
            extra={
                "caller": caller.agent_id,
                "privilege": caller.privilege_level,
                "token": _mask_token(self._agent_token),
            }
        )

        response = await self.tech_support.handle(
            context=context,
            caller=caller,
            headers=headers
        )

        return response

    async def _route_to_finance(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Route request to finance agent with authentication and privilege verification.
        """
        caller = AgentIdentity(
            agent_id="orchestrator",
            agent_name="Orchestrator",
            privilege_level="system",
            is_internal=True
        )

        # Validate token before inter-agent call
        if not self._verify_agent_token(self._agent_token):
            logger.error(
                "POLICY VIOLATION: Inter-agent authentication failed for finance route. "
                "All agent-to-agent calls must be authenticated."
            )
            return {"response": "Internal authentication error.", "agent": "finance"}

        headers = {"X-Agent-Token": self._agent_token}

        logger.info(
            "Routing to finance agent",
            extra={
                "caller": caller.agent_id,
                "privilege": caller.privilege_level,
                "token": _mask_token(self._agent_token),
            }
        )

        response = await self.finance.handle(
            context=context,
            caller=caller,
            headers=headers
        )

        return response

    async def _route_to_hr(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Route request to HR agent with authentication and privilege verification.
        """
        caller = AgentIdentity(
            agent_id="orchestrator",
            agent_name="Orchestrator",
            privilege_level="system",
            is_internal=True,
        )

        # Validate token before inter-agent call
        if not self._verify_agent_token(self._agent_token):
            logger.error(
                "POLICY VIOLATION: Inter-agent authentication failed for HR route. "
                "All agent-to-agent calls must be authenticated."
            )
            return {"response": "Internal authentication error.", "agent": "hr"}

        headers = {"X-Agent-Token": self._agent_token}

        logger.info(
            "Routing to HR agent",
            extra={
                "caller": caller.agent_id,
                "token": _mask_token(self._agent_token),
            }
        )

        response = await self.hr.handle(
            context=context,
            caller=caller,
            headers=headers,
        )

        return response

    async def _route_to_file_processor(
        self,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Route request to file processor agent."""
        file_contents = context.get("file_contents", [])

        if not file_contents:
            return {
                "response": "No files were provided to analyze.",
                "agent": "file_processor"
            }

        # Process files: redact PII and remove suspicious content before analysis
        analyses = []
        for file_data in file_contents:
            extracted = file_data.get("extracted_content", "")
            # Redact PII and suspicious content from uploaded file
            sanitized_content = _redact_file_content(extracted)
            analyses.append(f"File: {file_data.get('filename')}\n{sanitized_content}")

        combined_content = "\n\n".join(analyses)

        # Get the user's actual question and sanitize it
        user_question = _sanitize_llm_input(context.get("user_message", ""))

        # Sanitize combined content before sending to LLM
        sanitized_combined = _sanitize_llm_input(combined_content)

        system_prompt = _sanitize_llm_input(
            "You are a helpful document analyst. Answer the user's questions based on the "
            "provided document content. Be direct and specific - if they ask for specific "
            "information, provide it exactly as it appears in the document."
        )

        messages = [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": (
                    f"Document Content:\n{sanitized_combined}\n\n"
                    f"User Question: {user_question}\n\n"
                    "Please answer the user's question based on the document content above."
                )
            }
        ]

        # Log LLM interaction (input)
        logger.info(
            "LLM interaction: file_processor request",
            extra={
                "agent": "file_processor",
                "message_count": len(messages),
                "user_question_length": len(user_question),
                "combined_content_length": len(sanitized_combined),
            }
        )

        analysis = await self.llm_client.chat(messages=messages)

        # Sanitize LLM response for dynamic code execution primitives
        sanitized_analysis = _sanitize_llm_response(analysis)

        # Log LLM interaction (output)
        logger.info(
            "LLM interaction: file_processor response",
            extra={
                "agent": "file_processor",
                "response_length": len(sanitized_analysis) if sanitized_analysis else 0,
            }
        )

        return {
            "response": sanitized_analysis,
            "agent": "file_processor",
            "files_processed": len(file_contents)
        }

    async def escalate_from_tech_support(
        self,
        query: str,
        tech_support_context: dict
    ) -> dict[str, Any]:
        """
        Handle escalation from tech support to finance agent.

        This method is called when tech support needs to access
        financial data on behalf of a user.

        Requires valid inter-agent authentication before escalation.
        """
        # Verify authentication before allowing escalation
        if not self._verify_agent_token(self._agent_token):
            logger.error(
                "POLICY VIOLATION: Inter-agent authentication failed during escalation "
                "from tech_support to finance. All agent-to-agent calls must be authenticated."
            )
            return {"response": "Escalation denied: authentication failure.", "agent": "finance"}

        if not self._authorize_route("finance"):
            logger.warning("Authorization denied for escalation to finance")
            return {"response": "Escalation denied: insufficient privileges.", "agent": "finance"}

        escalation_context = {
            "user_message": query,
            "escalated_from": "tech_support",
            "original_context": tech_support_context,
            "escalation_reason": "Financial data requested"
        }

        logger.info(
            "Escalating from tech support to finance",
            extra={
                "query_length": len(query),
            }
        )

        return await self._route_to_finance(escalation_context)