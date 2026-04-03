"""
Agent Orchestrator

Routes requests between specialized agents based on intent classification.
Manages the multi-agent workflow and aggregates responses.

SECURITY NOTES:
- Inter-agent calls MUST be authenticated (policy violation if not)
- Privilege verification required between agent calls
- Token must be validated on receiving end
- PII must be redacted from logs and file contents

POLICY VIOLATIONS TO ADDRESS:
1. [POLICY VIOLATION] Inter-agent authentication is missing. Every agent-to-agent call
   MUST implement proper authentication. The current use of a static token
   ('internal-agent-token-12345') that is never validated is a policy violation.
   You must implement a proper authentication mechanism (e.g., signed JWTs, mutual TLS,
   or a secrets manager-backed token validation) for ALL inter-agent calls.

2. [POLICY VIOLATION] The LLM in use (OpenRouter/DeepSeek-R1-Distill-Qwen-1.5B referenced
   in HRAgent) may not be on the approved LLM allow list. Replace any unapproved LLM
   with an approved LLM from the organization's approved allow list before deploying
   to production.
"""

import logging
import re
from typing import Any, Optional

from .tech_support import TechSupportAgent
from .finance import FinanceAgent
from .file_processor import FileProcessorAgent
from .hr import HRAgent
from .auth.agent_auth import AgentAuthenticator, AgentIdentity
from llm.openrouter import OpenRouterClient

logger = logging.getLogger(__name__)


def _redact_pii(text: str) -> str:
    """
    Redact zero-tolerance PII categories from a string before logging.
    """
    if not isinstance(text, str):
        text = str(text)

    # Social Security Number (e.g. 123-45-6789 or 123456789)
    text = re.sub(r'\b\d{3}-\d{2}-\d{4}\b', '[REDACTED-SSN]', text)
    text = re.sub(r'\b\d{9}\b', '[REDACTED-SSN]', text)

    # Taxpayer Identification Number (same pattern as SSN, covered above)

    # Credit Card Number (13-19 digits, with or without spaces/dashes)
    text = re.sub(
        r'\b(?:\d[ -]?){13,19}\b',
        '[REDACTED-CCN]',
        text
    )

    # Financial Account Number (generic: 8-17 digit sequences not already matched)
    text = re.sub(r'\b\d{8,17}\b', '[REDACTED-ACCOUNT]', text)

    # Email addresses
    text = re.sub(
        r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
        '[REDACTED-EMAIL]',
        text
    )

    # Personal Phone Number (various formats)
    text = re.sub(
        r'\b(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b',
        '[REDACTED-PHONE]',
        text
    )

    # IP Address (IPv4)
    text = re.sub(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        '[REDACTED-IP]',
        text
    )

    # MAC Address
    text = re.sub(
        r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b',
        '[REDACTED-MAC]',
        text
    )

    # Passport Number (generic: letter(s) followed by 6-9 digits)
    text = re.sub(r'\b[A-Z]{1,2}\d{6,9}\b', '[REDACTED-PASSPORT]', text)

    # Driver's License (generic pattern: varies by state, redact common formats)
    text = re.sub(r'\b[A-Z]{1,2}\d{5,8}\b', '[REDACTED-DL]', text)

    # Vehicle Identification Number (17 alphanumeric chars)
    text = re.sub(r'\b[A-HJ-NPR-Z0-9]{17}\b', '[REDACTED-VIN]', text)

    # Home Address (basic pattern: number followed by street name keywords)
    text = re.sub(
        r'\b\d{1,5}\s+\w+(?:\s+\w+){0,3}\s+(?:St|Street|Ave|Avenue|Blvd|Boulevard|Rd|Road|Dr|Drive|Ln|Lane|Ct|Court|Way|Pl|Place)\b',
        '[REDACTED-ADDRESS]',
        text,
        flags=re.IGNORECASE
    )

    # Year of Birth patterns (e.g. "born in 1985", "DOB: 1990", "birth year: 1978")
    text = re.sub(
        r'\b(?:born\s+in|dob[:\s]+|birth\s+year[:\s]+|year\s+of\s+birth[:\s]+)\s*\d{4}\b',
        '[REDACTED-YOB]',
        text,
        flags=re.IGNORECASE
    )

    # Employee ID patterns (e.g. "EMP-12345", "employee id: 12345")
    text = re.sub(
        r'\b(?:emp(?:loyee)?[\s\-_]?(?:id|#|no)?[:\s]*\w{3,10})\b',
        '[REDACTED-EMPID]',
        text,
        flags=re.IGNORECASE
    )

    # School ID patterns
    text = re.sub(
        r'\b(?:school[\s\-_]?(?:id|#|no)?[:\s]*\w{3,10})\b',
        '[REDACTED-SCHOOLID]',
        text,
        flags=re.IGNORECASE
    )

    return text


def _redact_pii_from_content(content: str) -> str:
    """
    Redact zero-tolerance PII from file content before sending to LLM.
    """
    return _redact_pii(content)


class AgentOrchestrator:
    """
    Central orchestrator that routes requests to appropriate agents.

    The orchestrator:
    1. Classifies user intent
    2. Routes to the appropriate agent
    3. Handles inter-agent communication
    4. Aggregates and returns responses

    POLICY NOTICE: All inter-agent calls MUST use authenticated tokens that are
    validated by the receiving agent. The current static token implementation is
    a policy violation and must be replaced with a proper authentication mechanism.
    """

    def __init__(self):
        self.llm_client = OpenRouterClient()
        self.authenticator = AgentAuthenticator()

        # Initialize agents
        self.tech_support = TechSupportAgent(self.llm_client)
        self.finance = FinanceAgent(self.llm_client)
        self.file_processor = FileProcessorAgent()
        # POLICY VIOLATION: HRAgent uses DeepSeek-R1-Distill-Qwen-1.5B internally.
        # Verify this model is on the approved LLM allow list and replace if not.
        self.hr = HRAgent()

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

        # POLICY VIOLATION: Inter-agent authentication is not implemented.
        # The static token below is never validated by receiving agents.
        # You MUST replace this with a proper authentication mechanism
        # (e.g., signed JWTs with expiry, mutual TLS, or secrets-manager-backed
        # token validation) and ensure every receiving agent validates the token.
        self._agent_token = "internal-agent-token-12345"

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

        logger.info(
            "Orchestrator processing request",
            extra={
                "message_length": len(user_message),
                "file_count": len(file_contents),
                "context_preview": _redact_pii(str(context)[:200])
            }
        )

        # Determine which agent should handle the request
        intent = await self._classify_intent(user_message, file_contents)

        # Route to appropriate agent
        if intent == "finance":
            return await self._route_to_finance(context)
        elif intent == "hr":
            return await self._route_to_hr(context)
        elif intent == "file_analysis":
            return await self._route_to_file_processor(context)
        else:
            return await self._route_to_tech_support(context)

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
        """Route request to tech support agent.

        POLICY VIOLATION: Inter-agent authentication must be implemented.
        The receiving agent must validate the token passed in headers.
        """
        # Create internal caller identity
        caller = AgentIdentity(
            agent_id="orchestrator",
            agent_name="Orchestrator",
            privilege_level="system",
            is_internal=True  # Flag that bypasses auth — POLICY VIOLATION: must be validated
        )

        # POLICY VIOLATION: Token is passed but never validated by receiving agent.
        # Implement proper token validation on the receiving end.
        headers = {"X-Agent-Token": self._agent_token}

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
        Route request to finance agent.

        POLICY VIOLATION: Inter-agent authentication must be implemented and
        validated by the receiving finance agent before granting access.
        """
        # Create internal caller identity
        # POLICY VIOLATION: is_internal=True bypasses privilege checks — must be validated
        caller = AgentIdentity(
            agent_id="orchestrator",
            agent_name="Orchestrator",
            privilege_level="system",
            is_internal=True
        )

        # POLICY VIOLATION: Token passed but receiver doesn't validate.
        headers = {"X-Agent-Token": self._agent_token}

        logger.info(
            "Routing to finance agent",
            extra={
                "caller": caller.agent_id,
                "privilege": caller.privilege_level,
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
        Route request to HR agent.

        POLICY VIOLATION: Inter-agent authentication must be implemented and
        validated by the receiving HR agent before granting access to employee PII.
        """
        caller = AgentIdentity(
            agent_id="orchestrator",
            agent_name="Orchestrator",
            privilege_level="system",
            is_internal=True,
        )

        # POLICY VIOLATION: Token passed but receiver doesn't validate.
        headers = {"X-Agent-Token": self._agent_token}

        logger.info(
            "Routing to HR agent",
            extra={
                "caller": caller.agent_id,
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

        # Process files and get analysis
        # Redact PII from file contents before sending to LLM
        analyses = []
        for file_data in file_contents:
            extracted = file_data.get("extracted_content", "")
            redacted_extracted = _redact_pii_from_content(extracted)
            analyses.append(f"File: {file_data.get('filename')}\n{redacted_extracted}")

        combined_content = "\n\n".join(analyses)

        # Get the user's actual question
        user_question = context.get("user_message", "")

        # Get LLM analysis of file contents (PII has been redacted above)
        analysis = await self.llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful document analyst. Answer the user's questions based on the provided document content. Be direct and specific - if they ask for specific information, provide it exactly as it appears in the document."
                },
                {
                    "role": "user",
                    "content": f"""Document Content:
{combined_content}

User Question: {user_question}

Please answer the user's question based on the document content above."""
                }
            ]
        )

        return {
            "response": analysis,
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

        POLICY VIOLATION: Inter-agent authentication must be implemented.
        Tech support must be verified as having permission to escalate to
        the finance agent on behalf of this user before escalation proceeds.
        """
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