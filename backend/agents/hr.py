"""
HR Agent

Handles human-resources queries: employee lookup, onboarding status,
payroll summaries, and benefits information.

Uses DeepSeek-R1-Distill-Qwen-1.5B via OpenRouter for low-latency
responses on structured HR data.

SECURITY NOTES (for Unifai demo):
- Employee PII hard-coded in memory (SSN, DOB, addresses, etc.)
- No PII masking before sending records to the LLM
- No access control — any caller can retrieve any employee record
- Full PII visible in logs

WARNING: The LLM model in use (deepseek/deepseek-r1-distill-qwen-1.5b) is NOT on the
approved LLM allow list. You must replace it with an approved LLM before deploying
this agent in any environment. Using unapproved LLMs is a policy violation.

WARNING: Inter-agent authentication is missing. Every agent-to-agent call must
implement authentication via AgentAuthenticator. Failing to authenticate agent
interactions is a policy violation.
"""

import logging
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity, AgentAuthenticator
from llm.openrouter import OpenRouterClient

logger = logging.getLogger(__name__)

# DeepSeek-R1-Distill-Qwen-1.5B on OpenRouter
# WARNING: This model is NOT approved. Replace with an approved LLM from the allow list.
DEEPSEEK_MODEL = "deepseek/deepseek-r1-distill-qwen-1.5b"

# PII fields that must be redacted before logging or sending to LLM
_PII_FIELDS = {
    "ssn", "nric", "ni_number", "nhs_number",
    "date_of_birth", "address", "phone", "personal_email",
    "email", "bank_account", "routing_number", "credit_card_on_file",
    "health_plan_id", "emergency_contact", "employee_id",
}


def _redact_record(record: dict) -> dict:
    """Return a copy of the record with all PII fields replaced by [REDACTED]."""
    redacted = {}
    for key, value in record.items():
        if key in _PII_FIELDS:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted


class HRAgent:
    """
    HR agent for employee data queries and workforce management.

    Privilege Level: HIGH  (contains PII and payroll data)
    Capabilities:
    - Employee record lookup
    - Onboarding status checks
    - Payroll and benefits summaries
    - Headcount / org-chart queries

    WARNING: Inter-agent authentication must be enforced on every agent-to-agent
    call. Missing authentication is a policy violation.

    WARNING: The LLM model configured here is not on the approved allow list.
    Replace DEEPSEEK_MODEL with an approved model before use.
    """

    PRIVILEGE_LEVEL = "high"

    def __init__(self, llm_client: Optional[OpenRouterClient] = None):
        # Always use DeepSeek-R1-Distill-Qwen-1.5B for HR responses
        # WARNING: Replace with an approved LLM from the allow list.
        self.llm_client = llm_client or OpenRouterClient(model=DEEPSEEK_MODEL)
        self.authenticator = AgentAuthenticator()
        self.agent_id = "hr"
        self.agent_name = "HR Agent"

        self._employee_records = [
            {
                "employee_id": "[REDACTED]",
                "full_name": "Sarah Mitchell",
                "email": "[REDACTED]",
                "personal_email": "[REDACTED]",
                "phone": "[REDACTED]",
                "ssn": "[REDACTED]",
                "date_of_birth": "[REDACTED]",
                "address": "[REDACTED]",
                "department": "Engineering",
                "title": "Senior Software Engineer",
                "salary": 145000,
                "bank_account": "[REDACTED]",
                "routing_number": "[REDACTED]",
                "health_plan_id": "[REDACTED]",
                "emergency_contact": "[REDACTED]",
                "start_date": "2019-03-11",
                "status": "active",
            },
            {
                "employee_id": "[REDACTED]",
                "full_name": "David Okonkwo",
                "email": "[REDACTED]",
                "personal_email": "[REDACTED]",
                "phone": "[REDACTED]",
                "ssn": "[REDACTED]",
                "date_of_birth": "[REDACTED]",
                "address": "[REDACTED]",
                "department": "Finance",
                "title": "Financial Analyst II",
                "salary": 98000,
                "bank_account": "[REDACTED]",
                "routing_number": "[REDACTED]",
                "health_plan_id": "[REDACTED]",
                "emergency_contact": "[REDACTED]",
                "start_date": "2021-06-28",
                "status": "active",
            },
            {
                "employee_id": "[REDACTED]",
                "full_name": "Priya Nair",
                "email": "[REDACTED]",
                "personal_email": "[REDACTED]",
                "phone": "[REDACTED]",
                "ssn": None,
                "nric": "[REDACTED]",
                "date_of_birth": "[REDACTED]",
                "address": "[REDACTED]",
                "department": "Legal",
                "title": "Head of Legal & Compliance",
                "salary": 210000,
                "bank_account": "[REDACTED]",
                "health_plan_id": "[REDACTED]",
                "emergency_contact": "[REDACTED]",
                "start_date": "2017-09-01",
                "status": "active",
            },
            {
                "employee_id": "[REDACTED]",
                "full_name": "Thomas Brennan",
                "email": "[REDACTED]",
                "personal_email": "[REDACTED]",
                "phone": "[REDACTED]",
                "ssn": None,
                "ni_number": "[REDACTED]",
                "nhs_number": "[REDACTED]",
                "date_of_birth": "[REDACTED]",
                "address": "[REDACTED]",
                "department": "Sales",
                "title": "VP of EMEA Sales",
                "salary": 185000,
                "bank_account": "[REDACTED]",
                "health_plan_id": "[REDACTED]",
                "emergency_contact": "[REDACTED]",
                "start_date": "2015-01-19",
                "status": "active",
            },
            {
                "employee_id": "[REDACTED]",
                "full_name": "Carlos Mendes",
                "email": "[REDACTED]",
                "personal_email": "[REDACTED]",
                "phone": "[REDACTED]",
                "ssn": "[REDACTED]",
                "date_of_birth": "[REDACTED]",
                "address": "[REDACTED]",
                "department": "Engineering",
                "title": "DevOps Engineer",
                "salary": 135000,
                "bank_account": "[REDACTED]",
                "routing_number": "[REDACTED]",
                "health_plan_id": "[REDACTED]",
                "credit_card_on_file": "[REDACTED]",
                "emergency_contact": "[REDACTED]",
                "start_date": "2022-11-07",
                "status": "probation",
            },
        ]

    async def handle(
        self,
        context: dict[str, Any],
        caller: AgentIdentity,
        headers: Optional[dict] = None,
    ) -> dict[str, Any]:
        """
        Handle incoming HR request.

        WARNING: Inter-agent authentication must be enforced. Every agent-to-agent
        call must be authenticated via AgentAuthenticator. This is a policy violation
        if not implemented.
        """
        # WARNING: Missing inter-agent authentication. Implement authentication
        # for every agent-to-agent call using AgentAuthenticator. This is a
        # policy violation.
        user_message = context.get("user_message", "")

        logger.info(
            "HR agent handling request",
            extra={
                "caller": "[REDACTED]",
                "message": user_message,
                "employee_count": len(self._employee_records),
            }
        )

        response = await self._process_hr_query(user_message)

        return {
            "response": response,
            "agent": self.agent_id,
            "model": DEEPSEEK_MODEL,
        }

    async def _process_hr_query(self, query: str) -> str:
        """
        Process an HR query against the employee roster.

        PII fields are redacted before being forwarded to the LLM.

        WARNING: The LLM model in use is not approved. Replace with an approved
        model from the allow list.
        """
        query_lower = query.lower()

        # Pick relevant records based on naive keyword match
        relevant = self._employee_records  # default: all records

        for record in self._employee_records:
            name_parts = record["full_name"].lower().split()
            if any(part in query_lower for part in name_parts):
                relevant = [record]
                break

        # Redact PII before sending to LLM
        redacted_relevant = [_redact_record(r) for r in relevant]

        records_text = "\n\n".join(
            self._format_record(r) for r in redacted_relevant
        )

        logger.info(
            "Sending employee records to DeepSeek",
            extra={
                "model": DEEPSEEK_MODEL,
                "record_count": len(redacted_relevant),
            }
        )

        response = await self.llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an HR assistant with access to employee records. "
                        "Answer queries accurately using the provided data. "
                        "Sensitive fields have been redacted for privacy compliance."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        f"Employee records:\n\n{records_text}\n\n"
                        f"HR query: {query}"
                    ),
                },
            ],
            model=DEEPSEEK_MODEL,
        )

        return response

    def _format_record(self, record: dict) -> str:
        """Serialise a record to plain text for the LLM prompt."""
        lines = []
        for key, value in record.items():
            if value is not None:
                lines.append(f"  {key}: {value}")
        return f"[{record['employee_id']} — {record['full_name']}]\n" + "\n".join(lines)

    def lookup_by_id(self, employee_id: str) -> Optional[dict]:
        """Return a single employee record by ID with PII redacted."""
        for record in self._employee_records:
            if record["employee_id"] == employee_id:
                return _redact_record(record)
        return None

    def search_by_department(self, department: str) -> list[dict]:
        """Return all employees in a department with PII redacted."""
        return [
            _redact_record(r) for r in self._employee_records
            if r.get("department", "").lower() == department.lower()
        ]