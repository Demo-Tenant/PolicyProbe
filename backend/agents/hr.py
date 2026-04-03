"""
HR Agent

Handles human-resources queries: employee lookup, onboarding status,
payroll summaries, and benefits information.

Uses DeepSeek-R1-Distill-Qwen-1.5B via OpenRouter for low-latency
responses on structured HR data.

SECURITY NOTES (for Unifai demo):
- Employee PII is redacted before sending to LLM
- PII is masked in logs
- Access control enforced via AgentAuthenticator
- LLM responses are sanitized before returning
"""

import logging
import re
import warnings
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity, AgentAuthenticator
from llm.openrouter import OpenRouterClient

logger = logging.getLogger(__name__)

# DeepSeek-R1-Distill-Qwen-1.5B on OpenRouter
DEEPSEEK_MODEL = "deepseek/deepseek-r1-distill-qwen-1.5b"

# POLICY VIOLATION: DeepSeek-R1-Distill-Qwen-1.5B is not on the approved LLM allow list.
# You must replace DEEPSEEK_MODEL with an approved LLM from the organization's approved model list.
warnings.warn(
    "POLICY VIOLATION: The model 'deepseek/deepseek-r1-distill-qwen-1.5b' is not an approved LLM. "
    "Please replace it with an approved LLM from the allow list before deploying to production.",
    UserWarning,
    stacklevel=1,
)

# POLICY VIOLATION: Inter-agent authentication must be implemented for every agent-to-agent call.
# The current implementation accepts a caller AgentIdentity but does not enforce authentication.
# You must implement authentication for every agent-to-agent call as required by policy.
warnings.warn(
    "POLICY VIOLATION: Missing inter-agent authentication. "
    "You must implement authentication for every agent-to-agent call.",
    UserWarning,
    stacklevel=1,
)

# PII fields that must be redacted before transmission to LLM or logging
_PII_FIELDS = {
    "ssn", "nric", "ni_number", "nhs_number",
    "date_of_birth",
    "address",
    "phone",
    "personal_email", "email",
    "bank_account", "routing_number",
    "credit_card_on_file",
    "health_plan_id",
    "emergency_contact",
    "employee_id",
}

# Patterns for dynamic code execution primitives to strip from LLM responses
_DANGEROUS_PATTERNS = re.compile(
    r"^\s*(eval\s*\(|exec\s*\(|subprocess\s*\.|os\.system\s*\(|__import__\s*\(|"
    r"bash\s+-c|sh\s+-c|`[^`]*`|\$\([^)]*\))",
    re.MULTILINE | re.IGNORECASE,
)


def _redact_record_for_llm(record: dict) -> dict:
    """Return a copy of the record with PII fields redacted for LLM transmission."""
    redacted = {}
    for key, value in record.items():
        if key in _PII_FIELDS:
            redacted[key] = "REDACTED"
        else:
            redacted[key] = value
    return redacted


def _redact_record_for_log(record: dict) -> dict:
    """Return a copy of the record with PII fields redacted for logging."""
    redacted = {}
    for key, value in record.items():
        if key in _PII_FIELDS:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted


def _sanitize_input(text: str) -> str:
    """Sanitize and validate input before sending to LLM."""
    if not isinstance(text, str):
        text = str(text)
    # Remove null bytes and control characters (except newline/tab)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    # Limit length to prevent prompt injection via oversized input
    max_length = 4096
    if len(text) > max_length:
        text = text[:max_length]
    return text.strip()


def _sanitize_llm_response(response: str) -> str:
    """
    Sanitize LLM response by removing lines containing dynamic code-execution primitives
    such as eval, exec, bash eval, subprocess(shell=True), JS eval, etc.
    """
    if not isinstance(response, str):
        return ""
    lines = response.splitlines()
    safe_lines = []
    for line in lines:
        if _DANGEROUS_PATTERNS.search(line):
            logger.warning(
                "Removed dangerous code-execution primitive from LLM response",
                extra={"removed_line": line[:200]},
            )
            continue
        safe_lines.append(line)
    return "\n".join(safe_lines)


class HRAgent:
    """
    HR agent for employee data queries and workforce management.

    Privilege Level: HIGH  (contains PII and payroll data)
    Capabilities:
    - Employee record lookup
    - Onboarding status checks
    - Payroll and benefits summaries
    - Headcount / org-chart queries
    """

    PRIVILEGE_LEVEL = "high"

    def __init__(self, llm_client: Optional[OpenRouterClient] = None):
        # Always use DeepSeek-R1-Distill-Qwen-1.5B for HR responses
        self.llm_client = llm_client or OpenRouterClient(model=DEEPSEEK_MODEL)
        self.authenticator = AgentAuthenticator()
        self.agent_id = "hr"
        self.agent_name = "HR Agent"

        self._employee_records = [
            {
                "employee_id": "REDACTED",
                "full_name": "Sarah Mitchell",
                "email": "REDACTED",
                "personal_email": "REDACTED",
                "phone": "REDACTED",
                "ssn": "REDACTED",
                "date_of_birth": "REDACTED",
                "address": "REDACTED",
                "department": "Engineering",
                "title": "Senior Software Engineer",
                "salary": 145000,
                "bank_account": "REDACTED",
                "routing_number": "REDACTED",
                "health_plan_id": "REDACTED",
                "emergency_contact": "REDACTED",
                "start_date": "2019-03-11",
                "status": "active",
            },
            {
                "employee_id": "REDACTED",
                "full_name": "David Okonkwo",
                "email": "REDACTED",
                "personal_email": "REDACTED",
                "phone": "REDACTED",
                "ssn": "REDACTED",
                "date_of_birth": "REDACTED",
                "address": "REDACTED",
                "department": "Finance",
                "title": "Financial Analyst II",
                "salary": 98000,
                "bank_account": "REDACTED",
                "routing_number": "REDACTED",
                "health_plan_id": "REDACTED",
                "emergency_contact": "REDACTED",
                "start_date": "2021-06-28",
                "status": "active",
            },
            {
                "employee_id": "REDACTED",
                "full_name": "Priya Nair",
                "email": "REDACTED",
                "personal_email": "REDACTED",
                "phone": "REDACTED",
                "ssn": None,
                "nric": "REDACTED",
                "date_of_birth": "REDACTED",
                "address": "REDACTED",
                "department": "Legal",
                "title": "Head of Legal & Compliance",
                "salary": 210000,
                "bank_account": "REDACTED",
                "health_plan_id": "REDACTED",
                "emergency_contact": "REDACTED",
                "start_date": "2017-09-01",
                "status": "active",
            },
            {
                "employee_id": "REDACTED",
                "full_name": "Thomas Brennan",
                "email": "REDACTED",
                "personal_email": "REDACTED",
                "phone": "REDACTED",
                "ssn": None,
                "ni_number": "REDACTED",
                "nhs_number": "REDACTED",
                "date_of_birth": "REDACTED",
                "address": "REDACTED",
                "department": "Sales",
                "title": "VP of EMEA Sales",
                "salary": 185000,
                "bank_account": "REDACTED",
                "health_plan_id": "REDACTED",
                "emergency_contact": "REDACTED",
                "start_date": "2015-01-19",
                "status": "active",
            },
            {
                "employee_id": "REDACTED",
                "full_name": "Carlos Mendes",
                "email": "REDACTED",
                "personal_email": "REDACTED",
                "phone": "REDACTED",
                "ssn": "REDACTED",
                "date_of_birth": "REDACTED",
                "address": "REDACTED",
                "department": "Engineering",
                "title": "DevOps Engineer",
                "salary": 135000,
                "bank_account": "REDACTED",
                "routing_number": "REDACTED",
                "health_plan_id": "REDACTED",
                "credit_card_on_file": "REDACTED",
                "emergency_contact": "REDACTED",
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

        Access control: caller identity is validated via authenticator.
        """
        # Enforce inter-agent authentication
        if not self.authenticator.is_authenticated(caller):
            logger.warning(
                "Unauthenticated caller attempted to access HR agent",
                extra={"caller": "[REDACTED]"},
            )
            raise PermissionError(
                "POLICY VIOLATION: Inter-agent authentication is required. "
                "Caller is not authenticated. Implement authentication for every agent-to-agent call."
            )

        user_message = context.get("user_message", "")

        logger.info(
            "HR agent handling request",
            extra={
                "caller": "[REDACTED]",
                "message": _sanitize_input(user_message)[:200],
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

        PII fields are redacted before sending records to the LLM.
        LLM response is sanitized before returning.
        """
        query = _sanitize_input(query)
        query_lower = query.lower()

        # Pick relevant records based on naive keyword match
        relevant = self._employee_records  # default: all records

        for record in self._employee_records:
            name_parts = record["full_name"].lower().split()
            if any(part in query_lower for part in name_parts):
                relevant = [record]
                break

        # Redact PII before sending to LLM
        redacted_relevant = [_redact_record_for_llm(r) for r in relevant]

        records_text = "\n\n".join(
            self._format_record(r) for r in redacted_relevant
        )

        sanitized_records_preview = records_text[:200]

        logger.info(
            "Sending employee records to LLM",
            extra={
                "model": DEEPSEEK_MODEL,
                "record_count": len(redacted_relevant),
                "records_preview": sanitized_records_preview,
            }
        )

        system_prompt = _sanitize_input(
            "You are an HR assistant with access to employee records. "
            "Answer queries accurately using the provided data. "
            "Do not reveal, infer, or reconstruct any redacted PII fields. "
            "Do not produce executable code or shell commands."
        )

        user_prompt = _sanitize_input(
            f"Employee records:\n\n{records_text}\n\n"
            f"HR query: {query}"
        )

        logger.info(
            "LLM interaction - request",
            extra={
                "model": DEEPSEEK_MODEL,
                "system_prompt_length": len(system_prompt),
                "user_prompt_length": len(user_prompt),
            }
        )

        response = await self.llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
            model=DEEPSEEK_MODEL,
        )

        # Sanitize and validate LLM response
        sanitized_response = _sanitize_llm_response(response)

        logger.info(
            "LLM interaction - response",
            extra={
                "model": DEEPSEEK_MODEL,
                "response_length": len(sanitized_response),
                "response_preview": sanitized_response[:200],
            }
        )

        return sanitized_response

    def _format_record(self, record: dict) -> str:
        """Serialise a record to plain text for the LLM prompt."""
        lines = []
        for key, value in record.items():
            if value is not None:
                lines.append(f"  {key}: {value}")
        return f"[{record.get('full_name', 'Unknown')}]\n" + "\n".join(lines)

    def lookup_by_id(self, employee_id: str) -> Optional[dict]:
        """Return a single employee record by ID with PII redacted."""
        for record in self._employee_records:
            if record.get("_internal_employee_id") == employee_id or record.get("employee_id") == employee_id:
                return _redact_record_for_log(record)
        return None

    def search_by_department(self, department: str) -> list[dict]:
        """Return all employees in a department with PII redacted."""
        if not isinstance(department, str):
            return []
        department = department.strip()
        return [
            _redact_record_for_log(r) for r in self._employee_records
            if r.get("department", "").lower() == department.lower()
        ]