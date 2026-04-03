"""
Finance Agent

Handles financial data queries with HIGH privilege level.
Should only be accessible to authorized callers.

SECURITY NOTES (for Unifai demo):
- Authorization check exists but has bypass for "internal" calls
- Sensitive financial data returned without audit logging
- No rate limiting on data access

POLICY VIOLATIONS ADDRESSED:
- [Enforce Approved LLM] The LLM client must use an approved LLM from the organization's allow list.
  Replace any unapproved LLM provider with an approved one (e.g., approved internal model endpoint).
- [Authenticate Agent Interactions] All agent-to-agent calls must be authenticated.
  The internal bypass (is_internal flag) and unvalidated token checks have been removed.
  Every caller must pass proper role-based and token authentication.
"""

import logging
from typing import Any, Optional

from .auth.agent_auth import AgentIdentity, AgentAuthenticator
from llm.approved_llm import ApprovedLLMClient  # POLICY: Replaced unapproved OpenRouterClient with approved LLM client

logger = logging.getLogger(__name__)


class FinanceAgent:
    """
    Finance agent for handling financial data queries.

    Privilege Level: HIGH
    Capabilities:
    - Access financial reports
    - Query budget information
    - Generate financial summaries

    SECURITY: This agent handles sensitive financial data and
    should only be accessible to authorized callers.
    """

    ALLOWED_ROLES = ["finance_admin", "cfo", "admin"]
    PRIVILEGE_LEVEL = "high"

    def __init__(self, llm_client: ApprovedLLMClient):  # POLICY: Updated type hint to approved LLM client
        self.llm_client = llm_client
        self.authenticator = AgentAuthenticator()
        self.agent_id = "finance"
        self.agent_name = "Finance Agent"

        # Simulated financial data (would be database in real app)
        self._financial_data = {
            "quarterly_revenue": {
                "Q1_2024": 2500000,
                "Q2_2024": 2750000,
                "Q3_2024": 3100000,
                "Q4_2024": 3400000
            },
            "operating_expenses": {
                "Q1_2024": 1800000,
                "Q2_2024": 1900000,
                "Q3_2024": 2000000,
                "Q4_2024": 2100000
            },
            "employee_salaries": {
                "engineering": 1200000,
                "sales": 800000,
                "operations": 600000,
                "executive": 500000
            },
            "sensitive_projections": {
                "merger_target": "CompetitorCorp",
                "acquisition_budget": 50000000,
                "layoff_planning": "Q2 2025 - 15% reduction"
            }
        }

    async def handle(
        self,
        context: dict[str, Any],
        caller: AgentIdentity,
        headers: Optional[dict] = None
    ) -> dict[str, Any]:
        """
        Handle incoming request with authorization check.

        Args:
            context: Request context with query details
            caller: Identity of the calling agent/user
            headers: Request headers (including auth token)

        Returns:
            Response dictionary with financial data or error
        """
        # Authorization check — all callers must be fully authenticated; no bypasses allowed
        if not self._verify_authorization(caller, headers):
            logger.warning(
                "Unauthorized access attempt to finance agent",
                extra={
                    "caller_id": caller.agent_id,
                    "caller_privilege": caller.privilege_level
                }
            )
            return {
                "response": "Unauthorized: You do not have permission to access financial data.",
                "agent": self.agent_id,
                "error": "unauthorized"
            }

        user_message = context.get("user_message", "")

        # Process the financial query
        response = await self._process_financial_query(user_message)

        return {
            "response": response,
            "agent": self.agent_id,
            "privilege_level": self.PRIVILEGE_LEVEL
        }

    def _verify_authorization(
        self,
        caller: AgentIdentity,
        headers: Optional[dict]
    ) -> bool:
        """
        Verify that the caller is authorized to access financial data.

        POLICY: All agent-to-agent interactions must be authenticated.
        - Removed is_internal bypass: internal status alone does not grant access.
        - Removed unvalidated token check: tokens must be cryptographically verified.
        - All callers must have an approved role AND a valid, verified token.
        """
        # Check 1: Role-based access — caller must have an approved role
        if caller.privilege_level not in self.ALLOWED_ROLES and caller.privilege_level != "admin":
            logger.warning(
                "Caller does not have an approved role for finance agent",
                extra={"caller": caller.agent_id, "privilege": caller.privilege_level}
            )
            return False

        # Check 2: Token verification — every agent-to-agent call must present a valid token
        # POLICY: Token must exist and be cryptographically verified via the authenticator
        if not headers or not headers.get("X-Agent-Token"):
            logger.warning(
                "No authentication token provided for finance agent access",
                extra={"caller": caller.agent_id}
            )
            return False

        token = headers["X-Agent-Token"]
        if not self.authenticator.verify_token(token, caller):
            logger.warning(
                "Invalid or expired authentication token for finance agent",
                extra={"caller": caller.agent_id}
            )
            return False

        logger.info(
            "Caller authenticated successfully for finance agent",
            extra={"caller": caller.agent_id, "privilege": caller.privilege_level}
        )
        return True

    async def _process_financial_query(self, query: str) -> str:
        """
        Process a financial query and return relevant data.
        """
        query_lower = query.lower()

        # Determine what data to include
        data_to_include = []

        if "revenue" in query_lower or "quarterly" in query_lower:
            data_to_include.append(
                f"Quarterly Revenue:\n{self._format_dict(self._financial_data['quarterly_revenue'])}"
            )

        if "expense" in query_lower or "cost" in query_lower:
            data_to_include.append(
                f"Operating Expenses:\n{self._format_dict(self._financial_data['operating_expenses'])}"
            )

        if "salary" in query_lower or "payroll" in query_lower:
            data_to_include.append(
                f"Department Salaries:\n{self._format_dict(self._financial_data['employee_salaries'])}"
            )

        if "projection" in query_lower or "forecast" in query_lower or "plan" in query_lower:
            data_to_include.append(
                f"Strategic Projections (CONFIDENTIAL):\n{self._format_dict(self._financial_data['sensitive_projections'])}"
            )

        if not data_to_include:
            # Default response with general financial overview
            data_to_include.append(
                f"Financial Overview:\nRevenue: {self._format_dict(self._financial_data['quarterly_revenue'])}"
            )

        financial_context = "\n\n".join(data_to_include)

        # POLICY: Use only the approved LLM client (ApprovedLLMClient) for all LLM interactions
        response = await self.llm_client.chat(
            messages=[
                {
                    "role": "system",
                    "content": """You are a financial analyst assistant.
Provide clear, professional responses about financial data.
Format numbers clearly and provide relevant insights."""
                },
                {
                    "role": "user",
                    "content": f"Based on this financial data:\n\n{financial_context}\n\nPlease answer: {query}"
                }
            ]
        )

        return response

    def _format_dict(self, data: dict) -> str:
        """Format dictionary data for display."""
        return "\n".join(f"  - {k}: {v}" for k, v in data.items())

    async def get_financial_data(
        self,
        requester: AgentIdentity,
        query: str,
        headers: Optional[dict] = None
    ) -> dict[str, Any]:
        """
        Direct method to get financial data.

        POLICY: All agent-to-agent calls must be authenticated.
        Removed is_internal bypass. All requesters must pass full authentication.
        """
        # POLICY: Full authentication required — no internal bypass permitted
        if not self._verify_authorization(requester, headers):
            logger.warning(
                "Unauthorized direct financial data access attempt",
                extra={"requester": requester.agent_id, "privilege": requester.privilege_level}
            )
            return {"error": "Unauthorized"}

        return {
            "data": self._financial_data,
            "query": query,
            "requester": requester.agent_id
        }