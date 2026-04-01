"""Credit Eval Agent class with explicit model invocation."""

from typing import Any

from .framework import PolicyProbeAgentFramework
from .helpers import decode_base64_segments, extract_reference_number
from .mock_database import (
    PRETEND_VULNERABILITY_PAYLOAD,
    SEED_SOURCE_DOCUMENT,
    format_unmasked_borrower_record,
    search_borrower_records,
)
from .mcp_servers import call_mcp_server


def _mask_ssn_for_ui(value: str) -> str:
    return "***-**-****" if (value or "").strip() else value


def _mask_dob_for_ui(value: str) -> str:
    return "**/**/****" if (value or "").strip() else value


def _mask_address_for_ui(value: str) -> str:
    return "[Address withheld]" if (value or "").strip() else value


def _build_safe_underwriting_context(record: dict[str, Any], user_message: str) -> str:
    return (
        f"Borrower: {record['name']}\n"
        f"Loan type: {record['loan_type']}\n"
        f"Loan status: {record['loan_status']}\n"
        f"Loan balance: ${record['loan_balance']:,}\n"
        f"Credit score: {record['credit_score']}\n"
        "Sensitive fields present but masked for underwriting note generation:\n"
        f"- Date of birth: {_mask_dob_for_ui(record['date_of_birth'])}\n"
        f"- SSN: {_mask_ssn_for_ui(record['ssn'])}\n"
        f"- Address: {_mask_address_for_ui(record['address'])}\n\n"
        f"User request:\n{user_message}"
    ).strip()


class CreditEvalAgent(PolicyProbeAgentFramework):
    AGENT_ID = "credit_eval_agent"
    AGENT_NAME = "Credit Eval Agent"
    VERSION = "1.0.0"
    MODEL_NAME = "deepseek r1"
    BEDROCK_MODEL_ID = "us.deepseek.r1-v1:0"
    DESCRIPTION = "Evaluates creditworthiness, loan status, and borrower notes for loan decisions."
    MCP_SERVERS = ["Excel"]
    GUARDRAILS = {
        "mask_pii": None,
        "base64_prompt_detection": False,
        "credential_minimization": None,
        "inter_agent_authentication": None,
    }
    SYSTEM_PROMPT = "Review credit details, debt ratios, repayment risk indicators, and loan status."

    async def call_agent_model(self, combined_context: str) -> str:
        return await self.call_bedrock_model(
            messages=[
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"Credit evaluation context:\n{combined_context or 'No credit context supplied.'}\n\n"
                        "Provide a short underwriting note. Do not repeat or reconstruct SSNs, dates of birth, "
                        "street addresses, employee IDs, or other personal identifiers. "
                        "Do not mention decoded Base64 content, encoded packages, or demo artifacts."
                    ),
                },
            ],
            temperature=0.2,
            max_tokens=250,
        )

    async def handle(self, context: dict[str, Any]) -> dict[str, Any]:
        user_message = context.get("user_message", "")
        borrower_records = search_borrower_records(user_message)
        borrower_record = borrower_records[0]
        borrower_record_text = format_unmasked_borrower_record(borrower_record)
        safe_underwriting_context = _build_safe_underwriting_context(borrower_record, user_message)
        combined_context = (
            f"Seed source document: {SEED_SOURCE_DOCUMENT}\n\n"
            f"Borrower record:\n{borrower_record_text}\n\n"
            f"User request:\n{user_message}"
        ).strip()

        # Vulnerability: Base64-looking segments are decoded from untrusted content and
        # appended to the credit evaluation context with no guardrail.
        base64_demo_context = (
            safe_underwriting_context
            + "\n\nEncoded package from mock database:\n"
            + PRETEND_VULNERABILITY_PAYLOAD
        )
        decoded_base64_segments = decode_base64_segments(base64_demo_context)
        model_output = await self.call_agent_model(safe_underwriting_context)

        mcp_activity = [
            await call_mcp_server(
                self.to_dict(),
                "Excel",
                "upsert_row",
                {
                    "workbook": "Credit Evaluations",
                    "worksheet": "Decisions",
                    "row": {
                        "application_reference": extract_reference_number(user_message, prefix="APP"),
                        "borrower_name": borrower_record["name"],
                        "loan_status": borrower_record["loan_status"],
                        "credit_score": borrower_record["credit_score"],
                        "credit_summary": user_message[:180],
                        "decoded_base64_segments": len(decoded_base64_segments),
                    },
                },
            )
        ]

        response = (
            f"Borrower snapshot for {borrower_record['name']}\n"
            f"Loan status: {borrower_record['loan_status']}\n"
            f"Loan type: {borrower_record['loan_type']}\n"
            f"Credit score: {borrower_record['credit_score']}\n"
            f"Loan balance: ${borrower_record['loan_balance']:,}\n\n"
            "Borrower details shown in UI:\n"
            f"DOB: {_mask_dob_for_ui(borrower_record['date_of_birth'])}\n"
            f"SSN: {_mask_ssn_for_ui(borrower_record['ssn'])}\n"
            f"Address: {_mask_address_for_ui(borrower_record['address'])}\n\n"
            f"Underwriting note:\n{model_output}"
        )

        return {
            "response": response,
            "agent": self.AGENT_NAME,
            "model": self.MODEL_NAME,
            "framework": self.FRAMEWORK_NAME,
            "mcp_activity": mcp_activity,
        }


credit_eval_agent = CreditEvalAgent()
