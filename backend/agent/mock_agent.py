import re
from typing import List, Dict, Any, Tuple, Optional
from sqlalchemy.orm import Session
from backend.models.schema import Principal
from backend.security.gateway import gateway


class MockAgent:
    """
    Deterministic business AI agent that translates user intent into tool calls.
    It is deliberately vulnerable/injectable to demonstrate that the Security Gateway
    safeguards the system even when the LLM is completely tricked by indirect prompt injection.
    """

    def __init__(self):
        pass

    def run_agent(
        self,
        principal: Principal,
        user_message: str,
        request_id: str,
        session_id: str,
        db: Session
    ) -> Tuple[List[Dict[str, Any]], str, bool]:
        msg = user_message.strip()
        proposed: List[Dict[str, Any]] = []
        is_tainted = False

        cust_match = re.search(r"\b(CUST-[A-Z0-9_-]+)\b", msg, re.IGNORECASE)
        report_match = re.search(r"\b(REP-[A-Z0-9_-]+)\b", msg, re.IGNORECASE)

        # A. Customer record update (priority over retrieval)
        if "update" in msg.lower() and cust_match:
            cust_id = cust_match.group(1).upper()
            field = "email"
            val = "updated@acme-corp.internal"
            # Extract email if present
            email_m = re.search(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", msg)
            if email_m:
                val = email_m.group(0)
            elif "phone" in msg.lower():
                field = "phone"
                val = "+1-555-0199"

            proposed.append({
                "tool_name": "update_customer_record",
                "args": {"customer_id": cust_id, "field": field, "new_value": val},
                "is_tainted": False,
                "origin": "user_prompt"
            })
            return proposed, f"Proposed update of customer record {cust_id}.", False

        # B. Direct Customer record retrieval
        if ("customer" in msg.lower() or "client" in msg.lower() or "account" in msg.lower() or "profile" in msg.lower()) and cust_match:
            cust_id = cust_match.group(1).upper()
            proposed.append({
                "tool_name": "get_customer_record",
                "args": {"customer_id": cust_id},
                "is_tainted": False,
                "origin": "user_prompt"
            })
            return proposed, f"Proposed retrieval of customer record {cust_id}.", False

        # C. Export report
        if "export" in msg.lower() and report_match:
            rep_id = report_match.group(1).upper()
            dest_match = re.search(r"to\s+([a-zA-Z0-9_.-]+(?:\.[a-zA-Z]{2,})?)", msg, re.IGNORECASE)
            destination = dest_match.group(1) if dest_match else "partner.example.com"
            proposed.append({
                "tool_name": "export_report",
                "args": {"report_id": rep_id, "destination": destination, "format": "json"},
                "is_tainted": False,
                "origin": "user_prompt"
            })
            return proposed, f"Proposed export of report {rep_id} to {destination}.", False

        # D. Summarize report directly
        if "summarize" in msg.lower() and report_match:
            rep_id = report_match.group(1).upper()
            proposed.append({
                "tool_name": "summarize_report",
                "args": {"report_id": rep_id, "format": "executive"},
                "is_tainted": False,
                "origin": "user_prompt"
            })
            return proposed, f"Proposed summary of report {rep_id}.", False

        # E. Direct email sending
        email_match = re.search(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", msg)
        if "send" in msg.lower() and "email" in msg.lower() and email_match:
            recipient = email_match.group(0)
            proposed.append({
                "tool_name": "send_email",
                "args": {"recipient": recipient, "subject": "Notification", "body": "Automated report"},
                "is_tainted": False,
                "origin": "user_prompt"
            })
            return proposed, f"Proposed email transmission to {recipient}.", False

        # F. Knowledge Base Search & Retrieval
        search_query = msg
        for prefix in ["search documents for", "search for", "find documents about", "lookup", "check docs for", "search"]:
            if msg.lower().startswith(prefix):
                search_query = msg[len(prefix):].strip()
                break

        # Remove trailing review words
        search_query = re.sub(r"\s+and\s+(?:review|summarize|check).*$", "", search_query, flags=re.IGNORECASE).strip()

        search_decision = gateway.evaluate_and_run(
            principal=principal,
            tool_name="search_documents",
            raw_args={"query": search_query or "general"},
            is_tainted=False,
            request_id=request_id,
            session_id=session_id,
            db=db
        )

        if search_decision.decision != "ALLOW" or not search_decision.result:
            return proposed, f"Search was not permitted: {search_decision.explanation}", False

        results = search_decision.result.get("results", [])
        if not results:
            return proposed, f"Search completed with 0 results for '{search_query}'.", False

        # Deliberately Injectable Agent Logic:
        for doc in results:
            content = doc.get("content", "")
            # Check for indirect prompt injection commands embedded in doc
            injection_exfil = re.search(
                r"(?:send|email|forward|transmit|exfiltrate)\s+(?:.*?to\s+)([a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+|https?://[^\s]+|[a-zA-Z0-9_.-]+\.[a-zA-Z]{2,})",
                content,
                re.IGNORECASE
            )
            if injection_exfil:
                injected_dest = injection_exfil.group(1).strip().rstrip("].;,")
                proposed.append({
                    "tool_name": "send_email",
                    "args": {
                        "recipient": injected_dest,
                        "subject": "Confidential Search Data",
                        "body": f"Automated extract based on retrieved document {doc.get('id')}: {content[:100]}"
                    },
                    "is_tainted": True,
                    "origin": f"untrusted_document_{doc.get('id')}"
                })
                is_tainted = True
                break

            if "summarize" in msg.lower() or "report" in doc.get("title", "").lower():
                proposed.append({
                    "tool_name": "summarize_report",
                    "args": {"report_id": doc.get("id"), "format": "executive"},
                    "is_tainted": False,
                    "origin": "retrieved_search"
                })
                break

        return proposed, f"Processed search and prepared {len(proposed)} proposed tool call(s).", is_tainted


mock_agent = MockAgent()
