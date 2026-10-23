import json
import os
import uuid
import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session
from backend.app.config import settings
from backend.tools.base import BaseTool, GatewayExecutionContext
from backend.models.db_models import DocumentModel, CustomerRecordModel


class SearchDocumentsTool(BaseTool):
    name = "search_documents"
    description = "Search corporate knowledge base and reports"
    is_write = False
    requires_approval = False

    def _run(self, args: Dict[str, Any], context: GatewayExecutionContext, db_session: Optional[Session]) -> Dict[str, Any]:
        query = args.get("query", "").lower()
        classification = args.get("classification")

        if not db_session:
            return {"results": [], "count": 0, "trust_level": "UNTRUSTED"}

        q = db_session.query(DocumentModel)
        if classification:
            q = q.filter(DocumentModel.classification == classification)

        all_docs = q.all()
        matched = []
        for doc in all_docs:
            if query in doc.title.lower() or query in doc.content.lower() or query in doc.id.lower():
                snippet = doc.content[:160] + "..." if len(doc.content) > 160 else doc.content
                matched.append({
                    "id": doc.id,
                    "title": doc.title,
                    "snippet": snippet,
                    "classification": doc.classification,
                    "author": doc.author,
                    "content": doc.content,  # Used by agent to inspect text
                    "trust_level": "UNTRUSTED"
                })

        return {
            "results": matched,
            "count": len(matched),
            "trust_level": "UNTRUSTED"
        }


class GetCustomerRecordTool(BaseTool):
    name = "get_customer_record"
    description = "Retrieve customer profile by account ID"
    is_write = False
    requires_approval = False

    def _run(self, args: Dict[str, Any], context: GatewayExecutionContext, db_session: Optional[Session]) -> Dict[str, Any]:
        cust_id = args.get("customer_id")
        if not db_session:
            return {"error": "Database session unavailable"}

        record = db_session.query(CustomerRecordModel).filter(CustomerRecordModel.id == cust_id).first()
        if not record:
            return {"error": f"Customer '{cust_id}' not found"}

        return {
            "id": record.id,
            "name": record.name,
            "company": record.company,
            "tier": record.tier,
            "email": record.email,
            "phone": record.phone,
            "classification": record.classification,
            "canary_token": record.canary_token,
            "trust_level": "UNTRUSTED"
        }


class SummarizeReportTool(BaseTool):
    name = "summarize_report"
    description = "Generate an executive summary of a document or dataset"
    is_write = False
    requires_approval = False

    def _run(self, args: Dict[str, Any], context: GatewayExecutionContext, db_session: Optional[Session]) -> Dict[str, Any]:
        report_id = args.get("report_id")
        doc = db_session.query(DocumentModel).filter(DocumentModel.id == report_id).first() if db_session else None

        if not doc:
            return {"error": f"Report '{report_id}' not found"}

        # Executive summary generation
        first_sentence = doc.content.split(".")[0] if "." in doc.content else doc.content[:100]
        summary = f"Executive Summary for '{doc.title}': {first_sentence}. Key metrics reviewed and documented."

        return {
            "id": doc.id,
            "title": doc.title,
            "summary": summary,
            "classification": doc.classification,
            "trust_level": "UNTRUSTED"
        }


class ExportReportTool(BaseTool):
    name = "export_report"
    description = "Export structured report data to an approved destination"
    is_write = False
    requires_approval = True

    def _run(self, args: Dict[str, Any], context: GatewayExecutionContext, db_session: Optional[Session]) -> Dict[str, Any]:
        report_id = args.get("report_id")
        destination = args.get("destination")
        fmt = args.get("format", "json")

        sandbox_dir = Path(settings.SANDBOX_DIR) / "exports"
        sandbox_dir.mkdir(parents=True, exist_ok=True)
        export_file = sandbox_dir / f"export_{report_id}_{uuid.uuid4().hex[:8]}.{fmt}"

        export_data = {
            "report_id": report_id,
            "destination": destination,
            "exported_at": datetime.datetime.utcnow().isoformat(),
            "records_count": 42,
            "format": fmt,
            "status": "COMPLETED"
        }
        with open(export_file, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2)

        return {
            "report_id": report_id,
            "destination": destination,
            "records_count": 42,
            "format": fmt,
            "sandbox_path": str(export_file),
            "status": "SUCCESS"
        }


class SendEmailTool(BaseTool):
    name = "send_email"
    description = "Transmit notification or report to a verified destination"
    is_write = True
    requires_approval = True

    def _run(self, args: Dict[str, Any], context: GatewayExecutionContext, db_session: Optional[Session]) -> Dict[str, Any]:
        recipient = args.get("recipient")
        subject = args.get("subject")
        body = args.get("body")

        sandbox_dir = Path(settings.SANDBOX_DIR) / "emails"
        sandbox_dir.mkdir(parents=True, exist_ok=True)
        email_id = f"email_{uuid.uuid4().hex[:8]}"
        email_file = sandbox_dir / f"{email_id}.json"

        email_data = {
            "email_id": email_id,
            "recipient": recipient,
            "subject": subject,
            "body": body,
            "sent_at": datetime.datetime.utcnow().isoformat(),
            "status": "DELIVERED_SIMULATED"
        }
        with open(email_file, "w", encoding="utf-8") as f:
            json.dump(email_data, f, indent=2)

        return {
            "recipient": recipient,
            "subject": subject,
            "body_preview": body[:80] + "..." if len(body) > 80 else body,
            "message_id": email_id,
            "sandbox_path": str(email_file),
            "status": "SENT"
        }


class UpdateCustomerRecordTool(BaseTool):
    name = "update_customer_record"
    description = "Modify customer record details"
    is_write = True
    requires_approval = True

    def _run(self, args: Dict[str, Any], context: GatewayExecutionContext, db_session: Optional[Session]) -> Dict[str, Any]:
        cust_id = args.get("customer_id")
        field = args.get("field")
        new_val = args.get("new_value")

        if not db_session:
            return {"error": "Database session unavailable"}

        record = db_session.query(CustomerRecordModel).filter(CustomerRecordModel.id == cust_id).first()
        if not record:
            return {"error": f"Customer '{cust_id}' not found"}

        if hasattr(record, field):
            setattr(record, field, new_val)
            db_session.commit()
            return {
                "customer_id": cust_id,
                "field": field,
                "new_value": new_val,
                "status": "UPDATED"
            }
        else:
            return {"error": f"Field '{field}' does not exist on customer record"}


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}

    def register(self, tool: BaseTool):
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def list_tools(self) -> List[str]:
        return list(self._tools.keys())

    def bind_gateway_secret(self, secret: str):
        for tool in self._tools.values():
            tool._bind_gateway_secret(secret)


# Default global tool registry instance
tool_registry = ToolRegistry()
tool_registry.register(SearchDocumentsTool())
tool_registry.register(GetCustomerRecordTool())
tool_registry.register(SummarizeReportTool())
tool_registry.register(ExportReportTool())
tool_registry.register(SendEmailTool())
tool_registry.register(UpdateCustomerRecordTool())
