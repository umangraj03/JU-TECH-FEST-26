from typing import Optional, Literal
from pydantic import BaseModel, ConfigDict, Field


class SearchDocumentsArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(..., min_length=1, max_length=200)
    classification: Optional[str] = Field(None, max_length=32)


class GetCustomerRecordArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    customer_id: str = Field(..., min_length=1, max_length=64)


class SummarizeReportArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    report_id: str = Field(..., min_length=1, max_length=64)
    format: Optional[str] = Field("executive", max_length=32)


class ExportReportArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    report_id: str = Field(..., min_length=1, max_length=64)
    destination: str = Field(..., min_length=3, max_length=256)
    format: Optional[str] = Field("json", max_length=32)


class SendEmailArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    recipient: str = Field(..., min_length=3, max_length=256)
    subject: str = Field(..., min_length=1, max_length=256)
    body: str = Field(..., min_length=1, max_length=10000)


class UpdateCustomerRecordArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    customer_id: str = Field(..., min_length=1, max_length=64)
    field: str = Field(..., min_length=1, max_length=64)
    new_value: str = Field(..., min_length=1, max_length=1024)


TOOL_ARG_SCHEMAS = {
    "search_documents": SearchDocumentsArgs,
    "get_customer_record": GetCustomerRecordArgs,
    "summarize_report": SummarizeReportArgs,
    "export_report": ExportReportArgs,
    "send_email": SendEmailArgs,
    "update_customer_record": UpdateCustomerRecordArgs,
}
