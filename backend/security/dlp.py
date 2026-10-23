import re
import base64
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from backend.models.db_models import SessionBudgetModel
from backend.app.config import settings

# Detectors
CANARY_REGEX = re.compile(r"CANARY-[A-Z0-9_-]+", re.IGNORECASE)
EMAIL_PII_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_PII_REGEX = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
SSN_ID_REGEX = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
API_KEY_REGEX = re.compile(r"\b(?:ak|sk|token|key|secret)_[a-zA-Z0-9_-]{16,}\b", re.IGNORECASE)
MARKDOWN_IMAGE_LEAK = re.compile(r"!\[.*?\]\((https?://[^\s)]+)\)", re.IGNORECASE)


class DLPScanner:
    """
    Data Loss Prevention and Leakage Prevention Module.
    Inspects outgoing arguments, proposed egress, canary tokens, PII,
    and enforces session cumulative egress limits and data minimization.
    """

    def __init__(self):
        pass

    def detect_canaries(self, text: str) -> List[str]:
        if not text:
            return []
        matches = CANARY_REGEX.findall(text)
        # Also inspect decoded base64 and hex strings for concealed canaries
        b64_cand = re.findall(r"\b[A-Za-z0-9+/]{16,}={0,2}\b", text)
        for m in b64_cand:
            try:
                dec = base64.b64decode(m).decode("utf-8", errors="ignore")
                matches.extend(CANARY_REGEX.findall(dec))
            except Exception:
                pass
        return list(set(matches))

    def detect_pii(self, text: str) -> List[Dict[str, str]]:
        if not text:
            return []
        findings = []
        for m in EMAIL_PII_REGEX.findall(text):
            findings.append({"type": "EMAIL", "match": m})
        for m in PHONE_PII_REGEX.findall(text):
            findings.append({"type": "PHONE", "match": m})
        for m in SSN_ID_REGEX.findall(text):
            findings.append({"type": "GOV_ID", "match": m})
        for m in API_KEY_REGEX.findall(text):
            findings.append({"type": "API_KEY", "match": m[:6] + "..."})
        return findings

    def check_embedded_query_leak(self, text: str) -> Tuple[bool, Optional[str]]:
        """Detects URLs or markdown images exfiltrating data via query parameters."""
        if not text:
            return False, None

        # Markdown image leaks
        img_match = MARKDOWN_IMAGE_LEAK.search(text)
        if img_match:
            url = img_match.group(1)
            parsed = urllib.parse.urlparse(url)
            if parsed.query:
                return True, f"Blocked markdown image query exfiltration: {url}"

        # URL with suspicious data payload query
        url_matches = re.findall(r"https?://[^\s)]+", text)
        for u in url_matches:
            parsed = urllib.parse.urlparse(u)
            if parsed.query and any(k in parsed.query.lower() for k in ["data=", "leak=", "token=", "canary=", "secret=", "record="]):
                return True, f"Blocked outbound URL embedding query payload: {u}"

        return False, None

    def validate_destination_exact(self, destination: str, approved_destinations: List[str]) -> Tuple[bool, Optional[str]]:
        """
        Exact registrable domain check against allowlist.
        Defeats:
        - Lookalikes (e.g. partner.example.com.evil.test)
        - Userinfo tricks (e.g. http://partner.example.com@evil.com)
        - Path/subdomain confusion
        """
        if not destination:
            return False, "Destination cannot be empty."

        dest_clean = destination.strip().lower()

        # Check if email address: extract domain
        if "@" in dest_clean and "://" not in dest_clean:
            dest_domain = dest_clean.split("@")[-1]
        else:
            # Parse URL
            if "://" not in dest_clean:
                dest_clean = "https://" + dest_clean
            try:
                parsed = urllib.parse.urlparse(dest_clean)
                dest_domain = parsed.hostname or dest_clean
            except Exception:
                dest_domain = dest_clean

        dest_domain = dest_domain.strip().lower()

        # Check exact registrable domain match
        for app in approved_destinations:
            app_lower = app.lower()
            if dest_domain == app_lower:
                return True, None

        return False, f"Domain '{dest_domain}' is not permitted. Must exactly match approved domains: {approved_destinations}"

    def check_and_update_egress_budget(self, session_id: str, payload_size_bytes: int, db: Session, max_budget: int) -> Tuple[bool, Optional[str]]:
        """Tracks and enforces cumulative session egress budget."""
        budget_record = db.query(SessionBudgetModel).filter(SessionBudgetModel.session_id == session_id).first()
        if not budget_record:
            budget_record = SessionBudgetModel(
                session_id=session_id,
                total_egress_bytes=0,
                tool_call_count=0
            )
            db.add(budget_record)
            db.commit()
            db.refresh(budget_record)

        projected = budget_record.total_egress_bytes + payload_size_bytes
        if projected > max_budget:
            return False, f"Cumulative session egress budget exceeded: {projected} > {max_budget} bytes."

        budget_record.total_egress_bytes = projected
        budget_record.tool_call_count += 1
        db.commit()
        return True, None

    def minimize_data(self, data: Dict[str, Any], field_allowlist: List[str]) -> Dict[str, Any]:
        """Field-level allowlist filtering for data minimization."""
        if not field_allowlist:
            return data
        return {k: v for k, v in data.items() if k in field_allowlist}

    def redact_sensitive(self, text: str) -> str:
        """Redacts canary tokens and sensitive PII from logs and explanations."""
        if not text:
            return ""
        # Redact Canaries
        redacted = CANARY_REGEX.sub("[REDACTED_CANARY]", text)
        # Redact SSNs
        redacted = SSN_ID_REGEX.sub("[REDACTED_ID]", redacted)
        # Redact API Keys
        redacted = API_KEY_REGEX.sub("[REDACTED_API_KEY]", redacted)
        return redacted


dlp_scanner = DLPScanner()
