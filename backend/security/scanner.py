import re
import base64
import urllib.parse
import unicodedata
from typing import List, Dict, Tuple, Optional
from pydantic import BaseModel


class ScanResult(BaseModel):
    threat_score: float  # 0 to 100
    severity: str        # LOW, MEDIUM, HIGH, CRITICAL
    reasons: List[Dict[str, str]]
    normalized_text: str
    detected_encodings: List[str]


HOMOGLYPH_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'ѕ': 's', 'х': 'x', 'у': 'y',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J', 'К': 'K',
    'М': 'M', 'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X', 'Ү': 'Y', 'і': 'i', 'ј': 'j',
    'α': 'a', 'β': 'b', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'τ': 't',
}

INVISIBLE_CHARS_REGEX = re.compile(
    r'[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E\u2060-\u206F\x00]'
)


class InputScanner:
    def __init__(self):
        self._init_rules()

    def _init_rules(self):
        self.injection_patterns = [
            (
                "INJ-OVERRIDE-01",
                "Instruction Override",
                75,
                re.compile(
                    r"(?:ignore|disregard|forget|override|bypass|drop|cancel|reset)\s+(?:all\s+)?(?:(?:prior|previous|above|system|security|all)\s+)*(?:instructions|prompts|rules|commands|constraints|directives|policies)",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-OVERRIDE-02",
                "Instruction Override",
                70,
                re.compile(
                    r"(?:new\s+instruction|system\s+update|urgent\s+directive|from\s+now\s+on\s+you\s+must|new\s+role\s+assigned|forget\s+all\s+constraints|you\s+must\s+now\s+obey)",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-ROLE-01",
                "Delimiter & Role Spoofing",
                75,
                re.compile(
                    r"(?:###\s*(?:SYSTEM|ADMIN|INSTRUCTION)|<\|im_start\|>|<system>|\[SYSTEM(?:\s+COMMAND)?\]|system:)",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-ROLE-02",
                "Delimiter & Role Spoofing",
                60,
                re.compile(
                    r"(?:\[INSTRUCTION\]|\[DEVELOPER\]|assistant:|human:|<human>|<assistant>)",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-DISCLOSE-01",
                "Secret Disclosure",
                85,
                re.compile(
                    r"(?:(?:give|show|reveal|print|leak|repeat|output|display|echo|tell|provide|share|send|dump|extract|list|export|get|want|need)\s+(?:me\s+)?(?:(?:all|the|your|ur|any|some|an?)\s+)?|what\s*(?:'s|is|are)\s+(?:the|your|ur)\s+)(?:system[-_\s]*prompts?|secret[-_\s]*keys?|canary(?:[-_\s]*tokens?)?|internal[-_\s]*instructions?|api[-_\s]*keys?|passwords?|credentials?|bearer[-_\s]*tokens?|auth[-_\s]*tokens?|tokens?|private[-_\s]*keys?|master[-_\s]*keys?|encryption[-_\s]*keys?)",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-BYPASS-01",
                "Authorization Bypass Phrasing",
                75,
                re.compile(
                    r"(?:dan\s+mode|jailbreak|unrestricted\s+mode|developer\s+mode\s+enabled|developer\s+mode|maintenance\s+override|god\s+mode|act\s+as\s+(?:an?\s+)?unfiltered|do\s+anything\s+now|bypass\s+security|override\s+security)",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-BYPASS-02",
                "Role / Persona Hijacking",
                80,
                re.compile(
                    r"(?:"
                    r"you\s+are\s+(?:now\s+)?(?:dan|jailbreak[\w-]*|freebot|an?\s+unfiltered|an?\s+unrestricted)"
                    r"|act\s+as\s+(?:an?\s+)?(?:unfiltered|unrestricted|hacker|evil)"
                    r"|enter\s+(?:god|dan|jailbreak|developer|maintenance)\s+mode"
                    r"|switch\s+to\s+(?:developer|unrestricted|god|jailbreak)\s+mode"
                    r"|pretend\s+you\s+are\s+(?:an?\s+)?(?:unrestricted|unfiltered)"
                    r"|roleplay\s+as\s+(?:a\s+)?(?:hacker|attacker|malicious|evil)"
                    r")",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-BYPASS-03",
                "Content Filter Removal",
                75,
                re.compile(
                    r"(?:"
                    r"disable\s+(?:all\s+)?(?:content\s+)?filters?"
                    r"|suspend\s+(?:all\s+)?(?:content\s+)?filter"
                    r"|no\s+(?:ethical\s+guidelines|content\s+moderation|content\s+filter|restrictions|rules|censorship)"
                    r"|without\s+censorship"
                    r"|safety\s+restrictions?\s+(?:are\s+)?(?:lifted|disabled|removed|off)"
                    r"|all\s+(?:safety\s+)?(?:measures?|filters?|constraints?)\s+(?:are\s+)?(?:disabled|removed|lifted|off)"
                    r")",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-SYNTAX-01",
                "Fake Tool Call Syntax",
                70,
                re.compile(
                    r"(?:\{\s*\"tool\"\s*:\s*\"[a-zA-Z0-9_]+\"|<function=[a-zA-Z0-9_]+>|CALL_TOOL\s*[:\[]\s*[a-zA-Z0-9_]+|TOOL_CALL\s+[a-zA-Z0-9_]+)",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-SYNTAX-02",
                "Fake Tool Call – Admin/Auth Bypass",
                80,
                re.compile(
                    r"(?:"
                    r"(?:execute|run|call|invoke|use)\s+(?:the\s+)?(?:send_email|export_report|update_customer_record|get_customer_record|delete_all_records)\b"
                    r"|authenticate\s+as\s+admin"
                    r"|bypass_dlp\s*="
                    r"|overrideAuth\s*="
                    r"|admin\s*=\s*true"
                    r")",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-SOCIAL-01",
                "Social Engineering Pretext",
                65,
                re.compile(
                    r"(?:"
                    r"(?:urgent|critical)\s+(?:security\s+)?(?:alert|audit|directive|notice)"
                    r"|management\s+directive"
                    r"|(?:i\s+am|this\s+is)\s+(?:your\s+)?(?:developer|admin|ceo|cto|it\s+security|ai\s+safety\s+team)"
                    r"|(?:penetration|pen)\s+test\s+authorized"
                    r"|for\s+(?:testing|research)\s+purposes\s*[,.]?\s*(?:disable|ignore|bypass|remove)"
                    r"|your\s+license\s+has\s+expired"
                    r"|you\s+have\s+been\s+granted\s+(?:special\s+)?admin"
                    r"|legal\s+compliance\s+requires?"
                    r")",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-DELIMITER-02",
                "YAML / Markdown Role Delimiter",
                70,
                re.compile(
                    r"(?:"
                    r"role\s*:\s*(?:system|admin|developer|root)"
                    r"|###\s*(?:ADMIN|DEVELOPER|ROOT|OVERRIDE)"
                    r"|\[(?:ADMIN|DEVELOPER|ROOT|OVERRIDE)(?:\s+(?:COMMAND|DIRECTIVE|MODE))?\]"
                    r"|###\s*ADMIN\s*OVERRIDE"
                    r")",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-EXFIL-01",
                "Exfiltration Directives",
                80,
                re.compile(
                    r"(?:send|post|forward|transmit|exfiltrate|upload|curl|fetch|wget|export)\s+(?:all\s+)?(?:data|records?|confidential|customer|accounts?|database|secrets?|canary)?\s*(?:records?|data)?\s*(?:to\s+|into\s+)(?:https?://|ftp://|webhook|pastebin|discord|evil|attacker|[a-zA-Z0-9_-]+\.(?:com|org|net|io|test|cc|ru|internal))",
                    re.IGNORECASE
                )
            ),
        ]

        self.context_patterns = [
            (
                "CTX-IMPERATIVE-01",
                "Untrusted Imperative Directive",
                50,
                re.compile(
                    r"(?:you\s+(?:must|should|have\s+to|are\s+required\s+to)\s+(?:now\s+)?(?:send|email|forward|export|update|delete|execute|call))",
                    re.IGNORECASE
                )
            ),
            (
                "CTX-TOOL-MENTION-01",
                "Contextual Tool Command Injection",
                50,
                re.compile(
                    r"(?:use\s+(?:the\s+)?(?:send_email|export_report|update_customer_record|get_customer_record)\s+tool|execute\s+(?:send_email|export_report|update_customer_record))",
                    re.IGNORECASE
                )
            ),
            (
                "CTX-HIDDEN-COMMAND",
                "Hidden Exfiltration Instructions",
                50,
                re.compile(
                    r"(?:forward\s+to|send\s+all\s+confidential\s+data\s+to|mail\s+to\s+[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+)",
                    re.IGNORECASE
                )
            ),
        ]

    def normalize(self, text: str) -> str:
        if not text:
            return ""
        norm = unicodedata.normalize("NFKC", text)
        norm = INVISIBLE_CHARS_REGEX.sub("", norm)
        norm = "".join(HOMOGLYPH_MAP.get(c, c) for c in norm)
        norm = re.sub(r"[ \t]+", " ", norm)
        norm = re.sub(r"\n\s*\n+", "\n", norm)
        return norm.strip()

    def _rot13(self, s: str) -> str:
        res = []
        for c in s:
            if 'a' <= c <= 'z':
                res.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                res.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
            else:
                res.append(c)
        return "".join(res)

    def extract_and_decode(self, text: str, max_depth: int = 2) -> List[Tuple[str, str]]:
        decoded_items: List[Tuple[str, str]] = []

        def _decode_step(current_text: str, current_depth: int):
            if current_depth > max_depth or len(current_text) < 6:
                return

            b64_matches = re.findall(r"(?:^|[\s:=,])([A-Za-z0-9+/]{12,}={0,2})(?:[\s;,]|$)", current_text)
            for m in b64_matches:
                try:
                    raw_bytes = base64.b64decode(m, validate=True)
                    decoded_str = raw_bytes.decode("utf-8", errors="ignore")
                    if len(decoded_str) >= 4 and any(c.isalpha() for c in decoded_str):
                        decoded_items.append((decoded_str, f"base64 (depth {current_depth})"))
                        _decode_step(decoded_str, current_depth + 1)
                except Exception:
                    pass

            hex_clean = re.sub(r"(?:\\x|0x|[\s,])", "", current_text)
            hex_matches = re.findall(r"\b[0-9a-fA-F]{16,}\b", hex_clean)
            for m in hex_matches:
                if len(m) % 2 == 0:
                    try:
                        raw_bytes = bytes.fromhex(m)
                        decoded_str = raw_bytes.decode("utf-8", errors="ignore")
                        if len(decoded_str) >= 4 and any(c.isalpha() for c in decoded_str):
                            decoded_items.append((decoded_str, f"hex (depth {current_depth})"))
                            _decode_step(decoded_str, current_depth + 1)
                    except Exception:
                        pass

            if "%" in current_text:
                try:
                    unquoted = urllib.parse.unquote(current_text)
                    if unquoted != current_text:
                        decoded_items.append((unquoted, f"url (depth {current_depth})"))
                        _decode_step(unquoted, current_depth + 1)
                except Exception:
                    pass

            rot = self._rot13(current_text)
            if re.search(r"\b(ignore|system|instruction|bypass|forward|email)\b", rot, re.IGNORECASE):
                decoded_items.append((rot, f"rot13 (depth {current_depth})"))
                _decode_step(rot, current_depth + 1)

        _decode_step(text, 1)
        return decoded_items

    def scan(self, text: str, is_untrusted_context: bool = False) -> ScanResult:
        if not text:
            return ScanResult(
                threat_score=0.0,
                severity="LOW",
                reasons=[],
                normalized_text="",
                detected_encodings=[]
            )

        norm_text = self.normalize(text)
        reasons: List[Dict[str, str]] = []
        matched_weights: List[float] = []
        detected_encodings: List[str] = []

        for rule_id, category, weight, pattern in self.injection_patterns:
            m = pattern.search(norm_text)
            if m:
                snippet = m.group(0)[:60]
                matched_weights.append(weight)
                reasons.append({
                    "rule_id": rule_id,
                    "category": category,
                    "severity": "CRITICAL" if weight >= 55 else "HIGH",
                    "evidence": f"Found injection phrase: '{snippet}'",
                    "weight": str(weight)
                })

        if is_untrusted_context:
            for rule_id, category, weight, pattern in self.context_patterns:
                m = pattern.search(norm_text)
                if m:
                    snippet = m.group(0)[:60]
                    matched_weights.append(weight)
                    reasons.append({
                        "rule_id": rule_id,
                        "category": category,
                        "severity": "HIGH",
                        "evidence": f"Found untrusted context directive: '{snippet}'",
                        "weight": str(weight)
                    })

        decoded_candidates = self.extract_and_decode(text, max_depth=2)
        for dec_text, enc_type in decoded_candidates:
            detected_encodings.append(enc_type)
            norm_dec = self.normalize(dec_text)

            for rule_id, category, weight, pattern in self.injection_patterns + (self.context_patterns if is_untrusted_context else []):
                m = pattern.search(norm_dec)
                if m:
                    snippet = m.group(0)[:60]
                    compound_weight = min(75.0, max(55.0, weight * 1.2))
                    matched_weights.append(compound_weight)
                    reasons.append({
                        "rule_id": "OBF-ENCODED-PAYLOAD",
                        "category": "Obfuscated Injection",
                        "severity": "CRITICAL",
                        "evidence": f"Encoded ({enc_type}) hidden command matched {rule_id}: '{snippet}'",
                        "weight": str(compound_weight)
                    })
                    break

        if not matched_weights:
            total_score = 0.0
        else:
            primary = max(matched_weights)
            secondary = sum(w for w in matched_weights if w != primary)
            total_score = min(100.0, primary + 0.4 * secondary)

        if total_score >= 75.0:
            severity = "CRITICAL"
        elif total_score >= 50.0:
            severity = "HIGH"
        elif total_score >= 25.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return ScanResult(
            threat_score=round(total_score, 1),
            severity=severity,
            reasons=reasons,
            normalized_text=norm_text,
            detected_encodings=list(set(detected_encodings))
        )


scanner = InputScanner()
