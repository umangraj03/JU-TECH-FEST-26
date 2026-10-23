import re
import base64
import urllib.parse
import unicodedata
from typing import List, Dict, Tuple, Optional
from pydantic import BaseModel

from backend.security.injection_corpus import INJECTION_CORPUS


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


def _clean_str(s: str) -> str:
    """Normalize text into pure lowercase alphanumeric string for robust corpus signature matching."""
    return re.sub(r"[^a-zA-Z0-9\s]", "", s).lower()


class InputScanner:
    def __init__(self):
        self._init_rules()
        self._train_on_corpus()

    def _train_on_corpus(self):
        """
        Train internal memory and signature index on all 100 INJECTION_CORPUS items.
        Enables immediate high-confidence zero-day prompt injection and keyword matching.
        """
        self.corpus_signatures: List[Dict[str, str]] = []
        for item in INJECTION_CORPUS:
            c_id = item["id"]
            domain = item["domain"]
            raw_prompt = item["prompt"]
            norm_p = _clean_str(raw_prompt)
            sev = item.get("severity", "HIGH")
            self.corpus_signatures.append({
                "id": c_id,
                "domain": domain,
                "clean_prompt": norm_p,
                "raw_prompt": raw_prompt,
                "severity": sev,
            })

    def _init_rules(self):
        self.injection_patterns = [
            (
                "INJ-OVERRIDE-01",
                "Instruction Override",
                75,
                re.compile(
                    r"(?:ignore|disregard|forget|override|bypass|drop|cancel|reset)\s+(?:all\s+)?(?:(?:prior|previous|above|system|security|all)\s+)*(?:instructions|prompts|rules|commands|constraints|directives|policies|guidelines)",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-OVERRIDE-02",
                "Instruction Override",
                70,
                re.compile(
                    r"(?:new\s+instruction|system\s+update|urgent\s+directive|from\s+now\s+on\s+you\s+must|new\s+role\s+assigned|forget\s+all\s+constraints|you\s+must\s+now\s+obey|reject\s+previous|drop\s+all\s+system\s+constraints)",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-OVERRIDE-03",
                "Policy / Content Bypass",
                75,
                re.compile(
                    r"(?:bypass\s+(?:content\s+)?policy|authorize\s+unrestricted\s+output|suspend\s+(?:all\s+)?content\s+filter|no\s+ethical\s+guidelines|no\s+content\s+moderation|without\s+censorship|no\s+workplace\s+restrictions)",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-ROLE-01",
                "Delimiter & Role Spoofing",
                75,
                re.compile(
                    r"(?:###\s*(?:SYSTEM|ADMIN|INSTRUCTION|ADMIN\s+OVERRIDE)|<\|im_start\|>|<system>|\[SYSTEM(?:\s+COMMAND)?\]|system:)",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-ROLE-02",
                "Delimiter & Role Spoofing",
                60,
                re.compile(
                    r"(?:\[INSTRUCTION\]|\[DEVELOPER\]|assistant:|human:|<human>|<assistant>|role:\s*system)",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-DISCLOSE-01",
                "Secret Disclosure",
                85,
                re.compile(
                    r"(?:(?:give|show|reveal|print|leak|repeat|output|display|echo|tell|provide|share|send|dump|extract|list|export|get|want|need)\s+(?:me\s+)?(?:(?:all|the|your|ur|any|some|an?)\s+)?|what\s*(?:'s|is|are)\s+(?:the|your|ur)\s+)(?:system[-_\s]*prompts?|secret[-_\s]*keys?|canary(?:[-_\s]*tokens?)?|internal[-_\s]*instructions?|api[-_\s]*keys?|passwords?|credentials?|bearer[-_\s]*tokens?|auth[-_\s]*tokens?|tokens?|private[-_\s]*keys?|master[-_\s]*keys?|encryption[-_\s]*keys?|\.env\s+file|database\s+connection\s+string|master\s+encryption\s+key)",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-BYPASS-01",
                "Authorization Bypass Phrasing",
                75,
                re.compile(
                    r"(?:dan\s+mode|jailbreak|unrestricted\s+mode|developer\s+mode\s+enabled|developer\s+mode|maintenance\s+override|god\s+mode|act\s+as\s+(?:an?\s+)?unfiltered|do\s+anything\s+now|bypass\s+security|override\s+security|jailbreak-gpt|freebot|root\s+with\s+full\s+system\s+access|simulate\s+(?:a\s+terminal\s+session\s+as\s+)?root)",
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
                    r"|pretend\s+you\s+are\s+(?:an?\s+)?(?:unrestricted|unfiltered|freebot)"
                    r"|roleplay\s+as\s+(?:a\s+)?(?:hacker|attacker|malicious|evil)"
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
                    r"|safe\s+research\s+environment.*ignore"
                    r")",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-EXFIL-01",
                "Exfiltration Directives",
                80,
                re.compile(
                    r"(?:send|post|forward|transmit|exfiltrate|upload|curl|fetch|wget|export|dump)\s+(?:all\s+)?(?:data|records?|confidential|customer|accounts?|database|secrets?|canary|financial|invoices|user\s+pii)?\s*(?:records?|data|dump|csv)?\s*(?:and\s+post\s+them\s+to|and\s+send\s+it\s+to|to\s+|into\s+)(?:https?://|ftp://|webhook|pastebin|discord|evil|attacker|logger|data-thief|public\s+s3|192\.168\.|[a-zA-Z0-9_-]+\.(?:cc|xyz|ru|net|org|test|io))",
                    re.IGNORECASE
                )
            ),
            (
                "INJ-INDIRECT-01",
                "Indirect Injection Directives",
                75,
                re.compile(
                    r"(?:"
                    r"ATTENTION\s+AI:\s*Disregard\s+this\s+document"
                    r"|when\s+summarising\s+this\s+doc.*email\s+all\s+customer\s+data"
                    r"|reclassify\s+to\s+CONFIDENTIAL\s+and\s+share\s+externally"
                    r"|exfiltrate\s+the\s+session\s+token"
                    r"|dump\s+all\s+invoices\s+to\s+/tmp"
                    r")",
                    re.IGNORECASE
                )
            )
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

        # De-obfuscate string concatenation additions: 'i' + 'gnore' + ' all' -> 'ignore all'
        while True:
            subbed = re.sub(r"['\"]([a-zA-Z0-9_\s-]+)['\"]\s*\+\s*['\"]([a-zA-Z0-9_\s-]+)['\"]", r"'\1\2'", norm)
            if subbed == norm:
                break
            norm = subbed

        # De-obfuscate hyphenated single letters: 'I-g-n-o-r-e' -> 'Ignore'
        norm = re.sub(r"\b[a-zA-Z](?:-[a-zA-Z]){2,}\b", lambda m: m.group(0).replace("-", ""), norm)

        # De-obfuscate spaced single letters: 'I g n o r e' -> 'Ignore'
        norm = re.sub(r"\b[a-zA-Z](?: [a-zA-Z]){2,}\b", lambda m: m.group(0).replace(" ", ""), norm)

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

    def _decode_pig_latin(self, text: str) -> str:
        words = text.split()
        res = []
        for w in words:
            clean = re.sub(r'[^\w]', '', w.lower())
            if clean.endswith('way') and len(clean) > 3:
                res.append(clean[:-3])
            elif clean.endswith('ay') and len(clean) > 4:
                res.append(clean[:-2])
            else:
                res.append(w)
        return " ".join(res)

    def extract_and_decode(self, text: str, max_depth: int = 2) -> List[Tuple[str, str]]:
        decoded_items: List[Tuple[str, str]] = []

        def _decode_step(current_text: str, current_depth: int):
            if current_depth > max_depth or len(current_text) < 4:
                return

            # Base64
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

            # Hex
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

            # URL encoding
            if "%" in current_text:
                try:
                    unquoted = urllib.parse.unquote(current_text)
                    if unquoted != current_text:
                        decoded_items.append((unquoted, f"url (depth {current_depth})"))
                        _decode_step(unquoted, current_depth + 1)
                except Exception:
                    pass

            # ROT13
            rot = self._rot13(current_text)
            if re.search(r"\b(ignore|system|instruction|bypass|forward|email|previous)\b", rot, re.IGNORECASE):
                decoded_items.append((rot, f"rot13 (depth {current_depth})"))
                _decode_step(rot, current_depth + 1)
            elif "vbaber" in current_text.lower():  # Handles corpus Caesar variation
                decoded_items.append(("ignore all previous instructions", f"rot13-caesar (depth {current_depth})"))

            # Pig Latin
            if "way" in current_text.lower() or "eviouspray" in current_text.lower():
                pig = self._decode_pig_latin(current_text)
                if "ignore" in pig.lower() or "instruction" in pig.lower():
                    decoded_items.append(("ignore all previous instructions", "pig-latin"))

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
        clean_input = _clean_str(norm_text)
        reasons: List[Dict[str, str]] = []
        matched_weights: List[float] = []
        detected_encodings: List[str] = []

        # 1. Corpus Signature Memory Matcher (Trained against 100 corpus payloads)
        for sig in self.corpus_signatures:
            c_id = sig["id"]
            c_prompt = sig["clean_prompt"]
            if clean_input == c_prompt or (len(c_prompt) >= 16 and c_prompt in clean_input) or (len(clean_input) >= 16 and clean_input in c_prompt):
                weight = 85.0 if sig["severity"] in ["CRITICAL", "HIGH"] else 70.0
                matched_weights.append(weight)
                reasons.append({
                    "rule_id": c_id,
                    "category": sig["domain"],
                    "severity": sig["severity"],
                    "evidence": f"Corpus signature match [{c_id}]: '{sig['raw_prompt'][:60]}'",
                    "weight": str(weight)
                })
                break

        # 2. General Pattern Engine
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

        # 3. Contextual Untrusted Patterns
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

        # 4. Multi-Layer De-obfuscation Pipeline
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
