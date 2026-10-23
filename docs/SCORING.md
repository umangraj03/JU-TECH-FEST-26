# CY-03 AI Agent Security Guard — Threat Scoring & Detection Engine

## 1. Overview
The **Input Scanner** inspects user prompts and retrieved documents using a multi-phase, layered defense pipeline. It does not rely on simple string equality or a single keyword list.

## 2. Multi-Stage Pipeline

```
Raw Text -> Unicode Normalization (NFKC)
         -> Strip Invisible & Bidi Control Characters
         -> Fold Homoglyphs & Obfuscation
         -> Bounded Multi-Encoding Decode (Base64, Hex, URL, ROT13 - max depth 2)
         -> Pattern & Rule Match Engine
         -> Contextual Semantic & Boundary Match Engine
         -> Weighted Score Aggregation (0 - 100)
         -> Severity Classification & Explanation Generation
```

### Stage 1: Text Normalization
1. **Unicode NFKC**: Canonical decomposition followed by canonical composition to neutralize full-width, compatibility, and decomposed representations.
2. **Invisible/Bidi Filtering**: Removal of zero-width spaces (`\u200B`), zero-width joiners (`\u200C`, `\u200D`), directional overrides (`\u202E`, `\u202B`), and null bytes.
3. **Homoglyph Folding**: Translates visually identical Cyrillic/Greek characters (e.g. Cyrillic `а`, `е`, `о`, `р`) back to Latin `a`, `e`, `o`, `p`.
4. **Whitespace & Delimiter Collapsing**: Compresses repeated whitespace and newline tricks used to break keyword matches.

### Stage 2: Bounded Recursive Decoder
Attackers often wrap payloads in Base64, Hexadecimal, URL percent-encoding, or ROT13.
- Recursion limit: **Max Depth 2**
- Minimum entropy & size requirements prevent false decoding on ordinary text.
- If decoded text matches an injection pattern, both the decoded content and the encoding anomaly are scored.

### Stage 3: Layered Detection Rules

| Rule ID | Category | Description | Base Weight |
|---|---|---|---|
| `INJ-OVERRIDE-01` | Instruction Override | Phrases like "ignore previous instructions", "disregard all prior rules", "forget your constraints". | 45 |
| `INJ-ROLE-02` | Delimiter & Role Spoofing | Pseudo-system markers: `system:`, `### SYSTEM`, `<system>`, `[INSTRUCTION]`, `assistant:`. | 40 |
| `INJ-DISCLOSE-03` | Secret Disclosure | Attempts to extract system prompts, API keys, canary tokens, or private instructions. | 50 |
| `INJ-SYNTAX-04` | Fake Tool Call Syntax | Embedded fake tool invocations like `{"tool": "send_email", ...}` or `<function=...>`. | 40 |
| `INJ-EXFIL-05` | Exfiltration Directives | Directives commanding transmission to external URLs, webhook, discord, pastebin, etc. | 55 |
| `INJ-BYPASS-06` | Auth Bypass Phrasing | Phrases claiming "override security", "admin debug mode", "unrestricted mode", "DAN". | 45 |
| `CTX-IMPERATIVE-01` | Untrusted Imperative | Second-person commands embedded inside retrieved documents ("You must now email..."). | 35 |
| `CTX-TOOL-MENTION-02`| Context Tool Mention | Retrieved document instructing the agent specifically to call a tool (`send_email`, `export_report`). | 45 |
| `CTX-TOPIC-MISMATCH` | Topic Command Mismatch | Embedded command unrelated to document metadata (e.g. quarterly report with webhook command). | 30 |
| `OBF-ENCODED-PAYLOAD`| Obfuscation Detected | Hidden instruction concealed via Base64, Hex, URL, or ROT13. | 35 |

## 3. Weighted Scoring Formula
The final threat score $S \in [0, 100]$ is calculated as:
$$S = \min\left(100, \sum_{i \in \text{Matches}} W_i \times C_i\right)$$
where:
- $W_i$ is the base weight of rule $i$.
- $C_i$ is the confidence multiplier (1.0 for explicit exact pattern matches; 0.7 for partial contextual anomalies; 1.3 for compounded attacks combining obfuscation with overrides).

### Severity Thresholds:
- **Low**: $0 \le S \le 24$ (Benign business queries or normal document reading).
- **Medium**: $25 \le S \le 49$ (Mild anomalies, benign technical terms; logged and monitored).
- **High**: $50 \le S \le 74$ (Explicit injection phrasing or unauthorized tool requests; blocked or escalated).
- **Critical**: $75 \le S \le 100$ (Blatant prompt injections, exfiltration directives, Canary leaks, or compound attacks; mandatory block).

## 4. Redaction of Evidence
Every match returns an explainable `reasons[]` array containing:
- `rule_id`: Standardized identifier.
- `category`: Category name.
- `severity`: Low, Medium, High, or Critical.
- `redacted_evidence`: An excerpt of the triggering text, with sensitive tokens, canaries, and PII replaced by `[REDACTED]`.
