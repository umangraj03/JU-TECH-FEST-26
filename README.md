# CY-03 — AI Agent Security Guard

A locally runnable, production-grade security gateway that sits directly between a simulated enterprise business AI agent and its tools. It inspects user input, retrieved knowledge documents, proposed tool calls, and outgoing data, returning an explainable decision (`ALLOW` / `BLOCK` / `REQUIRE_APPROVAL`) for each operation.

The gateway demonstrates active defense against **prompt injection**, **unauthorized tool usage**, and **sensitive data exfiltration**, utilizing a cryptographic hash-chained audit ledger and human-in-the-loop approval workflow.

---

## 1. Quickstart & Tooling

The project supports `make`, `npm`, and direct Python runner scripts (`python run.py`).

### Prerequisites
- Python 3.11+
- Node.js v18+ and npm

### Installation & Setup
```bash
# Option A: Using Make
make setup

# Option B: Using npm
npm run setup

# Option C: Using cross-platform Python runner
python run.py setup
```

### Seeding Fictional Data & Attack Corpus
```bash
make seed
# or: npm run seed
# or: python run.py seed
```
Seeds 12 documents (public reports, internal specs, and 6 malicious attack documents with obfuscated variants) and 5 confidential customer records with canary tokens.

### Running Test Suites
```bash
make test
# or: npm run test
# or: python run.py test
```
Executes all 30 Pytest cases across 7 test suites (`test_authz`, `test_injection`, `test_gateway`, `test_dlp`, `test_approval`, `test_audit`, `test_scenarios`).

### Running Development Services (Backend + Frontend)
```bash
make dev
# or: npm run dev
# or: python run.py dev
```
- **Backend (FastAPI)**: [http://127.0.0.1:8000](http://127.0.0.1:8000) (OpenAPI docs at `/docs`)
- **Frontend (Vite + React 18)**: [http://localhost:5173](http://localhost:5173)

---

## 2. Architecture & Request Flow

```
                      +-----------------------------+
                      |       User / Client         |
                      +--------------+--------------+
                                     |
                                (1) Request
                                     v
                      +-----------------------------+
                      |         Auth Layer          |  <- Bearer Token Principal
                      +--------------+--------------+
                                     |
                                (2) Normalized Message
                                     v
                      +-----------------------------+
                      |    Input Scanner (Layered)  |  <- Normalization, decode, pattern & context
                      +--------------+--------------+
                                     |
                            Risk Assessment & Score
                                     v
                      +-----------------------------+
                      |      Agent (Simulated)      |  <- Deliberately injectable mock
                      +--------------+--------------+
                                     |
                               Proposes Tool Calls
                                     v
========================== GATEWAY ENFORCEMENT BOUNDARY ==========================
                      +-----------------------------+
                      |       Security Gateway      |
                      |  1. Allowlist Check         |
                      |  2. Schema Validation       |
                      |  3. Authorization (RBAC)    |
                      |  4. Taint & Provenance      |
                      |  5. Data Classification     |
                      |  6. Destination Matching    |
                      |  7. DLP & Egress Budget     |
                      |  8. Policy Engine Decision  |
                      +--------------+--------------+
                                     |
              +----------------------+----------------------+
              |                      |                      |
          [ALLOW]           [REQUIRE_APPROVAL]           [BLOCK]
              |                      |                      |
              v                      v                      v
     +-----------------+    +-----------------+    +-----------------+
     | gateway.execute |    | Approval Queue  |    | Execution Halt  |
     | Tool Execution  |    | (Payload Hash)  |    | Explanation Log |
     +--------+--------+    +-----------------+    +-----------------+
              |
         Tool Output (Labeled UNTRUSTED)
              v
     +-----------------+
     |  Output Filter  |  <- Canary, PII, redaction
     +--------+--------+
              |
              +----------------------+
                                     v
                      +-----------------------------+
                      |    Audit & Hash-Chaining    |  <- Cryptographic SHA-256 ledger
                      +-----------------------------+
```

### Hard Security Invariants
1. **Isolated Tool Invocation**: Tools can **only** be executed via `gateway.execute()`. Calling tool methods directly raises `DirectToolInvocationForbidden`.
2. **Decision Precedence**:
   $$\text{MANDATORY\_DENY} \succ \text{DENY} \succ \text{REQUIRE\_APPROVAL} \succ \text{ALLOW}$$
   Approval **can never** override a mandatory-deny rule (e.g. unapproved destination, tainted exfiltration path, canary leakage).
3. **Taint Tracking**: Any argument originating from untrusted context (retrieved document or email) is tagged tainted. Tainted destinations trigger a mandatory `BLOCK`.
4. **Cumulative Egress Budgeting**: Prevents split exfiltration attacks by enforcing a session-level byte limit (default: 5,000 bytes).
5. **Tamper-Evident Ledger**: Every decision is hash-chained to the prior record using SHA-256 (`current_hash = sha256(prev_hash + record)`).

---

## 3. Demo Principals & Bearer Tokens

Preconfigured tokens loaded via `.env`:

| Role | Principal ID | Bearer Token | Permissions |
|---|---|---|---|
| **`requester`** | `user_requester` | `token-requester-secret-key-101` | Public and internal reports, knowledge base search, proposing writes for approval. |
| **`approver`** | `user_approver` | `token-approver-secret-key-202` | All requester permissions + confidential record access + reviewing and authorizing approval tickets. |
| **`admin`** | `user_admin` | `token-admin-secret-key-303` | Full system supervisory access, policy updates (`PUT /api/policy`), audit log inspection. |

---

## 4. Scripted Scenarios

All 6 scenarios can be executed via API or the Demo Playground UI:

1. **`scenario_1` (Legit Public Report Summary)**: Requester requests summary of `REP-PUB-01`. Gateway decision: **`ALLOW`**.
2. **`scenario_2` (Indirect Prompt Injection)**: Agent retrieves document `MAL-DOC-01` containing an embedded injection command attempting exfiltration. Gateway intercepts tainted destination and unapproved domain: **`BLOCK`** (threat score: Critical).
3. **`scenario_3` (Restricted Record Access)**: Requester attempts to access confidential customer record `CUST-CONF-101`. Role authorization check blocks access: **`BLOCK`** with `RULE-AUTHZ-02`.
4. **`scenario_4` (Lookalike Domain Exfiltration)**: Outbound transmission to `partner.example.com.evil.test`. Registrable domain match fails: **`BLOCK`** with `RULE-MANDATORY-02`.
5. **`scenario_5` (Sensitive State Write Escalation)**: Update customer profile request. Escalates to **`REQUIRE_APPROVAL`** (`RULE-APPROVAL-01`). Approver reviews ticket, validates cryptographic payload hash, approves, and passes fresh gateway re-check: **`EXECUTED`**.
6. **`scenario_6` (Benign Request Suite)**: Suite of 5 distinct benign business queries. Expected: 100% **`ALLOW`** with **0 false positives**.

---

## 5. API Reference Summary

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/agent/run` | Execute user message or scenario with full input scan, agent proposal, and gateway filtering |
| `GET` | `/api/stats/overview` | Live KPI counters, threat severity distribution, tool invocations, and ledger integrity |
| `GET` | `/api/events` | Paginated live event stream (polled every 2s) with filter by decision and threat |
| `GET` | `/api/threats` | Aggregated threat categories, top defensive rules, and attack evidence |
| `GET/PUT` | `/api/policy` | Retrieve parsed policy or update `policies/default.yaml` (Admin only) |
| `GET` | `/api/approvals` | List approval requests filtered by status (`PENDING`, `APPROVED`, `REJECTED`) |
| `POST` | `/api/approvals/{id}/approve` | Review and execute approval ticket after fresh gateway re-evaluation |
| `POST` | `/api/approvals/{id}/reject` | Reject pending approval ticket with optional reason |
| `GET` | `/api/audit` | Searchable, paginated audit ledger with multi-field filtering |
| `GET` | `/api/audit/verify` | Cryptographic SHA-256 chain verification proving zero tampering or deletion |
| `GET` | `/api/scenarios` | List scripted scenario definitions |
| `POST` | `/api/scenarios/{id}/run` | Execute specific scenario with targeted principal role |
| `POST` | `/api/demo/reset` | Reset SQLite database to default seed state |

---

## 6. Known Limitations & Threat Model Assumptions
- **Heuristic & Rule-Based Scanner**: While layered (normalization, NFKC, homoglyphs, bounded multi-encoding decode, contextual pattern match), heuristic scanners cannot guarantee 100% detection of zero-day semantic evasions. Defense-in-depth ensures authorization and DLP independently prevent unauthorized access even when injection scanner misses an input.
- **Local Simulated Environment**: Authentication utilizes static demo tokens loaded via `.env`. In production, this would integrate with OAuth2/OIDC (e.g. Okta, Keycloak, or AWS Cognito) with JWT signature verification and mTLS.
- **Simulated Tools**: No real external emails or internet requests are sent. Exports and emails write to localized sandbox storage under `sandbox_storage/`.
