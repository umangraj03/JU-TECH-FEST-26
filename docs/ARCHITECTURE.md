# CY-03 AI Agent Security Guard — Architecture Specification

## 1. System Overview
The **AI Agent Security Guard** is an explainable security gateway situated directly between a business AI agent (simulated LLM) and the execution environment of tools and data stores.

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
                      |    Input Scanner (Layered)  |  <- Obfuscation decode, rule & context checks
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
                      |    Audit & Hash-Chaining    |  <- Tamper-evident ledger
                      +-----------------------------+
```

## 2. Trust Boundaries & Invariants
1. **Tool Invocation Invariant**:
   Simulated tools **CANNOT** be called directly by any business logic. All tool invocations must pass through `gateway.execute(principal, tool_call, context)`. A dedicated architectural test verifies that direct tool calls fail or are forbidden by design.
2. **Untrusted Data Boundary**:
   Any document retrieved from search, incoming email body, or tool result is stamped with `trust_level: UNTRUSTED`. Untrusted text can never instruct the agent to elevate privileges, change policies, or route data to unapproved destinations.
3. **Deterministic Taint Tracking**:
   Arguments originating from untrusted context (e.g. extracted email address or domain in a prompt injection) inherit a `tainted: true` tag. A tainted destination will always trigger `MANDATORY_DENY`.
4. **Chain Depth Limits**:
   - Max tool calls per request: **5**
   - Max retrieval recursive depth: **2**
   Exceeding limits triggers an immediate `CHAIN_LIMIT_EXCEEDED` block.

## 3. Decision Precedence
Decisions are evaluated strictly according to:
$$\text{MANDATORY\_DENY} \succ \text{DENY} \succ \text{REQUIRE\_APPROVAL} \succ \text{ALLOW}$$

| Decision Level | Description | Can Be Overridden by Human Approver? |
|---|---|---|
| **MANDATORY_DENY** | Violations of unapproved domains, canary leaks, direct injection bypass, or tainted destinations. | **NO**. Even an approver's token cannot force execution. |
| **DENY (BLOCK)** | Missing role authorization, access to unauthorized record classes, schema validation failures. | **NO**. Requester must adjust permissions or inputs. |
| **REQUIRE_APPROVAL** | Sensitive write operations (`update_customer_record`) or authorized confidential exports to approved destinations. | **YES**, pending approval by a user with role `approver`. |
| **ALLOW** | All security gates pass with Low/tolerated risk score and full authorization. | N/A (Executes automatically). |

## 4. Hash-Chained Audit Ledger
Every request and decision writes an immutable log record with:
- `entry_id` (UUIDv4)
- `prev_hash` (SHA-256 of the prior log entry, or 64 zeroes for genesis)
- `current_hash` = $\text{SHA256}(\text{prev\_hash} + \text{canonical\_json}(\text{record}))$
- `redacted_payload`: All PII, API tokens, and confidential fields are replaced with cryptographic hashes or sanitized tokens.
The verification endpoint `GET /api/audit/verify` iterates through all entries to prove no tampering, deletion, or reordering occurred.
