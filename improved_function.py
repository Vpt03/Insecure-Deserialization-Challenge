#!/usr/bin/env python3
"""
improved_function.py — Part C: Improved version of the AI-generated function
This is the FUNCTION version (not the full pipeline) as Part C specifically asks for.
"""
import requests
import base64
import time


def check_deserialization(endpoint, payloads, canary_domain,
                          oob_poll_url, expected_status=400,
                          timing_threshold=5.0, oob_window=12,
                          oob_interval=2):
    """
    Sends serialized payloads to a target endpoint and detects whether
    deserialization was triggered via out-of-band DNS/HTTP callbacks.

    Args:
        endpoint        : target URL  e.g. "http://target/api/v1/session/restore"
        payloads        : list of dicts with keys: id, encoding, data
        canary_domain   : canary domain to watch  e.g. "find0139.oob.yours.com"
        oob_poll_url    : collector poll URL  e.g. "http://collector/hits?token="
        expected_status : HTTP status a fixed server should return (default 400)
        timing_threshold: seconds above which response is suspicious (default 5.0)
        oob_window      : seconds to poll OOB collector after each send (default 12)
        oob_interval    : seconds between each poll attempt (default 2)

    Returns:
        list of result dicts, one per payload
    """
    results = []

    for payload in payloads:
        print(f"\n[>] Sending {payload['id']} — {payload['description']}")
        result = {
            "id":           payload["id"],
            "description":  payload["description"],
            "status_code":  None,
            "elapsed_sec":  None,
            "oob_callback": False,
            "anomalies":    [],
            "verdict":      None
        }

        # ── STEP 1: Decode payload ─────────────────────────────────────────
        # FIX 6: handle decode errors gracefully instead of crashing
        raw_bytes = _decode(payload)
        if raw_bytes is None:
            result["anomalies"].append("Payload decode failed")
            result["verdict"] = "ERROR"
            results.append(result)
            continue

        # ── STEP 2: Send with correct Content-Type ─────────────────────────
        # FIX 3: embed payload ID in User-Agent as correlation token
        headers = {
            "Content-Type": "application/x-java-serialized-object",
            "User-Agent":   f"DeserialChecker/1.0 ({payload['id']})"
        }

        start = time.monotonic()
        try:
            resp    = requests.post(endpoint, data=raw_bytes,
                                    headers=headers, timeout=30)
            elapsed = round(time.monotonic() - start, 2)
            result["status_code"] = resp.status_code
            result["elapsed_sec"] = elapsed
            body = resp.text
            print(f"    HTTP {resp.status_code} in {elapsed}s")
        except requests.exceptions.RequestException as e:
            elapsed = round(time.monotonic() - start, 2)
            result["elapsed_sec"] = elapsed
            result["anomalies"].append(f"Request failed: {e}")
            result["verdict"] = "ERROR"
            results.append(result)
            continue

        # ── STEP 3: Anomaly signal A1 — wrong status code ──────────────────
        # FIX 5: check HTTP status — fixed server must return expected_status
        if resp.status_code != expected_status:
            if payload["id"] != "TC-02":  # TC-02 control is allowed to be 200
                result["anomalies"].append(
                    f"Status {resp.status_code} != expected {expected_status}")

        # ── STEP 4: Anomaly signal A2 — timing anomaly ─────────────────────
        # FIX 4: measure response time — gadget chains cause >5s delay
        if elapsed > timing_threshold:
            result["anomalies"].append(
                f"Timing anomaly {elapsed}s > {timing_threshold}s")

        # ── STEP 5: Anomaly signal A3 — canary in response body ────────────
        if canary_domain in body:
            result["anomalies"].append("Canary domain in response body")

        # ── STEP 6: Anomaly signal A4 — OOB callback ───────────────────────
        # FIX 1+2: poll the OOB collector with a time window
        # FIX 3:   use payload ID as correlation token
        oob_hit, oob_body = _poll_oob(
            oob_poll_url, payload["id"], oob_window, oob_interval
        )
        result["oob_callback"] = oob_hit
        if oob_hit:
            result["anomalies"].append("OOB callback received — RCE confirmed")

        # ── Verdict ────────────────────────────────────────────────────────
        result["verdict"] = "FAIL" if result["anomalies"] else "PASS"

        # Print result
        oob_label = "YES" if oob_hit else "NO"
        print(f"    OOB: {oob_label} | Anomalies: {result['anomalies']}")
        print(f"    Verdict: {result['verdict']}")

        results.append(result)

    return results


def _decode(payload):
    """Safely decode hex or base64 payload to raw bytes."""
    enc  = payload.get("encoding", "").lower()
    data = payload.get("data", "")
    try:
        if enc == "hex":
            if len(data) % 2 != 0:
                data += "0"                  # fix odd-length hex
            return bytes.fromhex(data)
        elif enc == "base64":
            missing = len(data) % 4
            if missing:
                data += "=" * (4 - missing)  # fix missing padding
            return base64.b64decode(data)
        else:
            print(f"    [!] Unknown encoding: {enc}")
            return None
    except Exception as e:
        print(f"    [!] Decode error: {e}")
        return None


def _poll_oob(base_url, payload_id, window, interval):
    """
    Poll OOB collector for `window` seconds after sending a payload.
    Returns (hit_detected: bool, response_body: str)

    This is the core fix over the raw AI output:
    - Raw AI checked response.text — WRONG, OOB never appears there
    - We poll a separate collector endpoint repeatedly
    - We use payload_id as the correlation token
    """
    poll_url = base_url + payload_id.lower()
    deadline = time.monotonic() + window
    attempts = 0
    print(f"    [OOB] Polling {window}s → {poll_url}")

    while time.monotonic() < deadline:
        attempts += 1
        try:
            r = requests.get(poll_url, timeout=5)
            if r.text.strip():
                print(f"    [OOB] HIT on poll {attempts}!")
                return True, r.text.strip()
        except Exception:
            pass
        time.sleep(interval)

    print(f"    [OOB] No hit after {attempts} polls")
    return False, ""


# ── Demo ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    PAYLOADS = [
        {"id": "TC-01", "description": "CommonsCollections6 gadget chain",
         "encoding": "hex",    "data": "aced000573720001"},
        {"id": "TC-02", "description": "Benign serialized object (control)",
         "encoding": "base64", "data": "rO0ABXNyAA5qYXZhLmxhbmcuTG9uZzs="},
        {"id": "TC-03", "description": "Invalid magic bytes",
         "encoding": "hex",    "data": "deadbeef0001"},
        {"id": "TC-04", "description": "Spring gadget chain",
         "encoding": "hex",    "data": "aced000573720002"},
    ]

    results = check_deserialization(
        endpoint        = "http://127.0.0.1:8888/api/v1/session/restore",
        payloads        = PAYLOADS,
        canary_domain   = "find0139.oob.yourplatform.com",
        oob_poll_url    = "http://127.0.0.1:8889/api/hits?token=",
        expected_status = 400,
        timing_threshold= 5.0,
        oob_window      = 12,
        oob_interval    = 2
    )

    print("\n===== RESULTS =====")
    for r in results:
        oob = "YES" if r["oob_callback"] else "NO"
        print(f"[{r['id']}] {r['verdict']} | "
              f"HTTP {r['status_code']} | "
              f"Time {r['elapsed_sec']}s | "
              f"OOB {oob}")
        if r["anomalies"]:
            for a in r["anomalies"]:
                print(f"       -> {a}")
