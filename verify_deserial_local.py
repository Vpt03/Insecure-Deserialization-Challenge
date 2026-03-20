#!/usr/bin/env python3
"""
verify_deserial_local.py
Points at local fake_server.py (127.0.0.1:8888)
OOB collector also local (127.0.0.1:8889)
"""
import requests, base64, json, time, hashlib, os
from datetime import datetime, timezone

CONFIG = {
    "target": "http://127.0.0.1:8888/api/v1/session/restore",
    "finding": "insecure_deserialization",
    "content_type": "application/x-java-serialized-object",
    "payloads": [
        {
            "id": "TC-01",
            "description": "CommonsCollections6 gadget chain",
            "encoding": "hex",
            "data": "aced000573720001"   # byte[7]=01 -> classified as cc6_chain
        },
        {
            "id": "TC-02",
            "description": "Benign serialized object (control)",
            "encoding": "base64",
            "data": "rO0ABXNyAA5qYXZhLmxhbmcuTG9uZzs="  # 23 bytes -> benign
        },
        {
            "id": "TC-03",
            "description": "Invalid magic bytes",
            "encoding": "hex",
            "data": "deadbeef0001"   # no AC ED header -> malformed
        },
        {
            "id": "TC-04",
            "description": "Spring gadget chain",
            "encoding": "hex",
            "data": "aced000573720002"   # byte[7]=02 -> classified as spring_chain
        }
    ],
    "canary_domain": "find0139.oob.yourplatform.com",
    "expected_rejection_code": 400,
    # Points to local OOB collector running inside fake_server.py on port 8889
    "oob_poll_url": "http://127.0.0.1:8889/api/hits?token="
}

TIMING_THRESHOLD = 5.0
OOB_WINDOW       = 12   # seconds to poll after each send
OOB_INTERVAL     = 2    # seconds between polls


def decode_payload(payload):
    enc  = payload.get("encoding", "").lower()
    data = payload.get("data", "")
    try:
        if enc == "hex":
            if len(data) % 2 != 0:
                data += "0"
            return bytes.fromhex(data)
        elif enc == "base64":
            missing = len(data) % 4
            if missing:
                data += "=" * (4 - missing)
            return base64.b64decode(data)
        else:
            print(f"  [!] Unknown encoding for {payload['id']}")
            return None
    except Exception as e:
        print(f"  [!] Decode error for {payload['id']}: {e}")
        return None


def send_payload(target, raw_bytes, content_type, payload_id):
    """
    Send payload with Content-Type header.
    Also embeds payload_id in User-Agent so the server knows which
    test case triggered an OOB callback.
    """
    headers = {
        "Content-Type": content_type,
        # payload_id in User-Agent = correlation token the server reads
        "User-Agent": f"RemediationVerifier/1.0 ({payload_id})"
    }
    start = time.monotonic()
    try:
        r       = requests.post(target, data=raw_bytes, headers=headers, timeout=30)
        elapsed = time.monotonic() - start
        return r.status_code, round(elapsed, 2), r.text
    except requests.exceptions.RequestException as e:
        elapsed = time.monotonic() - start
        print(f"  [!] Request failed: {e}")
        return -1, round(elapsed, 2), ""


def poll_oob_callback(base_poll_url, payload_id,
                      window=OOB_WINDOW, interval=OOB_INTERVAL):
    """
    Poll local OOB collector for `window` seconds.
    URL format: http://127.0.0.1:8889/api/hits?token=tc-04
    The collector returns the token in the body if a hit was registered.

    Key design: payload_id is the correlation token — even if multiple
    payloads fire callbacks we know exactly which one triggered.
    """
    # Build poll URL with lowercase token (server stores lowercase)
    poll_url = base_poll_url + payload_id.lower()
    deadline = time.monotonic() + window
    oob_body = ""
    attempts = 0

    print(f"    [OOB] Polling {window}s window (every {interval}s)...")
    print(f"    [OOB] Collector: {poll_url}")

    while time.monotonic() < deadline:
        attempts += 1
        try:
            r        = requests.get(poll_url, timeout=5)
            oob_body = r.text.strip()
            if oob_body:  # any non-empty response = hit registered
                print(f"    [OOB] CALLBACK HIT on poll {attempts}! Response: '{oob_body}'")
                return True, oob_body
        except requests.exceptions.RequestException:
            pass  # collector not yet ready or request failed — keep polling
        time.sleep(interval)

    print(f"    [OOB] No callback after {attempts} polls ({window}s)")
    return False, oob_body


def evaluate_result(payload, status, elapsed, body,
                    oob_hit, expected_code, canary):
    anomalies = []

    # A1 — Wrong status code
    if status != expected_code:
        if payload["id"] != "TC-02":  # TC-02 is expected to return 200
            anomalies.append(
                f"Unexpected status {status} (expected {expected_code})")

    # A2 — Timing anomaly
    if elapsed > TIMING_THRESHOLD:
        anomalies.append(f"Timing anomaly ({elapsed}s > {TIMING_THRESHOLD}s)")

    # A3 — Canary in response body
    if canary in body:
        anomalies.append("Canary domain found in response body")

    # A4 — OOB callback = definitive RCE confirmation
    if oob_hit:
        anomalies.append("OOB callback received — RCE confirmed")

    note = ""
    if payload["id"] == "TC-02" and not oob_hit:
        note = "Control test accepted as expected"
    elif payload["id"] == "TC-03" and status == expected_code:
        note = "Malformed stream correctly rejected"

    return {
        "id":           payload["id"],
        "description":  payload["description"],
        "encoding":     payload["encoding"],
        "status_code":  status,
        "elapsed_sec":  elapsed,
        "oob_callback": oob_hit,
        "anomalies":    anomalies,
        "result":       "PASS" if not anomalies else "FAIL",
        "note":         note
    }


def print_report(config, results, timestamp):
    print("\n" + "=" * 44)
    print("===== REMEDIATION VERIFICATION REPORT =====")
    print("=" * 44)
    print(f"Finding  : {config['finding']}")
    print(f"Target   : {config['target']}")
    print(f"Timestamp: {timestamp}")
    print()
    failed = 0
    for r in results:
        oob = "YES" if r["oob_callback"] else "NO"
        print(f"[{r['id']}] Description : {r['description']}")
        print(f"       Encoding    : {r['encoding']}")
        print(f"       Status      : {r['status_code']} | "
              f"Time: {r['elapsed_sec']}s | OOB Callback: {oob}")
        if r["anomalies"]:
            print(f"       Result      : {r['result']} -- {' + '.join(r['anomalies'])}")
            failed += 1
        elif r["note"]:
            print(f"       Result      : {r['result']} -- {r['note']}")
        else:
            print(f"       Result      : {r['result']}")
        print()
    verdict = "REMEDIATION VERIFIED" if failed == 0 else "REMEDIATION FAILED"
    print(f"===== VERDICT: {verdict} =====")
    print(f"Failed Tests: {failed} / {len(results)}")
    print("=" * 44 + "\n")


def save_evidence(config, results, timestamp):
    os.makedirs("evidence", exist_ok=True)
    safe_ts   = timestamp.replace(":", "-").replace("T", "_").rstrip("Z")
    json_path = f"evidence/report_{safe_ts}.json"
    hash_path = json_path.replace(".json", ".sha256")
    evidence  = {"finding": config["finding"], "target": config["target"],
                 "timestamp": timestamp, "results": results}
    report_json = json.dumps(evidence, indent=2)
    with open(json_path, "w") as f:
        f.write(report_json)
    digest = hashlib.sha256(report_json.encode()).hexdigest()
    with open(hash_path, "w") as f:
        f.write(digest + "\n")
    print(f"[+] Evidence saved : {json_path}")
    print(f"[+] SHA-256        : {digest}")
    print(f"[+] Hash file      : {hash_path}")


def run_verification(config):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    results   = []

    print(f"\n[*] FIND-0139 Remediation Verification")
    print(f"[*] Target      : {config['target']}")
    print(f"[*] OOB Polling : {config['oob_poll_url']}<payload_id>")
    print(f"[*] Payloads    : {len(config['payloads'])}")
    print(f"[*] Started     : {timestamp}")
    print("-" * 44)

    for payload in config["payloads"]:
        print(f"\n[>] {payload['id']} — {payload['description']}")

        # Step 1: Decode
        raw = decode_payload(payload)
        if raw is None:
            results.append({
                "id": payload["id"], "description": payload["description"],
                "encoding": payload["encoding"], "status_code": -1,
                "elapsed_sec": 0.0, "oob_callback": False,
                "anomalies": ["Decode failed"], "result": "ERROR", "note": ""
            })
            continue
        print(f"    Decoded  : {len(raw)} bytes | {raw.hex()}")

        # Step 2: Send — payload_id passed so server embeds it in OOB callback
        status, elapsed, body = send_payload(
            config["target"], raw, config["content_type"], payload["id"]
        )
        print(f"    Response : HTTP {status} in {elapsed}s")

        # Step 3: Poll OOB collector
        oob_hit, oob_body = poll_oob_callback(
            config["oob_poll_url"], payload["id"]
        )

        # Step 4: Evaluate
        result = evaluate_result(
            payload, status, elapsed, body, oob_hit,
            config["expected_rejection_code"], config["canary_domain"]
        )
        if oob_hit and oob_body:
            result["oob_response_body"] = oob_body

        results.append(result)

    # Step 5: Report + Evidence
    print_report(config, results, timestamp)
    save_evidence(config, results, timestamp)


if __name__ == "__main__":
    run_verification(CONFIG)
