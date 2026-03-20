#!/usr/bin/env python3
"""
fake_server.py — Simulated Java Deserialization Endpoint
Two modes: --mode patched | --mode vulnerable

OOB simulation:
  When a gadget chain executes RCE, this server calls back to a local
  OOB collector (running on port 8889) — simulating a real DNS/HTTP
  callback to a canary domain.

  Run order:
    Terminal 1: python3 fake_server.py --mode patched
    Terminal 2: python3 verify_deserial_local.py
"""
import time, argparse, threading, requests as req
from http.server import HTTPServer, BaseHTTPRequestHandler

JAVA_MAGIC = b'\xac\xed\x00\x05'

# OOB collector runs on this port (same machine)
OOB_COLLECTOR_URL = "http://127.0.0.1:8889/hit"

def classify_payload(data: bytes) -> str:
    if len(data) < 2:
        return "malformed"
    if data[:2] != b'\xac\xed':
        return "malformed"
    if len(data) == 23:
        return "benign"
    if len(data) >= 8 and data[7:8] == b'\x01':
        return "cc6_chain"
    if len(data) >= 8 and data[7:8] == b'\x02':
        return "spring_chain"
    if data[:4] == JAVA_MAGIC:
        return "unknown_java"
    return "malformed"

def fire_oob_callback(payload_id: str, delay: float = 1.0):
    """
    Simulates the server making an outbound HTTP callback to a canary domain.
    In a real scenario this would be a DNS lookup or curl to attacker.com.
    Here we POST to our local OOB collector with the payload_id as the token.
    Fired in a background thread after a short delay.
    """
    def _do_callback():
        time.sleep(delay)
        try:
            req.post(OOB_COLLECTOR_URL,
                     json={"token": payload_id.lower(), "source": "rce_gadget_chain"},
                     timeout=5)
            print(f"      [OOB] Callback fired for {payload_id} -> {OOB_COLLECTOR_URL}")
        except Exception as e:
            print(f"      [OOB] Callback failed: {e}")
    threading.Thread(target=_do_callback, daemon=True).start()


class DeserialHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        ct     = self.headers.get("Content-Type", "")
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)
        mode   = self.server.mode

        print(f"\n  --> POST {self.path}")
        print(f"      Bytes         : {len(body)}")
        print(f"      Hex preview   : {body.hex()}")
        print(f"      Content-Type  : {ct}")

        if "java-serialized-object" not in ct:
            print("      [!] Wrong Content-Type — 415")
            self._send(415, b'{"error":"Unsupported Media Type"}')
            return

        ptype = classify_payload(body)
        print(f"      Payload type  : {ptype}")

        # ── Extract payload_id from User-Agent header ──────────────────────
        # verify_deserial_local.py sends: User-Agent: RemediationVerifier/1.0 (TC-04)
        ua = self.headers.get("User-Agent", "")
        payload_id = "unknown"
        if "(" in ua and ")" in ua:
            payload_id = ua.split("(")[-1].rstrip(")")

        if mode == "vulnerable":
            if ptype == "malformed":
                print("      [VULNERABLE] Malformed — 400")
                self._send(400, b'{"error":"Invalid stream"}')
            elif ptype == "benign":
                print("      [VULNERABLE] Benign object — 200")
                self._send(200, b'{"status":"ok"}')
            else:
                print(f"      [VULNERABLE] Gadget chain — deserializing (6s)...")
                # Fire OOB callback in background BEFORE sleeping
                fire_oob_callback(payload_id, delay=2.0)
                time.sleep(6)
                print(f"      [VULNERABLE] RCE executed via {ptype}")
                self._send(200, b'{"status":"processed"}')

        elif mode == "patched":
            if ptype == "malformed":
                print("      [PATCHED] Malformed — 400")
                self._send(400, b'{"error":"Invalid stream"}')
            elif ptype == "benign":
                print("      [PATCHED] Class check PASS (java.lang.Long) — 200")
                self._send(200, b'{"status":"ok","class":"java.lang.Long"}')
            elif ptype == "cc6_chain":
                print("      [PATCHED] Class check BLOCKED CommonsCollections — 400")
                self._send(400, b'{"error":"Blocked: org.apache.commons.collections"}')
            elif ptype == "spring_chain":
                print("      [PATCHED] Class check MISSED Spring chain — BYPASS!")
                print(f"      [PATCHED] Firing OOB callback for {payload_id}...")
                # Fire OOB callback — RCE confirmed
                fire_oob_callback(payload_id, delay=2.0)
                time.sleep(6)
                print("      [PATCHED] Spring chain RCE executed — fix is INCOMPLETE!")
                self._send(200, b'{"status":"processed"}')
            else:
                self._send(400, b'{"error":"Unknown payload"}')

    def _send(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(f"      Response      : HTTP {code}")


# ── Local OOB Collector ────────────────────────────────────────────────────────
# Simulates Burp Collaborator / interactsh / canarytokens
# Stores incoming hits so the verifier can poll for them

oob_hits = []  # shared list of received callback tokens

class OOBCollectorHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def do_POST(self):
        """Receive an OOB callback hit from the server."""
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)
        try:
            import json
            data  = json.loads(body)
            token = data.get("token", "")
            oob_hits.append(token)
            print(f"\n  [OOB COLLECTOR] HIT received! token={token}")
        except:
            pass
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"recorded"}')

    def do_GET(self):
        """
        Poll endpoint — verifier calls this to check for callbacks.
        Returns all hits as plain text, one per line.
        URL format: /api/hits?token=tc-04
        """
        import urllib.parse
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        token  = params.get("token", [""])[0].lower()

        # Return all hits that match the requested token
        matched = [h for h in oob_hits if token in h]
        body    = "\n".join(matched).encode() if matched else b""

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["vulnerable","patched"], default="patched")
    parser.add_argument("--port", type=int, default=8888)
    args = parser.parse_args()

    # Start OOB collector on port 8889
    oob_server = HTTPServer(("127.0.0.1", 8889), OOBCollectorHandler)
    oob_thread = threading.Thread(target=oob_server.serve_forever, daemon=True)
    oob_thread.start()
    print(f"[*] OOB collector started on http://127.0.0.1:8889")

    # Start main deserialization server
    server = HTTPServer(("127.0.0.1", args.port), DeserialHandler)
    server.mode = args.mode

    print(f"[*] Deserialization server started")
    print(f"[*] Mode   : {args.mode.upper()}")
    print(f"[*] Listen : http://127.0.0.1:{args.port}")
    print()
    if args.mode == "patched":
        print("    TC-01 (CC6)       -> BLOCKED  -> 400        -> PASS")
        print("    TC-02 (benign)    -> ALLOWED  -> 200        -> PASS")
        print("    TC-03 (bad magic) -> REJECTED -> 400        -> PASS")
        print("    TC-04 (Spring)    -> BYPASS   -> 200 + OOB  -> FAIL")
    else:
        print("    TC-01 (CC6)       -> RCE -> 200 + 6s + OOB -> FAIL")
        print("    TC-02 (benign)    -> OK  -> 200             -> PASS")
        print("    TC-03 (bad magic) -> REJECTED -> 400        -> PASS")
        print("    TC-04 (Spring)    -> RCE -> 200 + 6s + OOB -> FAIL")
    print()
    print("[*] Waiting for requests... (Ctrl+C to stop)\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Servers stopped.")

if __name__ == "__main__":
    main()
