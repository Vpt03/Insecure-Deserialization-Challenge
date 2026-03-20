# raw_ai_output.py — Testing the broken AI version
import requests
import base64

def test_deserialization(endpoint, payloads, canary_domain):
    for payload in payloads:
        if payload['encoding'] == 'base64':
            data = base64.b64decode(payload['data'])
        else:
            data = bytes.fromhex(payload['data'])
        
        headers = {'Content-Type': 'application/x-java-serialized-object'}
        response = requests.post(endpoint, data=data, headers=headers)
        
        if canary_domain in response.text:
            print(f"Callback detected for {payload['id']}")
        else:
            print(f"No callback for {payload['id']}")

# Test it against our fake server
payloads = [
    {"id": "TC-01", "encoding": "hex",    "data": "aced000573720001"},
    {"id": "TC-02", "encoding": "base64", "data": "rO0ABXNyAA5qYXZhLmxhbmcuTG9uZzs="},
    {"id": "TC-03", "encoding": "hex",    "data": "deadbeef0001"},
    {"id": "TC-04", "encoding": "hex",    "data": "aced000573720002"},
]

test_deserialization(
    "http://127.0.0.1:8888/api/v1/session/restore",
    payloads,
    "find0139.oob.yourplatform.com"
)
