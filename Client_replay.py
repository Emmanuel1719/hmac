import requests
import time
import hmac
import hashlib
import json

URL = "http://127.0.0.1:5000/apply"
CLIENT_ID = "client1"
SECRET = b"supersecretkey"


def sign(body, timestamp, nonce):
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = f"POST\n/apply\n{body_hash}\n{timestamp}\n{nonce}"
    return hmac.new(SECRET, canonical.encode(), hashlib.sha256).hexdigest()


# Create a valid request payload
payload = json.dumps({
    "name": "Sophia",
    "degree": "COMPUTER SCIENCE"
}).encode()

# Generate timestamp and FIXED nonce
timestamp = str(int(time.time()))
# Fixed nonce is intentionally reused to simulate a replay attack
nonce = "REPLAY-NONCE-123"

# Generate HMAC signature
signature = sign(payload, timestamp, nonce)

headers = {
    "X-Client-Id": CLIENT_ID,
    "X-Timestamp": timestamp,
    "X-Nonce": nonce,
    "X-Signature": signature,
    "Content-Type": "application/json"
}

# Send request once — accepted
response = requests.post(URL, data=payload, headers=headers)
print("First request:", response.status_code, response.text)

# Send same request again — should be rejected as a replay
response = requests.post(URL, data=payload, headers=headers)
print("Replay attempt:", response.status_code, response.text)
