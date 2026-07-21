import requests
import time
import uuid
import hmac
import hashlib
import json

URL = "http://127.0.0.1:5000/apply"

# Client identifier and shared secret key.
CLIENT_ID = "client1"
SECRET = b"supersecretkey"


def sign(body, timestamp, nonce):
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = f"POST\n/apply\n{body_hash}\n{timestamp}\n{nonce}"
    return hmac.new(SECRET, canonical.encode(), hashlib.sha256).hexdigest()


# Create a valid request payload
# This payload represents a legitimate application submission
payload = json.dumps({
    "name": "Sophia",
    "degree": "COMPUTER SCIENCE"
}).encode()

# Generate freshness and uniqueness values
timestamp = str(int(time.time()))
# Nonce ensures the request cannot be replayed
nonce = str(uuid.uuid4())

# Generate the HMAC signature
signature = sign(payload, timestamp, nonce)

# Payload is modified AFTER signing — simulating an attacker tampering with the request
# The signature is now invalid for this new payload
payload = json.dumps({
    "name": "Ben",
    "degree": "COMPUTER SCIENCE"
}).encode()

# Prepare HTTP authentication headers
headers = {
    "X-Client-Id": CLIENT_ID,
    "X-Timestamp": timestamp,
    "X-Nonce": nonce,
    "X-Signature": signature,
    "Content-Type": "application/json"
}

# Send the tampered request — server should reject with 401 Invalid signature
response = requests.post(URL, data=payload, headers=headers)
print(response.status_code, response.text)
