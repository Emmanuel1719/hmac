from flask import Flask, request, jsonify
import hmac
import hashlib
import time

# Create the Flask application instance
app = Flask(__name__)

# Mapping of client identifiers to shared secret keys.
CLIENTS = {"client1": b"supersecretkey"}

# This prevents replay attacks by ensuring request uniqueness.
USED_NONCES = set()

# Maximum allowed time difference (in seconds) between client
# timestamp and server time. Requests outside this window are rejected.
TIME_WINDOW = 60  # seconds


def canonical_request(req, body_hash: str) -> str:
    """
    Creates a canonical representation of the HTTP request.

    The canonical request string makes sure that the client and server
    compute the HMAC over the exact same data. It associates the signature
    with the request method, endpoint, body content, timestamp, and nonce.
    """
    return (
        f"{req.method}\n"                        # HTTP method (e.g., POST)
        f"{req.path}\n"                          # API endpoint path
        f"{body_hash}\n"                         # SHA-256 hash of request body
        f"{req.headers.get('X-Timestamp')}\n"   # Client timestamp
        f"{req.headers.get('X-Nonce')}"          # Client nonce
    )


@app.route("/apply", methods=["POST"])
def apply():
    """
    Secure API endpoint for graduate applications.

    Requests must be authenticated with HMAC-SHA256 and contain valid
    timestamps and nonce values to avoid replay.
    """

    # Extract authentication headers from the incoming request
    cid = request.headers.get("X-Client-Id")
    ts = request.headers.get("X-Timestamp")
    nonce = request.headers.get("X-Nonce")
    sig = request.headers.get("X-Signature")

    # Ensure all required authentication headers are present
    if not all([cid, ts, nonce, sig]):
        return jsonify({"error": "Missing headers"}), 401

    # Verify that the client identifier is recognised
    if cid not in CLIENTS:
        return jsonify({"error": "Unknown client"}), 401

    # Validate the timestamp to ensure the request is recent
    now = int(time.time())
    if abs(now - int(ts)) > TIME_WINDOW:
        return jsonify({"error": "Expired timestamp"}), 401

    # Check if the nonce has already been used
    # If so, the request is considered a replay attack
    if nonce in USED_NONCES:
        return jsonify({"error": "Replay detected"}), 401

    # Read the raw request body and compute its SHA-256 hash
    # This binds the HMAC signature to the exact request payload
    body = request.get_data() or b""
    body_hash = hashlib.sha256(body).hexdigest()

    # Reconstruct the canonical request string on the server
    canon = canonical_request(request, body_hash)

    # Recompute the expected HMAC signature using the shared secret
    expected = hmac.new(
        CLIENTS[cid],
        canon.encode(),
        hashlib.sha256
    ).hexdigest()

    # Compare the received signature with the expected signature
    # compare_digest is used to mitigate timing attacks
    if not hmac.compare_digest(expected, sig):
        return jsonify({"error": "Invalid signature"}), 401

    # Store the nonce after successful verification
    # This prevents the same request from being replayed
    USED_NONCES.add(nonce)

    # All security checks passed — process the request
    return jsonify({"status": "Application accepted"}), 200


if __name__ == "__main__":
    # Start the Flask development server.
    app.run(host="0.0.0.0", port=5000)
