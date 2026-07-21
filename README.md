# HMAC-Based API Authentication for Recruitment Platforms

A cryptographic authentication scheme designed and implemented to secure a simulated online graduate recruitment API handling sensitive candidate data (CVs, personal details, employer records).

## The Problem

Recruitment platforms handle sensitive personal data over public APIs, making authentication a critical attack surface. Common approaches like static API keys and basic bearer tokens don't cryptographically bind authentication to the actual content of a request — leaving them exposed to:

- **Replay attacks** – a captured valid request can be resent later
- **Message tampering** – request parameters can be altered without detection
- **Credential leakage** – static keys embedded in client code can be extracted and reused

## Proof of the Problem

To confirm this, I set up a test REST API (Python/Flask) protected only by a static API key, then used curl and Postman to intercept, replay, and modify authenticated requests. All of them were accepted by the server — demonstrating the complete absence of replay protection or integrity checking.

## The Solution: HMAC-SHA256 Request Signing

I designed and implemented an authentication scheme where each API request is cryptographically signed using HMAC-SHA256:

1. Each client is issued a unique client ID and shared secret key during registration
2. Every request is converted into a canonical form (HTTP method, path, query params, hash of body, timestamp, nonce)
3. The client signs this canonical request with its shared secret and attaches the signature, client ID, timestamp, and nonce as headers
4. The server independently recomputes the signature, checks the timestamp window, and verifies the nonce hasn't been used before — using constant-time comparison to prevent timing attacks
5. Requests failing any check are rejected and logged

## Results

Testing confirmed the scheme worked as designed:
-  Correctly signed requests from authorised clients were accepted
-  Requests modified after signing were rejected (signature mismatch)
-  Replayed requests (reused nonce) were rejected
-  Requests with expired timestamps were rejected
- Performance overhead from HMAC-SHA256 was negligible — no meaningful impact on request latency

## Why HMAC over OAuth 2.0 / JWT / mTLS?

| Approach | Trade-off |
|---|---|
| Static API keys | Simple, but no protection against replay or tampering |
| JWT | Stateless and verifiable, but bearer tokens are reusable if stolen |
| OAuth 2.0 | Powerful, fine-grained access control, but heavy setup/operational complexity |
| mTLS | Strong client authentication via certificates, but costly certificate lifecycle management |
| **HMAC-SHA256 (this project)** | Lightweight, cryptographically ties auth to request content, strong replay protection via timestamp + nonce, no third-party identity provider needed |

## Tech Used

Python, Flask, `hmac` and `hashlib` (Python standard library), curl, Postman

## Key Takeaway

This project reflects a security engineering approach: identify the threat model, prove the vulnerability practically (not just theoretically), design a proportionate cryptographic control, and validate it experimentally.
