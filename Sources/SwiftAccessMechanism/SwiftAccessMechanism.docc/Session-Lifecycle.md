# Session Lifecycle

Understanding device mode, session mode, and the transition between them.

## Overview

``ProtocolSession`` manages two encryption modes:

1. **Device mode** (initial): ECDH-ES encryption using server's public key
2. **Session mode** (after OPAQUE): Direct symmetric encryption using session key

## State Diagram

```
┌──────────────────┐
│  Initialization  │
│                  │
│  ProtocolSession(│
│    clientPrivKey,│
│    serverPubKey) │
└────────┬─────────┘
         │
         v
┌──────────────────┐
│   DEVICE MODE    │
│                  │
│  Encryption:     │
│  ECDH-ES         │
│                  │
│  Operations:     │
│  - Register      │
│  - Authenticate  │
└────────┬─────────┘
         │
         │ enterSession(sessionId, sessionKey)
         │ (after OPAQUE authentication)
         v
┌──────────────────┐
│   SESSION MODE   │
│                  │
│  Encryption:     │
│  Direct          │
│  (sessionKey)    │
│                  │
│  Operations:     │
│  - HSM ops       │
└──────────────────┘
```

## Device Mode

**When:** Before OPAQUE authentication completes.

**Encryption:** ECDH-ES + A256GCM
- Uses server's public key
- Creates ephemeral key pair per request
- ECDH produces shared secret for content encryption

**Operations:**
- OPAQUE registration start/finish
- OPAQUE authentication start/finish

**Example (Protocol layer):**

```swift
import SwiftAccessMechanism

let serverParams = try ServerParameters()
let clientPrivateKey: SecKey = ... // P-256 private key

// Initialize in device mode
var session = try ProtocolSession(
    clientPrivateKey: clientPrivateKey,
    serverPublicKey: serverParams.serverPublicKey
)

// session.mode == .device
// session.sessionId == nil

// Build registration request (encrypted with ECDH-ES)
let regStart = try ProtocolRequest.registrationStart(password: password)
let jws = try regStart.outerRequest.toJWS(signer: session.signer, session: session)
// Send JWS to server
```

**Key Points:**
- No session ID yet (requests use `sessionId: nil`)
- Each request creates new ephemeral key pair
- Can only perform OPAQUE operations

## Session Mode

**When:** After OPAQUE authentication succeeds.

**Encryption:** Direct + A256GCM
- Uses symmetric session key from OPAQUE
- More efficient (no ECDH computation)
- Same key for all requests in session

**Transition:**

```swift
// After authentication completes (BFFHttpClient does this automatically):
session.enterSession(
    sessionId: "abc-123-def-456",
    sessionKey: authFinishResult.sessionKey  // 32-byte symmetric key
)

// session.mode == .session
// session.sessionId == "abc-123-def-456"
```

**Example (Protocol layer):**

```swift
// Build HSM request (encrypted with session key)
let outerRequest = try ProtocolRequest.hsmGenerateKey()
let jws = try outerRequest.toJWS(signer: session.signer, session: session)
// Send JWS to server
```

**Key Points:**
- Requests include `sessionId`
- Same session key reused (more efficient)
- Can only perform HSM operations

## Mode Comparison

| Aspect | Device Mode | Session Mode |
|--------|-------------|--------------|
| **When** | Before authentication | After authentication |
| **Encryption** | ECDH-ES (asymmetric) | Direct (symmetric) |
| **Key material** | Server public key | Session key (32 bytes) |
| **Ephemeral keys** | Yes (per request) | No |
| **Session ID** | `nil` | Required |
| **Operations** | OPAQUE only | HSM only |
| **Performance** | Slower (ECDH) | Faster (symmetric) |

## Complete Flow with BFFHttpClient

``BFFHttpClient`` manages mode transition automatically:

```swift
import SwiftAccessMechanism
import CryptoKit

// Initialize test client (starts in device mode internally)
var client = try BFFHttpClient.getTestClient(baseUrl: "http://localhost:8088")
let password = "user-pin".data(using: .utf8)!

// 1. Register (device mode)
_ = try await client.registration(password: password)

// 2. Authenticate (device mode → session mode transition happens internally)
let authResult = try await client.authenticate(password: password)

// 3. HSM operations (session mode)
let createdKey = try await client.createHsmKey()
let key = createdKey.public_key

let digest = Data(SHA256.hash(data: "test".data(using: .utf8)!))
let sig = try await client.sign(hsmKeyId: key.kid, digest: digest)

try verifySignature(publicKey: key, signature: sig, digest: digest)
```

## Errors

**Device mode errors:**
- `ProtocolSession.Errors.signerCreationFailed` — Client private key invalid
- `ProtocolSession.Errors.serverKeyParseError` — Server public key invalid
- `ProtocolSession.Errors.clientKeyParseError` — Client key parse failed

**Session mode errors:**
- `ProtocolSession.Errors.invalidSessionKey` — Session key rejected (wrong size)
- `ProtocolSession.Errors.failedToCreateDirectDecrypter` — Decrypter creation failed

See <doc:Error-Handling> for error handling patterns.

## Implementation Notes

**Thread Safety:** ``ProtocolSession`` is not thread-safe. Use one session per concurrent flow or synchronize access.

**Session Lifetime:** Session keys expire server-side. Re-authenticate when HSM operations fail.

**Mode Transition:** `enterSession()` is irreversible — can't return to device mode. Create new session to re-authenticate.

**BFFHttpClient:** Calls `enterSession()` automatically after successful `authenticate()`.

## See Also

- ``ProtocolSession`` — Core session management API
- ``ServerParameters`` — Server configuration
- <doc:Protocol-Layer> — Full Protocol API reference
- <doc:Architecture> — Crypto stack details
