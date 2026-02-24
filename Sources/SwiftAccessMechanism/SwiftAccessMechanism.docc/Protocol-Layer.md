# Protocol Layer

The stable core API for building JWS/JWE wrapped requests and managing session state.

## Overview

The Protocol layer is the stable foundation that apps use directly. It provides:

- ``ProtocolSession`` — manages encryption mode (device/session) and keys
- ``OuterRequest``/``OuterResponse`` — JWS signed layer
- ``InnerRequest``/``InnerResponse`` — JWE encrypted layer
- ``ProtocolRequest`` — typed request builders
- ``ServerParameters`` — server configuration

## Core Concepts

### Session Management

``ProtocolSession`` maintains encryption state:

```swift
let serverParams = try ServerParameters()
let clientPrivateKey: SecKey = ...  // P-256 private key

var session = try ProtocolSession(
    clientPrivateKey: clientPrivateKey,
    serverPublicKey: serverParams.serverPublicKey
)

// Start in device mode (ECDH-ES encryption)
// session.mode == .device

// After OPAQUE authentication, switch to session mode
try session.enterSession(sessionId: "abc-123", sessionKey: sessionKeyData)
// session.mode == .session
```

See <doc:Session-Lifecycle> for mode details.

### Request Building with ProtocolRequest

``ProtocolRequest`` provides static methods for all operations:

```swift
// Registration start — returns OuterRequest + client state
let regStart = try ProtocolRequest.registrationStart(password: password)
let jws = try regStart.outerRequest.toJWS(signer: session.signer, session: session)

// HSM generate key — returns OuterRequest
let genKey = try ProtocolRequest.hsmGenerateKey()
let jws = try genKey.toJWS(signer: session.signer, session: session)
```

### Message Layers

Outer → Inner wrapping (what ProtocolRequest does internally):

```swift
// 1. Create inner request (plaintext payload)
let innerRequest = try InnerRequest(type: .hsmGenerateKey, jsonData: ["curve": "P-256"])

// 2. Wrap in outer request (inner will be encrypted to JWE inside toJWS)
let outerRequest = OuterRequest(inner: innerRequest)

// 3. Encrypt inner → JWE, encode outer, sign → JWS
let jwsString = try outerRequest.toJWS(signer: session.signer, session: session)
```

## Wire Format

Non-normative examples of on-the-wire representation. **JWS** = compact JWS serialization, **JWE** = compact JWE serialization, **JWK** = JWK format key.

### Request (Device Mode)

OPAQUE registration start, before session established:

```
JWS(
  header: {
    alg: "ES256",
    kid: "client-key-thumbprint"
  },
  payload: {
    version: 1,
    context: "hsm",
    inner_jwe: JWE(
      header: {
        alg: "ECDH-ES",
        enc: "A256GCM",
        epk: JWK("ephemeral-public-key")
      },
      payload: {
        version: 1,
        type: "register_start",
        request_counter: 1,
        data: "{\"data\":\"<base64-opaque-ke1>\"}"
      }
    )
  }
)
```

### Request (Session Mode)

HSM key generation after session established:

```
JWS(
  header: {
    alg: "ES256",
    kid: "client-key-thumbprint"
  },
  payload: {
    version: 1,
    context: "hsm",
    session_id: "7a3f9c2e-1b4d-4a8c-9f2e-8d7c6b5a4e3f",
    inner_jwe: JWE(
      header: {
        alg: "dir",
        enc: "A256GCM"
      },
      payload: {
        version: 1,
        type: "hsm_generate_key",
        request_counter: 5,
        data: "{\"curve\":\"P-256\"}"
      }
    )
  }
)
```

### Response

Server response (session mode):

```
JWS(
  header: {
    alg: "ES256",
    kid: "server-key-id"
  },
  payload: {
    version: 1,
    session_id: "7a3f9c2e-1b4d-4a8c-9f2e-8d7c6b5a4e3f",
    inner_jwe: JWE(
      header: {
        alg: "dir",
        enc: "A256GCM"
      },
      payload: {
        version: 1,
        status: "OK",
        expires_in: "PT10S",
        data: "{\"public_key\":JWK(\"hsm-key-id\")}"
      }
    )
  }
)
```

**Notes:**
- `version` is integer 1
- `context` is always `"hsm"`
- `JWK("key-id")` = JWK format public key (e.g., `{"kty":"EC","crv":"P-256","x":"...","y":"...","kid":"..."}`)
- Device mode: `alg: "ECDH-ES"` with ephemeral key in `epk`
- Session mode: `alg: "dir"` (direct symmetric encryption with OPAQUE session key)
- `inner_jwe` is compact JWE string in actual wire format (not JSON object)
- `data` field contains JSON-encoded operation-specific data

## API Reference

### Registration

**Start:**

```swift
let result = try ProtocolRequest.registrationStart(password: stretchedPin)
// Returns: RegistrationStartResult
//   .outerRequest — ready to sign
//   .clientRegistration — OPAQUE state (keep for finish)

let jws = try result.outerRequest.toJWS(signer: session.signer, session: session)
// Send JWS to server
```

**Finish:**

```swift
// Parse server response
let outerResponse = try OuterResponse(jwsString: serverJWS, session: session)
let pakeResponse: PakeResponse = try outerResponse.innerResponse.decodePayload(PakeResponse.self)
let credentialData = try pakeResponse.decodedResponseData()

// Complete registration
let outerRequest = try ProtocolRequest.registrationFinish(
    clientRegistration: result.clientRegistration,
    password: stretchedPin,
    credentialResponse: credentialData,
    clientIdentifier: clientId,
    serverIdentifier: serverParams.opaqueServerIdentifier
)

let jws = try outerRequest.toJWS(signer: session.signer, session: session)
// Send JWS to server
```

### Authentication

**Start:**

```swift
let result = try ProtocolRequest.authenticateStart(password: stretchedPin)
// Same return type as registrationStart:
//   .outerRequest — ready to sign
//   .clientRegistration — OPAQUE state (keep for finish)

let jws = try result.outerRequest.toJWS(signer: session.signer, session: session)
// Send JWS to server
```

**Finish:**

```swift
// Parse server response
let outerResponse = try OuterResponse(jwsString: serverJWS, session: session)
let pakeResponse: PakeResponse = try outerResponse.innerResponse.decodePayload(PakeResponse.self)
let credentialData = try pakeResponse.decodedResponseData()

// Complete authentication
let finishResult = try ProtocolRequest.authenticateFinish(
    clientRegistration: result.clientRegistration,
    password: stretchedPin,
    credentialResponse: credentialData,
    context: serverParams.opaqueContext,
    clientIdentifier: clientId,
    serverIdentifier: serverParams.opaqueServerIdentifier,
    sessionId: outerResponse.sessionId!
)

// Switch to session mode using OPAQUE session key
try session.enterSession(
    sessionId: outerResponse.sessionId!,
    sessionKey: finishResult.sessionKey
)

let jws = try finishResult.outerRequest.toJWS(signer: session.signer, session: session)
// Send JWS to server
```

### HSM Generate Key

```swift
let outerRequest = try ProtocolRequest.hsmGenerateKey()
let jws = try outerRequest.toJWS(signer: session.signer, session: session)
// Send JWS to server

// Parse response
let outerResponse = try OuterResponse(jwsString: serverJWS, session: session)
let createKeyResponse: HsmCreateKeyResponse = try outerResponse.innerResponse.decodePayload(HsmCreateKeyResponse.self)

print("Created key: \(createKeyResponse.public_key.kid)")
```

### HSM List Keys

```swift
let outerRequest = try ProtocolRequest.hsmListKeys()
let jws = try outerRequest.toJWS(signer: session.signer, session: session)
// Send JWS to server

// Parse response
let outerResponse = try OuterResponse(jwsString: serverJWS, session: session)
let listResponse: HsmListResponse = try outerResponse.innerResponse.decodePayload(HsmListResponse.self)

for keyInfo in listResponse.keyInfo {
    print("Key: \(keyInfo.kid), Created: \(keyInfo.createdAt)")
}
```

### HSM Sign

```swift
import CryptoKit

// Pre-hash the message (sign expects a SHA-256 digest)
let message = "Hello, EUDI!".data(using: .utf8)!
let digest = Data(SHA256.hash(data: message))

let outerRequest = try ProtocolRequest.hsmSign(
    hsmKid: "key-id-123",
    message: digest
)
let jws = try outerRequest.toJWS(signer: session.signer, session: session)
// Send JWS to server

// Parse response
let outerResponse = try OuterResponse(jwsString: serverJWS, session: session)
let signResponse: SignatureResponse = try outerResponse.innerResponse.decodePayload(SignatureResponse.self)

// Convert to DER format for verification
let derSignature = try signResponse.toDER()
```

### Signature Verification

```swift
// Using verifySignature() helper (throws on failure)
try verifySignature(publicKey: jwkKey, signature: signResponse, digest: digest)

// Or manually with SecKey
let secKey = try jwkKey.toSecKey()
let derSig = try signResponse.toDER()

var cfError: Unmanaged<CFError>?
let valid = SecKeyVerifySignature(
    secKey,
    .ecdsaSignatureDigestX962SHA256,
    digest as CFData,
    derSig as CFData,
    &cfError
)
```

## Data Models

### PAKE Models

**PakeRequest:**
```swift
struct PakeRequest: Codable {
    let authorization: String?
    let task: String?
    let sessionDuration: Int?
    let requestData: String  // CodingKey: "data" — base64-encoded OPAQUE message
}
```

**PakeResponse:**
```swift
struct PakeResponse: Codable {
    let task: String?
    let responseData: String?  // CodingKey: "data" — base64-encoded OPAQUE message

    func decodedResponseData() throws -> Data  // Decodes base64
    func responseDataForDebug() -> String
}
```

### HSM Models

**HsmKeyInfo:**
```swift
struct HsmKeyInfo: Codable {
    let createdAt: String   // CodingKey: "created_at"
    let publicKey: JwkKey   // CodingKey: "public_key"
    var kid: String         // Computed from publicKey.kid
}
```

**HsmListResponse:**
```swift
struct HsmListResponse: Codable {
    let keyInfo: [HsmKeyInfo]  // CodingKey: "key_info"
}
```

**HsmCreateKeyResponse:**
```swift
struct HsmCreateKeyResponse: Codable {
    let public_key: JwkKey
}
```

**SignatureResponse:**
```swift
struct SignatureResponse: Codable {
    let signature: String  // Base64-encoded DER signature

    func toDER() throws -> Data
}
```

**JwkKey:**
```swift
struct JwkKey: Codable {
    let kty: String  // "EC"
    let crv: String  // "P-256"
    let x: String    // Base64url-encoded X coordinate
    let y: String    // Base64url-encoded Y coordinate
    let kid: String  // Server-assigned key ID

    func toSecKey() throws -> SecKey
    func toECPublicKey() throws -> ECPublicKey
}
```

## Server Configuration

``ServerParameters`` encapsulates server config:

```swift
// Test/dev defaults
let serverParams = try ServerParameters()

// Production config
let serverParams = try ServerParameters(
    serverPublicKeyPEM: "-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----",
    opaqueContext: Data("EUDI-Wallet-Production".utf8),
    opaqueServerIdentifier: Data("eudi.example.com".utf8)
)

// Access properties
let publicKey = serverParams.serverPublicKey       // SecKey
let context = serverParams.opaqueContext           // Data
let serverId = serverParams.opaqueServerIdentifier // Data
```

## ProtocolSession Errors

```swift
enum Errors: Error {
    case signerCreationFailed
    case serverKeyParseError
    case clientKeyParseError
    case invalidSessionKey
    case failedToCreateDirectDecrypter
}
```

See <doc:Error-Handling> for comprehensive error patterns.

## InnerRequestId Types

All request types available via ``InnerRequestId``:

**OPAQUE:** `registerStart`, `registerFinish`, `authenticateStart`, `authenticateFinish`

**HSM:** `hsmGenerateKey`, `hsmListKeys`, `hsmSign`, `hsmDeleteKey`, `hsmEcdh`

**Session:** `endSession`, `pinChange`

**Storage:** `store`, `retrieve`

**Other:** `log`, `getLog`, `info`

## See Also

- ``ProtocolSession`` — Session state management
- ``ServerParameters`` — Server configuration
- ``OuterRequest`` — JWS signed layer
- ``InnerRequest`` — JWE encrypted layer
- ``ProtocolRequest`` — Convenience request builders
- <doc:Session-Lifecycle> — Mode transitions
- <doc:Architecture> — Crypto details
