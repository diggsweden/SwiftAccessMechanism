# BFF HTTP Client

Provisional HTTP client for early development.

## Overview

``BFFHttpClient`` and ``BFFLayer`` provide HTTP transport for communicating with the HSM worker backend during early development. This provisional client sends ``OuterRequest``/``OuterResponse`` messages directly to the backend REST API.

## Status

**Provisional implementation** for project early life. Options:
- Use this HTTP client for prototyping and early integration
- Implement custom transport using ``ProtocolSession`` + ``OuterRequest``/``OuterResponse`` directly

See <doc:Protocol-Layer> for direct Protocol usage.

## API Overview

### Initialization

```swift
// Test client (localhost:8088, test keys)
var client = try BFFHttpClient.getTestClient(baseUrl: "http://localhost:8088")

// Production client
let serverParams = try ServerParameters(
    serverPublicKeyPEM: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
    opaqueContext: Data("EUDI-Wallet-Production".utf8),
    opaqueServerIdentifier: Data("eudi.example.com".utf8)
)

var client = try BFFHttpClient(
    clientPrivateKey: privateKey,
    serverParameters: serverParams,
    baseUrl: "https://api.example.com",
    clientId: clientId
)
// Note: OPAQUE client identifier is automatically computed as JWK thumbprint (RFC 7638) of clientPrivateKey's public key
```

### Registration Flow

```swift
// Registration (start + finish consolidated)
// Returns PakeResponse
_ = try await client.registration(password: password)
```

### Authentication Flow

```swift
// Authentication (start + finish consolidated, mutating)
// Internally calls enterSession() — client switches to session mode
let authResult = try await client.authenticate(password: password)

// authResult: BFFHttpClient.AuthenticationResult
//   .sessionKey — symmetric key (already applied internally)
//   .exportKey — OPAQUE export key
//   .response — parsed server response (includes sessionId)
```

### HSM Operations

All HSM methods require prior `authenticate()` (session mode):

```swift
// Generate key
let createdKey = try await client.createHsmKey()
// Returns: HsmCreateKeyResponse
//   .public_key — JwkKey with .kid, .kty, .crv, .x, .y

// List keys
let listResponse = try await client.listKeys()
// Returns: HsmListResponse
//   .keyInfo — [HsmKeyInfo] with .kid, .createdAt, .publicKey

// Sign data (pass SHA-256 digest, not raw message)
let digest = Data(SHA256.hash(data: message))
let signResponse = try await client.sign(
    hsmKeyId: createdKey.public_key.kid,
    digest: digest
)
// Returns: SignatureResponse
//   .signature — base64-encoded DER
//   .toDER() -> Data

// Verify signature
try verifySignature(publicKey: createdKey.public_key, signature: signResponse, digest: digest)
```

## Complete Example

Based on `testEcdsaSign` integration test:

```swift
import SwiftAccessMechanism
import CryptoKit

var client = try BFFHttpClient.getTestClient(baseUrl: "http://localhost:8088")
let password = "test".data(using: .utf8)!

// 1. Register
_ = try await client.registration(password: password)

// 2. Authenticate (switches to session mode)
_ = try await client.authenticate(password: password)

// 3. Create key
let createdKey = try await client.createHsmKey()
let key = createdKey.public_key

// 4. Sign
let message = "test message".data(using: .utf8)!
let digest = Data(SHA256.hash(data: message))
let sig = try await client.sign(hsmKeyId: key.kid, digest: digest)

// 5. Verify
try verifySignature(publicKey: key, signature: sig, digest: digest)
```

## BFFLayer (Transport-Independent)

``BFFLayer`` builds/parses JWS+JWE messages without HTTP:

```swift
// Compute OPAQUE client identifier from public key (RFC 7638)
let clientPublicKey = SecKeyCopyPublicKey(clientPrivateKey)!
let opaqueClientId = try computeJwkThumbprint(publicKey: clientPublicKey).data(using: .ascii)!

let layer = try BFFLayer(
    clientId: clientId,
    serverParameters: serverParams,
    opaqueClientId: opaqueClientId
)

// Build request
let startResult = try layer.registrationStart(password: password, with: session)
// Returns: PAKEStartResult with .request (HSMRequest) and .clientRegistration

// Send startResult.request.outerRequestJws (JWS String) via your transport

// Parse response
let parsed = try BFFLayer.parseAndValidateResponse(from: responseData, with: session, debugLog: false)
// Returns: ParsedBFFResponse with typed decodePayload()
let pakeResp = try parsed.decodePayload(PakeResponse.self)
```

Use ``BFFLayer`` when implementing custom transport but want message construction helpers.

## Error Handling

```swift
do {
    _ = try await client.authenticate(password: password)
} catch let error as BFFHttpClient.APIError {
    switch error {
    case .parameterError:
        print("Invalid base URL configuration")
    case .httpError(let statusCode):
        print("Server returned HTTP \(statusCode)")
    case .networkError:
        print("Cannot interpret response as HTTP")
    }
} catch let urlError as URLError {
    switch urlError.code {
    case .cannotConnectToHost, .cannotFindHost, .timedOut:
        print("Server unavailable")
    default:
        print("Network error: \(urlError)")
    }
}
```

See <doc:Error-Handling> for comprehensive patterns.

## Wire Format

Non-normative examples. HTTP POST to `{baseUrl}/r2ps-api/service`. **JWS** = compact JWS serialization, **JWE** = compact JWE serialization, **JWK** = JWK format key.

### HTTP Request (Device Mode)

OPAQUE authentication start, before session established:

```
POST /r2ps-api/service
Content-Type: application/json

JSON(
  clientId: "a25d8884-c77b-43ab-bf9d-1279c08d860d",
  outerRequestJws: JWS(
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
          type: "authenticate_start",
          request_counter: 1,
          data: "{\"data\":\"<base64-opaque-ke1>\"}"
        }
      )
    }
  )
)
```

### HTTP Request (Session Mode)

HSM key generation after session established:

```
POST /r2ps-api/service
Content-Type: application/json

JSON(
  clientId: "a25d8884-c77b-43ab-bf9d-1279c08d860d",
  outerRequestJws: JWS(
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
)
```

### HTTP Response

Server response (session mode):

```
HTTP/1.1 200 OK
Content-Type: text/plain

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
- Request body: JSON-encoded ``HSMRequest`` with `clientId` and `outerRequestJws`
- Response body: Raw compact JWS string (not JSON-wrapped)
- Device mode: `ECDH-ES` encryption with ephemeral key
- Session mode: `dir` (direct symmetric) encryption with OPAQUE session key
- OPAQUE client identifier: JWK thumbprint (RFC 7638) of client public key
- `inner_jwe` and `outerRequestJws` are compact serialized strings in actual wire format

## Implementation Notes

**HTTP Endpoint:** POST to `{baseUrl}/r2ps-api/service`

**Test Client:** ``BFFHttpClient/getTestClient(baseUrl:)`` uses fixed P-256 test private key and default ``ServerParameters``.

**Mutating:** `authenticate(password:)` is `mutating` — use `var` for client variable.

## See Also

- ``BFFHttpClient`` — HTTP client API
- ``BFFLayer`` — Message builder (transport-independent)
- ``HSMRequest`` — Request DTO
- <doc:Protocol-Layer> — Direct Protocol usage
- <doc:Getting-Started> — Complete examples
