# ``SwiftAccessMechanism``

Protocol stack for EUDI Wallet remote HSM operations.

## Overview

SwiftAccessMechanism provides secure authentication and key management for EUDI Wallet credentials:

**Core protocol layers:**
- **Protocol/** — JWS/JWE message wrapping (stable core API)
- **BFF-API/** — Provisional HTTP client for early development

**Cryptographic components:**
- **PIN Stretching** — Adds entropy to user PINs via Secure Enclave ECDH
- **OPAQUE PAKE** — Password-authenticated key exchange (Rust FFI)

## Quick Start

Based on `testEcdsaSign` integration test:

```swift
import SwiftAccessMechanism
import CryptoKit

// Initialize test client
var client = try BFFHttpClient.getTestClient(baseUrl: "http://localhost:8088")

// Stretch weak user PIN to 32-byte 'password' using a key in the Secure Enclave
let stretcher = PINStretch()
let password = try stretcher.stretch(input: "1234".data(using: .utf8)!)

// 1. Register password with server (one-time)
_ = try await client.registration(password: password)

// 2. Authenticate (OPAQUE, establishes session)
_ = try await client.authenticate(password: password)

// 3. Create HSM key (one-time)
let createdKey = try await client.createHsmKey()
let key = createdKey.public_key

// 4. Sign a digest of a message
let message = "Hello, EUDI!".data(using: .utf8)!
let digest = Data(SHA256.hash(data: message))
let sig = try await client.sign(hsmKeyId: key.kid, digest: digest)

// 5. Verify signature (locally)
try verifySignature(publicKey: key, signature: sig, digest: digest)
```

## Architecture

The library separates concerns into distinct layers:

- **Protocol/** — Core stable API that apps use directly (`ProtocolSession`, `OuterRequest/Response`, `InnerRequest/Response`)
- **BFF-API/** — Provisional HTTP client for early development (`BFFHttpClient`, `BFFLayer`)

Separate components:

- **Opaque/** — OPAQUE PAKE client (Rust FFI via `OpaqueKeUniffi.xcframework`)
- **PINStretch/** — PIN stretching via Secure Enclave ECDH

### Crypto Stack

| Layer | Algorithm | Key Type |
|-------|-----------|----------|
| Outer (JWS) | ES256 | P-256 ECDSA |
| Inner (device) | ECDH-ES + A256GCM | P-256 ephemeral |
| Inner (session) | Direct + A256GCM | Symmetric (from OPAQUE) |

### Session Flow

1. **Device mode** — Use ECDH-ES encryption with server's public key
2. **OPAQUE authentication** — Register or authenticate to obtain session key
3. **Session mode** — Call `enterSession()` to switch to symmetric encryption
4. **HSM operations** — Generate/list keys, sign data using session key

See <doc:Session-Lifecycle> for detailed state transitions.

## Topics

### Essentials

- <doc:Getting-Started>
- <doc:Architecture>
- ``BFFHttpClient``
- ``ProtocolSession``
- ``ServerParameters``

### Core Protocol Layer

- <doc:Protocol-Layer>
- <doc:Session-Lifecycle>
- ``OuterRequest``
- ``OuterResponse``
- ``InnerRequest``
- ``InnerResponse``
- ``ProtocolRequest``

### BFF HTTP Client (Provisional)

- <doc:BFF-HTTP-Client>
- ``BFFLayer``
- ``HSMRequest``

### PIN Stretching & Secure Enclave

- <doc:PIN-Stretching>
- ``PINStretch``
- ``AMSecureEnclave``

### OPAQUE PAKE

- ``OpaqueClient``

### Models & Utilities

- ``PakeRequest``
- ``PakeResponse``
- ``HsmKeyInfo``
- ``HsmListResponse``
- ``HsmCreateKeyResponse``
- ``SignatureResponse``
- ``JwkKey``

### Error Handling

- <doc:Error-Handling>
- ``OpaqueClientError``
- ``PINStretchError``

### Testing

- <doc:Testing>
